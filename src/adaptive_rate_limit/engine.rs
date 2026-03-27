//! Core adaptation engine — mode transitions, multiplier computation,
//! per-consumer trend tracking, and Redis synchronisation.

use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::adaptive_rate_limit::{
    config::AdaptiveRateLimitConfig,
    models::{
        AdaptationMode, AdminOverride, ConsumerPriorityTier, ConsumerRateTrend,
        ModeTransitionRecord, SignalSnapshot,
    },
    repository::AdaptiveRateLimitRepository,
    signals::SignalCollector,
};
use crate::cache::RedisCache;

// ---------------------------------------------------------------------------
// Engine state
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct EngineState {
    current_mode: AdaptationMode,
    mode_entered_at: DateTime<Utc>,
    relaxation_started_at: Option<DateTime<Utc>>,
    elevated_signal_started_at: Option<DateTime<Utc>>,
    admin_override: Option<AdminOverride>,
    consumer_trends: HashMap<Uuid, ConsumerRateTrend>,
}

impl EngineState {
    fn new() -> Self {
        Self {
            current_mode: AdaptationMode::Normal,
            mode_entered_at: Utc::now(),
            relaxation_started_at: None,
            elevated_signal_started_at: None,
            admin_override: None,
            consumer_trends: HashMap::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// AdaptiveRateLimitEngine
// ---------------------------------------------------------------------------

/// The central engine that drives all adaptive rate limiting decisions.
///
/// Cloneable — all state is behind `Arc<RwLock<_>>`.
#[derive(Clone)]
pub struct AdaptiveRateLimitEngine {
    pub config: Arc<AdaptiveRateLimitConfig>,
    pub signals: Arc<SignalCollector>,
    state: Arc<RwLock<EngineState>>,
    cache: Arc<RedisCache>,
    repo: Arc<AdaptiveRateLimitRepository>,
}

impl AdaptiveRateLimitEngine {
    pub fn new(
        config: AdaptiveRateLimitConfig,
        signals: Arc<SignalCollector>,
        cache: Arc<RedisCache>,
        repo: AdaptiveRateLimitRepository,
    ) -> Self {
        Self {
            config: Arc::new(config),
            signals,
            state: Arc::new(RwLock::new(EngineState::new())),
            cache,
            repo: Arc::new(repo),
        }
    }

    // ── Public API ───────────────────────────────────────────────────────────

    /// Returns the current adaptation mode (admin override takes precedence).
    pub async fn current_mode(&self) -> AdaptationMode {
        let state = self.state.read().await;
        if let Some(ref ov) = state.admin_override {
            return ov.mode;
        }
        state.current_mode
    }

    /// Compute the effective rate limit multiplier for a consumer.
    ///
    /// Returns a value in (0.0, 1.0] where 1.0 means "apply static limit as-is".
    pub async fn effective_multiplier(
        &self,
        consumer_id: Uuid,
        tier: ConsumerPriorityTier,
    ) -> f64 {
        let mode = self.current_mode().await;
        let base = self.base_multiplier(mode, tier);
        let extra = {
            let state = self.state.read().await;
            state
                .consumer_trends
                .get(&consumer_id)
                .map(|t| t.extra_multiplier)
                .unwrap_or(1.0)
        };
        (base * extra).max(0.01)
    }

    /// Compute the base multiplier for a tier in a given mode.
    pub fn base_multiplier(&self, mode: AdaptationMode, tier: ConsumerPriorityTier) -> f64 {
        match (mode, tier) {
            (AdaptationMode::Normal, _) => 1.0,
            (AdaptationMode::Elevated, ConsumerPriorityTier::High) => 1.0,
            (AdaptationMode::Elevated, ConsumerPriorityTier::Standard) => {
                self.config.elevated_standard_multiplier
            }
            (AdaptationMode::Elevated, ConsumerPriorityTier::Low) => {
                self.config.elevated_low_multiplier
            }
            (AdaptationMode::Critical, ConsumerPriorityTier::High) => 1.0,
            (AdaptationMode::Critical, ConsumerPriorityTier::Standard) => {
                self.config.critical_standard_multiplier
            }
            (AdaptationMode::Critical, ConsumerPriorityTier::Low) => {
                self.config.critical_low_multiplier
            }
            (AdaptationMode::Emergency, ConsumerPriorityTier::High) => {
                self.config.emergency_high_multiplier
            }
            (AdaptationMode::Emergency, _) => 0.05,
        }
    }

    /// Run one adaptation cycle: collect signals, evaluate transitions, sync Redis.
    pub async fn run_cycle(&self) {
        let snapshot = self.signals.collect().await;
        let averages = self.signals.rolling_averages().await;
        self.evaluate_transitions(&snapshot, &averages).await;
        self.sync_multipliers_to_redis().await;
        self.check_elevated_mode_alert().await;
    }

    /// Record a request for a consumer (for trend tracking).
    pub async fn record_request(&self, consumer_id: Uuid, tier: ConsumerPriorityTier) {
        let mode = self.current_mode().await;
        if matches!(mode, AdaptationMode::Normal) {
            return;
        }

        let bucket_count = self.config.consumer_trend_bucket_count;
        let mut state = self.state.write().await;
        let trend = state
            .consumer_trends
            .entry(consumer_id)
            .or_insert_with(|| ConsumerRateTrend::new(consumer_id, bucket_count));

        if trend.buckets.is_empty() {
            trend.buckets.push_back(1);
        } else {
            *trend.buckets.back_mut().unwrap() += 1;
        }
        trend.last_updated = Utc::now();

        if matches!(mode, AdaptationMode::Elevated | AdaptationMode::Critical)
            && trend.is_accelerating()
            && trend.extra_multiplier > self.config.accelerating_consumer_multiplier
        {
            trend.extra_multiplier = self.config.accelerating_consumer_multiplier;

            if tier == ConsumerPriorityTier::High {
                info!(
                    consumer_id = %consumer_id,
                    mode = %mode,
                    multiplier = trend.extra_multiplier,
                    "high-priority consumer adaptive throttle applied"
                );
            }

            warn!(
                consumer_id = %consumer_id,
                mode = %mode,
                multiplier = trend.extra_multiplier,
                "per-consumer adaptive throttle applied due to accelerating request rate"
            );

            crate::adaptive_rate_limit::metrics::consumer_throttle_applications_total()
                .with_label_values(&[&consumer_id.to_string(), mode.as_str()])
                .inc();
        }
    }

    /// Advance all consumer trend windows (called once per sampling interval).
    pub async fn advance_trend_windows(&self) {
        let bucket_count = self.config.consumer_trend_bucket_count;
        let mut state = self.state.write().await;
        for trend in state.consumer_trends.values_mut() {
            if trend.buckets.len() >= bucket_count {
                trend.buckets.pop_front();
            }
            trend.buckets.push_back(0);
            if !trend.is_accelerating() {
                trend.extra_multiplier = 1.0;
            }
        }
    }

    // ── Admin override ───────────────────────────────────────────────────────

    pub async fn set_admin_override(&self, override_: AdminOverride) {
        let mode = override_.mode;
        let set_by = override_.set_by.clone();
        {
            let mut state = self.state.write().await;
            state.admin_override = Some(override_);
        }
        info!(mode = %mode, set_by = %set_by, "admin override applied");
        self.sync_multipliers_to_redis().await;
    }

    pub async fn clear_admin_override(&self) {
        {
            let mut state = self.state.write().await;
            state.admin_override = None;
        }
        info!("admin override cleared — returning to signal-driven adaptation");
        self.sync_multipliers_to_redis().await;
    }

    pub async fn admin_override(&self) -> Option<AdminOverride> {
        let state = self.state.read().await;
        state.admin_override.clone()
    }

    // ── Status ───────────────────────────────────────────────────────────────

    pub async fn status(&self) -> EngineStatus {
        let mode = self.current_mode().await;
        let state = self.state.read().await;
        let latest_signals = self.signals.latest().await;
        let averages = self.signals.rolling_averages().await;

        EngineStatus {
            current_mode: mode,
            mode_entered_at: state.mode_entered_at,
            admin_override: state.admin_override.clone(),
            latest_signals,
            rolling_averages: averages,
            effective_multipliers: EffectiveMultipliers {
                high: self.base_multiplier(mode, ConsumerPriorityTier::High),
                standard: self.base_multiplier(mode, ConsumerPriorityTier::Standard),
                low: self.base_multiplier(mode, ConsumerPriorityTier::Low),
            },
        }
    }

    // ── Mode transition logic ────────────────────────────────────────────────

    async fn evaluate_transitions(&self, snapshot: &SignalSnapshot, averages: &SignalSnapshot) {
        {
            let state = self.state.read().await;
            if state.admin_override.is_some() {
                return;
            }
        }

        let current = {
            let state = self.state.read().await;
            state.current_mode
        };

        let target = self.compute_target_mode(snapshot, averages, current).await;

        if target != current {
            self.transition_to(target, snapshot, "signal-driven").await;
        } else if current != AdaptationMode::Normal {
            self.check_hysteresis(snapshot).await;
        }
    }

    async fn compute_target_mode(
        &self,
        _snapshot: &SignalSnapshot,
        averages: &SignalSnapshot,
        current: AdaptationMode,
    ) -> AdaptationMode {
        let cfg = &self.config;

        // Emergency: any single signal at emergency threshold.
        if averages.cpu_utilisation >= cfg.emergency_cpu_threshold
            || averages.db_pool_utilisation >= cfg.emergency_db_pool_threshold
            || averages.error_rate >= cfg.emergency_error_rate_threshold
        {
            return AdaptationMode::Emergency;
        }

        // Critical: multiple signals simultaneously exceed critical thresholds.
        let critical_count = [
            averages.cpu_utilisation >= cfg.critical_cpu_threshold,
            averages.db_pool_utilisation >= cfg.critical_db_pool_threshold,
            averages.redis_memory_pressure >= cfg.critical_redis_threshold,
            averages.request_queue_depth >= cfg.critical_queue_depth_threshold,
            averages.error_rate >= cfg.critical_error_rate_threshold,
            averages.p99_response_time_ms >= cfg.critical_p99_ms_threshold,
        ]
        .iter()
        .filter(|&&b| b)
        .count();

        if critical_count >= cfg.critical_signal_count {
            return AdaptationMode::Critical;
        }

        // Elevated: any single signal exceeds elevated threshold for sustained duration.
        let any_elevated = averages.cpu_utilisation >= cfg.elevated_cpu_threshold
            || averages.db_pool_utilisation >= cfg.elevated_db_pool_threshold
            || averages.redis_memory_pressure >= cfg.elevated_redis_threshold
            || averages.request_queue_depth >= cfg.elevated_queue_depth_threshold
            || averages.error_rate >= cfg.elevated_error_rate_threshold
            || averages.p99_response_time_ms >= cfg.elevated_p99_ms_threshold;

        if any_elevated {
            let sustained = {
                let mut state = self.state.write().await;
                if state.elevated_signal_started_at.is_none() {
                    state.elevated_signal_started_at = Some(Utc::now());
                }
                let started = state.elevated_signal_started_at.unwrap();
                let elapsed = Utc::now() - started;
                elapsed.to_std().unwrap_or_default() >= cfg.elevated_sustained_duration
            };
            if sustained {
                return AdaptationMode::Elevated;
            }
        } else {
            let mut state = self.state.write().await;
            state.elevated_signal_started_at = None;
        }

        // Don't auto-downgrade from elevated/critical/emergency here —
        // that's handled by hysteresis.
        if current != AdaptationMode::Normal {
            return current;
        }

        AdaptationMode::Normal
    }

    async fn check_hysteresis(&self, snapshot: &SignalSnapshot) {
        let cfg = &self.config;
        let all_relaxed = snapshot.cpu_utilisation < cfg.relax_cpu_threshold
            && snapshot.db_pool_utilisation < cfg.relax_db_pool_threshold
            && snapshot.redis_memory_pressure < cfg.relax_redis_threshold
            && snapshot.request_queue_depth < cfg.relax_queue_depth_threshold
            && snapshot.error_rate < cfg.relax_error_rate_threshold
            && snapshot.p99_response_time_ms < cfg.relax_p99_ms_threshold;

        let current = {
            let state = self.state.read().await;
            state.current_mode
        };

        if all_relaxed {
            let started = {
                let mut state = self.state.write().await;
                if state.relaxation_started_at.is_none() {
                    state.relaxation_started_at = Some(Utc::now());
                }
                state.relaxation_started_at.unwrap()
            };

            let elapsed = Utc::now() - started;
            if elapsed.to_std().unwrap_or_default() >= cfg.hysteresis_duration {
                let next = match current {
                    AdaptationMode::Emergency => AdaptationMode::Critical,
                    AdaptationMode::Critical => AdaptationMode::Elevated,
                    AdaptationMode::Elevated => AdaptationMode::Normal,
                    AdaptationMode::Normal => AdaptationMode::Normal,
                };
                if next != current {
                    self.transition_to(next, snapshot, "hysteresis relaxation")
                        .await;
                }
            }
        } else {
            let mut state = self.state.write().await;
            state.relaxation_started_at = None;
        }
    }

    async fn transition_to(
        &self,
        target: AdaptationMode,
        snapshot: &SignalSnapshot,
        reason: &str,
    ) {
        let current = {
            let mut state = self.state.write().await;
            let from = state.current_mode;
            state.current_mode = target;
            state.mode_entered_at = Utc::now();
            state.relaxation_started_at = None;
            state.elevated_signal_started_at = None;
            from
        };

        let record = ModeTransitionRecord {
            id: Uuid::new_v4(),
            from_mode: current,
            to_mode: target,
            trigger_signal: reason.to_string(),
            signal_values: snapshot.clone(),
            reason: reason.to_string(),
            is_manual_override: false,
            transitioned_at: Utc::now(),
        };

        let repo = self.repo.clone();
        let rec = record.clone();
        tokio::spawn(async move {
            if let Err(e) = repo.persist_transition(&rec).await {
                error!(error = %e, "failed to persist mode transition");
            }
        });

        crate::adaptive_rate_limit::metrics::mode_transitions_total()
            .with_label_values(&[current.as_str(), target.as_str()])
            .inc();
        crate::adaptive_rate_limit::metrics::current_mode().set(target.severity() as f64);

        if matches!(target, AdaptationMode::Critical | AdaptationMode::Emergency) {
            warn!(
                from_mode = %current,
                to_mode = %target,
                reason = %reason,
                cpu = snapshot.cpu_utilisation,
                db_pool = snapshot.db_pool_utilisation,
                redis = snapshot.redis_memory_pressure,
                queue_depth = snapshot.request_queue_depth,
                error_rate = snapshot.error_rate,
                p99_ms = snapshot.p99_response_time_ms,
                "ADAPTIVE_RATE_LIMIT_CRITICAL_TRANSITION"
            );
        } else {
            info!(
                from_mode = %current,
                to_mode = %target,
                reason = %reason,
                "adaptation mode transition"
            );
        }
    }

    // ── Redis synchronisation ────────────────────────────────────────────────

    async fn sync_multipliers_to_redis(&self) {
        let mode = self.current_mode().await;
        let prefix = &self.config.redis_key_prefix;

        let mut conn = match self.cache.get_connection().await {
            Ok(c) => c,
            Err(e) => {
                warn!(error = %e, "failed to get Redis connection for multiplier sync");
                return;
            }
        };

        let high = self.base_multiplier(mode, ConsumerPriorityTier::High);
        let standard = self.base_multiplier(mode, ConsumerPriorityTier::Standard);
        let low = self.base_multiplier(mode, ConsumerPriorityTier::Low);

        let _: Result<(), _> = redis::pipe()
            .atomic()
            .cmd("SET")
            .arg(format!("{prefix}:mode"))
            .arg(mode.as_str())
            .ignore()
            .cmd("EXPIRE")
            .arg(format!("{prefix}:mode"))
            .arg(60u64)
            .ignore()
            .cmd("SET")
            .arg(format!("{prefix}:multiplier:high"))
            .arg(high.to_string())
            .ignore()
            .cmd("EXPIRE")
            .arg(format!("{prefix}:multiplier:high"))
            .arg(60u64)
            .ignore()
            .cmd("SET")
            .arg(format!("{prefix}:multiplier:standard"))
            .arg(standard.to_string())
            .ignore()
            .cmd("EXPIRE")
            .arg(format!("{prefix}:multiplier:standard"))
            .arg(60u64)
            .ignore()
            .cmd("SET")
            .arg(format!("{prefix}:multiplier:low"))
            .arg(low.to_string())
            .ignore()
            .cmd("EXPIRE")
            .arg(format!("{prefix}:multiplier:low"))
            .arg(60u64)
            .ignore()
            .query_async(&mut *conn)
            .await;

        crate::adaptive_rate_limit::metrics::effective_multiplier()
            .with_label_values(&["high"])
            .set(high);
        crate::adaptive_rate_limit::metrics::effective_multiplier()
            .with_label_values(&["standard"])
            .set(standard);
        crate::adaptive_rate_limit::metrics::effective_multiplier()
            .with_label_values(&["low"])
            .set(low);
    }

    // ── Elevated mode alert ──────────────────────────────────────────────────

    async fn check_elevated_mode_alert(&self) {
        let (mode, entered_at) = {
            let state = self.state.read().await;
            (state.current_mode, state.mode_entered_at)
        };

        if mode != AdaptationMode::Elevated {
            return;
        }

        let elapsed = Utc::now() - entered_at;
        if elapsed.to_std().unwrap_or_default() >= self.config.elevated_mode_alert_duration {
            warn!(
                elapsed_secs = elapsed.num_seconds(),
                "ADAPTIVE_RATE_LIMIT_ELEVATED_MODE_SUSTAINED: \
                 platform has been in elevated mode beyond configured threshold"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Status response types
// ---------------------------------------------------------------------------

#[derive(Debug, serde::Serialize)]
pub struct EngineStatus {
    pub current_mode: AdaptationMode,
    pub mode_entered_at: DateTime<Utc>,
    pub admin_override: Option<AdminOverride>,
    pub latest_signals: Option<SignalSnapshot>,
    pub rolling_averages: SignalSnapshot,
    pub effective_multipliers: EffectiveMultipliers,
}

#[derive(Debug, serde::Serialize)]
pub struct EffectiveMultipliers {
    pub high: f64,
    pub standard: f64,
    pub low: f64,
}
