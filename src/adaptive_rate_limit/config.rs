//! Configuration for the adaptive rate limiting system.
//!
//! All values are loaded from environment variables with sensible defaults
//! so the system can be tuned without recompiling.

use std::time::Duration;

/// Full configuration for the adaptive rate limiting system.
#[derive(Debug, Clone)]
pub struct AdaptiveRateLimitConfig {
    // ── Signal collection ────────────────────────────────────────────────────
    /// How often platform health signals are sampled.
    pub signal_sampling_interval: Duration,
    /// Number of samples in the rolling average window.
    pub rolling_window_size: usize,
    /// How often signal snapshots are persisted to the database.
    pub signal_persist_interval: Duration,

    // ── Elevated mode thresholds ─────────────────────────────────────────────
    /// CPU utilisation that triggers elevated mode [0.0, 1.0].
    pub elevated_cpu_threshold: f64,
    /// DB pool utilisation that triggers elevated mode [0.0, 1.0].
    pub elevated_db_pool_threshold: f64,
    /// Redis memory pressure that triggers elevated mode [0.0, 1.0].
    pub elevated_redis_threshold: f64,
    /// Request queue depth that triggers elevated mode.
    pub elevated_queue_depth_threshold: u64,
    /// Error rate that triggers elevated mode [0.0, 1.0].
    pub elevated_error_rate_threshold: f64,
    /// p99 response time (ms) that triggers elevated mode.
    pub elevated_p99_ms_threshold: f64,
    /// How long a signal must exceed its threshold before transitioning to elevated.
    pub elevated_sustained_duration: Duration,

    // ── Critical mode thresholds ─────────────────────────────────────────────
    /// CPU utilisation for critical mode.
    pub critical_cpu_threshold: f64,
    /// DB pool utilisation for critical mode.
    pub critical_db_pool_threshold: f64,
    /// Redis memory pressure for critical mode.
    pub critical_redis_threshold: f64,
    /// Request queue depth for critical mode.
    pub critical_queue_depth_threshold: u64,
    /// Error rate for critical mode.
    pub critical_error_rate_threshold: f64,
    /// p99 response time (ms) for critical mode.
    pub critical_p99_ms_threshold: f64,
    /// Number of signals that must simultaneously exceed critical thresholds.
    pub critical_signal_count: usize,

    // ── Emergency mode thresholds ────────────────────────────────────────────
    /// CPU utilisation for emergency mode.
    pub emergency_cpu_threshold: f64,
    /// DB pool utilisation for emergency mode.
    pub emergency_db_pool_threshold: f64,
    /// Error rate for emergency mode.
    pub emergency_error_rate_threshold: f64,

    // ── Hysteresis ───────────────────────────────────────────────────────────
    /// Relaxation thresholds — all signals must be below these before downgrading.
    pub relax_cpu_threshold: f64,
    pub relax_db_pool_threshold: f64,
    pub relax_redis_threshold: f64,
    pub relax_queue_depth_threshold: u64,
    pub relax_error_rate_threshold: f64,
    pub relax_p99_ms_threshold: f64,
    /// How long all signals must remain below relaxation thresholds before downgrading.
    pub hysteresis_duration: Duration,

    // ── Adaptive multipliers ─────────────────────────────────────────────────
    /// Rate limit multiplier applied to standard consumers in elevated mode (e.g. 0.5).
    pub elevated_standard_multiplier: f64,
    /// Rate limit multiplier applied to standard consumers in critical mode (e.g. 0.2).
    pub critical_standard_multiplier: f64,
    /// Rate limit multiplier applied to low-priority consumers in elevated mode.
    pub elevated_low_multiplier: f64,
    /// Rate limit multiplier applied to low-priority consumers in critical mode.
    pub critical_low_multiplier: f64,
    /// Rate limit multiplier applied to high-priority consumers in emergency mode.
    pub emergency_high_multiplier: f64,
    /// Minimal rate limit (requests/min) applied to all consumers in emergency mode.
    pub emergency_minimal_limit: i64,

    // ── Per-consumer accelerating request detection ──────────────────────────
    /// Number of rate-trend buckets to maintain per consumer.
    pub consumer_trend_bucket_count: usize,
    /// Additional throttle multiplier applied to accelerating consumers.
    pub accelerating_consumer_multiplier: f64,

    // ── Emergency request queue ──────────────────────────────────────────────
    /// Maximum number of essential requests queued in emergency mode.
    pub emergency_queue_max_depth: usize,

    // ── Alerting ─────────────────────────────────────────────────────────────
    /// How long the platform can remain in elevated mode before an alert fires.
    pub elevated_mode_alert_duration: Duration,

    // ── Redis key prefix ─────────────────────────────────────────────────────
    pub redis_key_prefix: String,
}

impl Default for AdaptiveRateLimitConfig {
    fn default() -> Self {
        Self {
            signal_sampling_interval: Duration::from_secs(10),
            rolling_window_size: 12, // 12 × 10 s = 2-minute window
            signal_persist_interval: Duration::from_secs(60),

            elevated_cpu_threshold: 0.70,
            elevated_db_pool_threshold: 0.75,
            elevated_redis_threshold: 0.70,
            elevated_queue_depth_threshold: 500,
            elevated_error_rate_threshold: 0.05,
            elevated_p99_ms_threshold: 1000.0,
            elevated_sustained_duration: Duration::from_secs(30),

            critical_cpu_threshold: 0.85,
            critical_db_pool_threshold: 0.90,
            critical_redis_threshold: 0.85,
            critical_queue_depth_threshold: 2000,
            critical_error_rate_threshold: 0.15,
            critical_p99_ms_threshold: 3000.0,
            critical_signal_count: 2,

            emergency_cpu_threshold: 0.95,
            emergency_db_pool_threshold: 0.98,
            emergency_error_rate_threshold: 0.30,

            relax_cpu_threshold: 0.60,
            relax_db_pool_threshold: 0.65,
            relax_redis_threshold: 0.60,
            relax_queue_depth_threshold: 200,
            relax_error_rate_threshold: 0.02,
            relax_p99_ms_threshold: 500.0,
            hysteresis_duration: Duration::from_secs(120),

            elevated_standard_multiplier: 0.5,
            critical_standard_multiplier: 0.2,
            elevated_low_multiplier: 0.3,
            critical_low_multiplier: 0.1,
            emergency_high_multiplier: 0.5,
            emergency_minimal_limit: 5,

            consumer_trend_bucket_count: 6,
            accelerating_consumer_multiplier: 0.5,

            emergency_queue_max_depth: 100,

            elevated_mode_alert_duration: Duration::from_secs(300),

            redis_key_prefix: "adaptive_rl".to_string(),
        }
    }
}

impl AdaptiveRateLimitConfig {
    /// Load configuration from environment variables, falling back to defaults.
    pub fn from_env() -> Self {
        let mut cfg = Self::default();

        macro_rules! env_secs {
            ($var:expr, $field:expr) => {
                if let Ok(v) = std::env::var($var) {
                    if let Ok(n) = v.parse::<u64>() {
                        $field = Duration::from_secs(n);
                    }
                }
            };
        }
        macro_rules! env_f64 {
            ($var:expr, $field:expr) => {
                if let Ok(v) = std::env::var($var) {
                    if let Ok(n) = v.parse::<f64>() {
                        $field = n;
                    }
                }
            };
        }
        macro_rules! env_u64 {
            ($var:expr, $field:expr) => {
                if let Ok(v) = std::env::var($var) {
                    if let Ok(n) = v.parse::<u64>() {
                        $field = n;
                    }
                }
            };
        }
        macro_rules! env_usize {
            ($var:expr, $field:expr) => {
                if let Ok(v) = std::env::var($var) {
                    if let Ok(n) = v.parse::<usize>() {
                        $field = n;
                    }
                }
            };
        }
        macro_rules! env_i64 {
            ($var:expr, $field:expr) => {
                if let Ok(v) = std::env::var($var) {
                    if let Ok(n) = v.parse::<i64>() {
                        $field = n;
                    }
                }
            };
        }

        env_secs!("ARL_SIGNAL_SAMPLING_INTERVAL_SECS", cfg.signal_sampling_interval);
        env_usize!("ARL_ROLLING_WINDOW_SIZE", cfg.rolling_window_size);
        env_secs!("ARL_SIGNAL_PERSIST_INTERVAL_SECS", cfg.signal_persist_interval);

        env_f64!("ARL_ELEVATED_CPU_THRESHOLD", cfg.elevated_cpu_threshold);
        env_f64!("ARL_ELEVATED_DB_POOL_THRESHOLD", cfg.elevated_db_pool_threshold);
        env_f64!("ARL_ELEVATED_REDIS_THRESHOLD", cfg.elevated_redis_threshold);
        env_u64!("ARL_ELEVATED_QUEUE_DEPTH_THRESHOLD", cfg.elevated_queue_depth_threshold);
        env_f64!("ARL_ELEVATED_ERROR_RATE_THRESHOLD", cfg.elevated_error_rate_threshold);
        env_f64!("ARL_ELEVATED_P99_MS_THRESHOLD", cfg.elevated_p99_ms_threshold);
        env_secs!("ARL_ELEVATED_SUSTAINED_DURATION_SECS", cfg.elevated_sustained_duration);

        env_f64!("ARL_CRITICAL_CPU_THRESHOLD", cfg.critical_cpu_threshold);
        env_f64!("ARL_CRITICAL_DB_POOL_THRESHOLD", cfg.critical_db_pool_threshold);
        env_f64!("ARL_CRITICAL_REDIS_THRESHOLD", cfg.critical_redis_threshold);
        env_u64!("ARL_CRITICAL_QUEUE_DEPTH_THRESHOLD", cfg.critical_queue_depth_threshold);
        env_f64!("ARL_CRITICAL_ERROR_RATE_THRESHOLD", cfg.critical_error_rate_threshold);
        env_f64!("ARL_CRITICAL_P99_MS_THRESHOLD", cfg.critical_p99_ms_threshold);
        env_usize!("ARL_CRITICAL_SIGNAL_COUNT", cfg.critical_signal_count);

        env_f64!("ARL_EMERGENCY_CPU_THRESHOLD", cfg.emergency_cpu_threshold);
        env_f64!("ARL_EMERGENCY_DB_POOL_THRESHOLD", cfg.emergency_db_pool_threshold);
        env_f64!("ARL_EMERGENCY_ERROR_RATE_THRESHOLD", cfg.emergency_error_rate_threshold);

        env_f64!("ARL_RELAX_CPU_THRESHOLD", cfg.relax_cpu_threshold);
        env_f64!("ARL_RELAX_DB_POOL_THRESHOLD", cfg.relax_db_pool_threshold);
        env_f64!("ARL_RELAX_REDIS_THRESHOLD", cfg.relax_redis_threshold);
        env_u64!("ARL_RELAX_QUEUE_DEPTH_THRESHOLD", cfg.relax_queue_depth_threshold);
        env_f64!("ARL_RELAX_ERROR_RATE_THRESHOLD", cfg.relax_error_rate_threshold);
        env_f64!("ARL_RELAX_P99_MS_THRESHOLD", cfg.relax_p99_ms_threshold);
        env_secs!("ARL_HYSTERESIS_DURATION_SECS", cfg.hysteresis_duration);

        env_f64!("ARL_ELEVATED_STANDARD_MULTIPLIER", cfg.elevated_standard_multiplier);
        env_f64!("ARL_CRITICAL_STANDARD_MULTIPLIER", cfg.critical_standard_multiplier);
        env_f64!("ARL_ELEVATED_LOW_MULTIPLIER", cfg.elevated_low_multiplier);
        env_f64!("ARL_CRITICAL_LOW_MULTIPLIER", cfg.critical_low_multiplier);
        env_f64!("ARL_EMERGENCY_HIGH_MULTIPLIER", cfg.emergency_high_multiplier);
        env_i64!("ARL_EMERGENCY_MINIMAL_LIMIT", cfg.emergency_minimal_limit);

        env_usize!("ARL_CONSUMER_TREND_BUCKET_COUNT", cfg.consumer_trend_bucket_count);
        env_f64!("ARL_ACCELERATING_CONSUMER_MULTIPLIER", cfg.accelerating_consumer_multiplier);

        env_usize!("ARL_EMERGENCY_QUEUE_MAX_DEPTH", cfg.emergency_queue_max_depth);
        env_secs!("ARL_ELEVATED_MODE_ALERT_DURATION_SECS", cfg.elevated_mode_alert_duration);

        cfg
    }
}
