//! Core domain models for adaptive rate limiting.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Adaptation Mode
// ---------------------------------------------------------------------------

/// The four adaptation modes the platform can be in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdaptationMode {
    /// Static limits apply — no adaptive adjustment.
    Normal,
    /// One or more signals exceeded elevated threshold for sustained duration.
    /// Standard consumers receive 50% of their static limits.
    Elevated,
    /// Multiple signals simultaneously exceeded critical thresholds.
    /// Standard consumers receive 20% of static limits; burst disabled.
    Critical,
    /// Imminent instability detected.
    /// Non-essential endpoints return 503; essential endpoints queue requests.
    Emergency,
}

impl AdaptationMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            AdaptationMode::Normal => "normal",
            AdaptationMode::Elevated => "elevated",
            AdaptationMode::Critical => "critical",
            AdaptationMode::Emergency => "emergency",
        }
    }

    /// Numeric severity (higher = more severe). Used for comparisons.
    pub fn severity(&self) -> u8 {
        match self {
            AdaptationMode::Normal => 0,
            AdaptationMode::Elevated => 1,
            AdaptationMode::Critical => 2,
            AdaptationMode::Emergency => 3,
        }
    }
}

impl std::fmt::Display for AdaptationMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Consumer Priority Tier
// ---------------------------------------------------------------------------

/// Priority tier assigned to a consumer, controlling how aggressively
/// adaptive throttling is applied to them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsumerPriorityTier {
    /// Verified partners and internal microservices.
    /// Protected from adaptive tightening in Normal/Elevated/Critical.
    /// Receive a reduced (but non-zero) limit in Emergency.
    High,
    /// Standard API consumers.
    /// Receive standard adaptive adjustments.
    Standard,
    /// Consumers with low trust or high historical abuse.
    /// Receive the most aggressive throttling.
    Low,
}

impl ConsumerPriorityTier {
    pub fn from_consumer_type(consumer_type: &str) -> Self {
        match consumer_type {
            "backend_microservice" => ConsumerPriorityTier::High,
            "third_party_partner" => ConsumerPriorityTier::High,
            "admin_dashboard" => ConsumerPriorityTier::High,
            "mobile_client" => ConsumerPriorityTier::Standard,
            _ => ConsumerPriorityTier::Standard,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            ConsumerPriorityTier::High => "high",
            ConsumerPriorityTier::Standard => "standard",
            ConsumerPriorityTier::Low => "low",
        }
    }
}

// ---------------------------------------------------------------------------
// Platform Health Signals
// ---------------------------------------------------------------------------

/// A single snapshot of all platform health signals at a point in time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalSnapshot {
    pub captured_at: DateTime<Utc>,
    /// CPU utilisation [0.0, 1.0]
    pub cpu_utilisation: f64,
    /// Database connection pool utilisation [0.0, 1.0]
    pub db_pool_utilisation: f64,
    /// Redis memory pressure [0.0, 1.0]
    pub redis_memory_pressure: f64,
    /// Request queue depth (absolute count)
    pub request_queue_depth: u64,
    /// Error rate over the last sampling window [0.0, 1.0]
    pub error_rate: f64,
    /// p99 response time in milliseconds
    pub p99_response_time_ms: f64,
}

impl SignalSnapshot {
    pub fn zero() -> Self {
        Self {
            captured_at: Utc::now(),
            cpu_utilisation: 0.0,
            db_pool_utilisation: 0.0,
            redis_memory_pressure: 0.0,
            request_queue_depth: 0,
            error_rate: 0.0,
            p99_response_time_ms: 0.0,
        }
    }
}

// ---------------------------------------------------------------------------
// Rolling Signal Average
// ---------------------------------------------------------------------------

/// Maintains a fixed-size ring buffer of signal snapshots and exposes
/// rolling averages for each signal dimension.
#[derive(Debug, Clone)]
pub struct RollingSignalAverage {
    window: std::collections::VecDeque<SignalSnapshot>,
    capacity: usize,
}

impl RollingSignalAverage {
    pub fn new(capacity: usize) -> Self {
        Self {
            window: std::collections::VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    pub fn push(&mut self, snapshot: SignalSnapshot) {
        if self.window.len() >= self.capacity {
            self.window.pop_front();
        }
        self.window.push_back(snapshot);
    }

    pub fn len(&self) -> usize {
        self.window.len()
    }

    pub fn is_empty(&self) -> bool {
        self.window.is_empty()
    }

    fn avg<F: Fn(&SignalSnapshot) -> f64>(&self, f: F) -> f64 {
        if self.window.is_empty() {
            return 0.0;
        }
        let sum: f64 = self.window.iter().map(&f).sum();
        sum / self.window.len() as f64
    }

    pub fn avg_cpu(&self) -> f64 {
        self.avg(|s| s.cpu_utilisation)
    }
    pub fn avg_db_pool(&self) -> f64 {
        self.avg(|s| s.db_pool_utilisation)
    }
    pub fn avg_redis_memory(&self) -> f64 {
        self.avg(|s| s.redis_memory_pressure)
    }
    pub fn avg_queue_depth(&self) -> f64 {
        self.avg(|s| s.request_queue_depth as f64)
    }
    pub fn avg_error_rate(&self) -> f64 {
        self.avg(|s| s.error_rate)
    }
    pub fn avg_p99_ms(&self) -> f64 {
        self.avg(|s| s.p99_response_time_ms)
    }

    /// Latest snapshot (most recent push).
    pub fn latest(&self) -> Option<&SignalSnapshot> {
        self.window.back()
    }
}

// ---------------------------------------------------------------------------
// Mode Transition Record
// ---------------------------------------------------------------------------

/// Persisted record of every adaptation mode transition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModeTransitionRecord {
    pub id: Uuid,
    pub from_mode: AdaptationMode,
    pub to_mode: AdaptationMode,
    pub trigger_signal: String,
    pub signal_values: SignalSnapshot,
    pub reason: String,
    pub is_manual_override: bool,
    pub transitioned_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Per-consumer throttle state
// ---------------------------------------------------------------------------

/// Tracks a consumer's request rate trend for accelerating-request detection.
#[derive(Debug, Clone)]
pub struct ConsumerRateTrend {
    pub consumer_id: uuid::Uuid,
    /// Request counts per sampling bucket (oldest first).
    pub buckets: std::collections::VecDeque<u64>,
    /// Additional per-consumer throttle multiplier (1.0 = no extra throttle).
    pub extra_multiplier: f64,
    pub last_updated: DateTime<Utc>,
}

impl ConsumerRateTrend {
    pub fn new(consumer_id: uuid::Uuid, bucket_count: usize) -> Self {
        Self {
            consumer_id,
            buckets: std::collections::VecDeque::with_capacity(bucket_count),
            extra_multiplier: 1.0,
            last_updated: Utc::now(),
        }
    }

    /// Returns true if the request rate is accelerating (each bucket > previous).
    pub fn is_accelerating(&self) -> bool {
        if self.buckets.len() < 3 {
            return false;
        }
        let v: Vec<u64> = self.buckets.iter().copied().collect();
        // Require at least 2 consecutive increases and last bucket > 1.5× first
        let increasing = v.windows(2).filter(|w| w[1] > w[0]).count();
        let ratio = if v[0] > 0 {
            *v.last().unwrap() as f64 / v[0] as f64
        } else {
            0.0
        };
        increasing >= 2 && ratio > 1.5
    }
}

// ---------------------------------------------------------------------------
// Admin override
// ---------------------------------------------------------------------------

/// A manually forced adaptation mode set by an admin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminOverride {
    pub mode: AdaptationMode,
    pub set_by: String,
    pub reason: Option<String>,
    pub set_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Endpoint category
// ---------------------------------------------------------------------------

/// Whether an endpoint is essential (financial) or non-essential.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointCategory {
    /// Critical financial endpoints — queued in emergency mode.
    Essential,
    /// Non-essential endpoints — return 503 in critical/emergency mode.
    NonEssential,
}

impl EndpointCategory {
    pub fn classify(path: &str) -> Self {
        // Essential: core financial transaction endpoints
        if path.starts_with("/api/onramp/initiate")
            || path.starts_with("/api/offramp/initiate")
            || path.starts_with("/api/wallet/transfer")
            || path.starts_with("/api/bills/pay")
        {
            EndpointCategory::Essential
        } else {
            EndpointCategory::NonEssential
        }
    }
}
