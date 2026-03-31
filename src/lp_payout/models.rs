use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct LpProvider {
    pub id: Uuid,
    pub stellar_address: String,
    pub display_name: String,
    pub is_active: bool,
    pub whitelisted_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct LpPoolSnapshot {
    pub id: Uuid,
    pub snapshot_at: DateTime<Utc>,
    pub lp_provider_id: Uuid,
    pub pool_id: String,
    pub lp_balance_stroops: i64,
    pub total_pool_stroops: i64,
    pub pro_rata_share: sqlx::types::BigDecimal,
    pub volume_stroops: i64,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct LpRewardEpoch {
    pub id: Uuid,
    pub epoch_start: DateTime<Utc>,
    pub epoch_end: DateTime<Utc>,
    pub total_fees_stroops: i64,
    pub total_volume_stroops: i64,
    pub mining_rate_per_1000: sqlx::types::BigDecimal,
    pub is_finalized: bool,
    pub finalized_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct LpAccruedReward {
    pub id: Uuid,
    pub epoch_id: Uuid,
    pub lp_provider_id: Uuid,
    pub reward_type: String,
    pub accrued_stroops: i64,
    pub paid_stroops: i64,
    pub is_wash_trade_excluded: bool,
    pub compliance_flagged: bool,
    pub compliance_reason: Option<String>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct LpPayout {
    pub id: Uuid,
    pub epoch_id: Uuid,
    pub lp_provider_id: Uuid,
    pub stellar_address: String,
    pub total_stroops: i64,
    pub status: String,
    pub stellar_tx_hash: Option<String>,
    pub compliance_withheld: bool,
    pub compliance_reason: Option<String>,
    pub attempted_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// API / service types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccruedVsPaidSummary {
    pub lp_provider_id: Uuid,
    pub stellar_address: String,
    pub epoch_id: Uuid,
    pub epoch_start: DateTime<Utc>,
    pub epoch_end: DateTime<Utc>,
    pub accrued_stroops: i64,
    pub paid_stroops: i64,
    pub pending_stroops: i64,
    pub compliance_flagged: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochRewardSummary {
    pub epoch_id: Uuid,
    pub epoch_start: DateTime<Utc>,
    pub epoch_end: DateTime<Utc>,
    pub total_fees_stroops: i64,
    pub total_volume_stroops: i64,
    pub payouts: Vec<PayoutRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayoutRecord {
    pub lp_provider_id: Uuid,
    pub stellar_address: String,
    pub total_stroops: i64,
    pub status: String,
    pub stellar_tx_hash: Option<String>,
    pub compliance_withheld: bool,
}

/// Compliance threshold in stroops above which a payout is flagged.
/// Default: 10,000,000 cNGN (10M stroops = 1 cNGN at 7 decimal places).
/// Configurable via LP_COMPLIANCE_THRESHOLD_STROOPS env var.
pub fn compliance_threshold_stroops() -> i64 {
    std::env::var("LP_COMPLIANCE_THRESHOLD_STROOPS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10_000_000_000) // 1,000 cNGN in stroops
}

/// Mining rate: cNGN stroops earned per 1,000 NGN provided per hour.
/// Configurable via LP_MINING_RATE_PER_1000 env var.
pub fn default_mining_rate_per_1000() -> f64 {
    std::env::var("LP_MINING_RATE_PER_1000")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(100.0) // 100 stroops per 1000 NGN/hr
}
