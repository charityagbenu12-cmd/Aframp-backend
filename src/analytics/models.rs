use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Validated date-range query parameters shared across all analytics endpoints.
/// Both bounds are required and the range is capped at 366 days to prevent
/// unbounded heavy queries.
#[derive(Debug, Deserialize)]
pub struct DateRangeParams {
    pub from: DateTime<Utc>,
    pub to: DateTime<Utc>,
    /// Grouping granularity: "daily" | "weekly" | "monthly"
    #[serde(default = "default_period")]
    pub period: String,
}

fn default_period() -> String {
    "daily".to_string()
}

impl DateRangeParams {
    /// Returns an error string if the range is invalid or exceeds 366 days.
    pub fn validate(&self) -> Result<(), String> {
        if self.to <= self.from {
            return Err("`to` must be after `from`".into());
        }
        let days = (self.to - self.from).num_days();
        if days > 366 {
            return Err("Date range must not exceed 366 days".into());
        }
        match self.period.as_str() {
            "daily" | "weekly" | "monthly" => Ok(()),
            other => Err(format!("Invalid period `{other}`. Use daily, weekly, or monthly")),
        }
    }
}

// ── Transaction Volume ────────────────────────────────────────────────────────

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct VolumeByPeriod {
    pub period: String,
    pub currency: String,
    pub transaction_type: String,
    pub status: String,
    pub count: i64,
    pub total_volume: sqlx::types::BigDecimal,
}

#[derive(Debug, Serialize)]
pub struct TransactionVolumeResponse {
    pub from: DateTime<Utc>,
    pub to: DateTime<Utc>,
    pub period: String,
    pub data: Vec<VolumeByPeriod>,
}

// ── cNGN Conversions ──────────────────────────────────────────────────────────

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct CngnConversionPeriod {
    pub period: String,
    pub minted: sqlx::types::BigDecimal,
    pub redeemed: sqlx::types::BigDecimal,
    pub avg_rate: sqlx::types::BigDecimal,
    pub net_circulation_change: sqlx::types::BigDecimal,
}

#[derive(Debug, Serialize)]
pub struct CngnConversionsResponse {
    pub from: DateTime<Utc>,
    pub to: DateTime<Utc>,
    pub period: String,
    pub data: Vec<CngnConversionPeriod>,
}

// ── Provider Performance ──────────────────────────────────────────────────────

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct ProviderPerformancePeriod {
    pub period: String,
    pub provider: String,
    pub total_count: i64,
    pub success_count: i64,
    pub success_rate: sqlx::types::BigDecimal,
    pub avg_processing_seconds: sqlx::types::BigDecimal,
    pub volume_share_pct: sqlx::types::BigDecimal,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct ProviderFailureBreakdown {
    pub provider: String,
    pub failure_reason: String,
    pub count: i64,
}

#[derive(Debug, Serialize)]
pub struct ProviderPerformanceResponse {
    pub from: DateTime<Utc>,
    pub to: DateTime<Utc>,
    pub period: String,
    pub performance: Vec<ProviderPerformancePeriod>,
    pub failure_breakdown: Vec<ProviderFailureBreakdown>,
}

// ── Summary ───────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct DeltaMetric {
    pub today: sqlx::types::BigDecimal,
    pub yesterday: sqlx::types::BigDecimal,
    pub delta_pct: sqlx::types::BigDecimal,
}

#[derive(Debug, Serialize)]
pub struct HealthIndicators {
    pub worker_status: String,
    pub rate_freshness_seconds: i64,
    pub active_providers: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct SummaryResponse {
    pub date: String,
    pub total_transactions: DeltaMetric,
    pub total_volume_ngn: DeltaMetric,
    pub total_cngn_transferred: DeltaMetric,
    pub active_wallets: DeltaMetric,
    pub health: HealthIndicators,
}
