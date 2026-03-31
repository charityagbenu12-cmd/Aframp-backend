use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Slippage severity thresholds.
pub const SLIPPAGE_WARNING_PCT: f64 = 0.5;
pub const SLIPPAGE_CRITICAL_PCT: f64 = 2.0;

/// Minimum cool-down between rebalancing triggers (anti-oscillation).
pub const REBALANCE_COOLDOWN_SECS: u64 = 300; // 5 minutes

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "liquidity_alert_level", rename_all = "snake_case")]
pub enum AlertLevel {
    Healthy,
    Warning,
    Critical,
}

impl AlertLevel {
    pub fn from_slippage(pct: f64) -> Self {
        if pct >= SLIPPAGE_CRITICAL_PCT {
            Self::Critical
        } else if pct >= SLIPPAGE_WARNING_PCT {
            Self::Warning
        } else {
            Self::Healthy
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Warning => "warning",
            Self::Critical => "critical",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "rebalance_trigger_type", rename_all = "snake_case")]
pub enum RebalanceTrigger {
    /// Buy-side thin — inject cNGN from Treasury to Market Maker.
    Deficit,
    /// Sell-side excess — buy back cNGN to absorb surplus.
    Surplus,
}

/// A single order-book depth snapshot.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct DepthSnapshot {
    pub id: Uuid,
    pub sampled_at: DateTime<Utc>,
    /// Simulated trade size in cNGN.
    pub probe_amount_cngn: String,
    /// Oracle mid-price (NGN per cNGN).
    pub oracle_price: String,
    /// Effective execution price from order-book simulation.
    pub execution_price: String,
    /// Slippage percentage vs oracle price.
    pub slippage_pct: f64,
    pub alert_level: AlertLevel,
    /// Total bid-side depth in cNGN.
    pub bid_depth_cngn: String,
    /// Total ask-side depth in cNGN.
    pub ask_depth_cngn: String,
    /// Constant-product k value of the Stellar LP (if available).
    pub amm_k_value: Option<String>,
    pub rebalance_triggered: bool,
}

/// A rebalancing event record.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct RebalanceEvent {
    pub id: Uuid,
    pub trigger: RebalanceTrigger,
    pub amount_cngn: String,
    pub snapshot_id: Uuid,
    /// Vault transfer request ID (links to multi-sig framework).
    pub vault_request_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
}

/// Live market depth summary for the dashboard.
#[derive(Debug, Serialize)]
pub struct MarketDepthSummary {
    pub sampled_at: DateTime<Utc>,
    pub slippage_pct: f64,
    pub alert_level: AlertLevel,
    pub bid_depth_cngn: String,
    pub ask_depth_cngn: String,
    pub oracle_price: String,
    pub execution_price: String,
    pub amm_pool_exhaustion_risk: bool,
}

/// Horizon order-book offer entry.
#[derive(Debug, Deserialize)]
pub struct HorizonOffer {
    pub amount: String,
    pub price: String,
}

/// Horizon order-book response.
#[derive(Debug, Deserialize)]
pub struct HorizonOrderBook {
    pub bids: Vec<HorizonOffer>,
    pub asks: Vec<HorizonOffer>,
}

/// Horizon liquidity pool response.
#[derive(Debug, Deserialize)]
pub struct HorizonLiquidityPool {
    pub reserves: Vec<HorizonPoolReserve>,
}

#[derive(Debug, Deserialize)]
pub struct HorizonPoolReserve {
    pub amount: String,
}
