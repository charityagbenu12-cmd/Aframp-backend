use serde::{Deserialize, Serialize};

/// Target bid-ask spread bounds (as a fraction, e.g. 0.001 = 0.1%).
pub const SPREAD_MIN: f64 = 0.001; // 0.1%
pub const SPREAD_MAX: f64 = 0.005; // 0.5%

/// Number of ladder rungs on each side of the book.
pub const LADDER_RUNGS: usize = 5;

/// Price step between ladder rungs (fraction of mid-price).
pub const LADDER_STEP: f64 = 0.001;

/// How often the bot re-quotes (seconds).
pub const REQUOTE_INTERVAL_SECS: u64 = 5;

/// Minimum price movement (fraction) that triggers an immediate re-quote.
pub const REQUOTE_THRESHOLD: f64 = 0.002; // 0.2%

/// Circuit breaker: max reserve drain rate per minute (fraction of inventory).
pub const CIRCUIT_BREAKER_DRAIN_RATE: f64 = 0.05; // 5% per minute

/// Circuit breaker: pause duration after trip (seconds).
pub const CIRCUIT_BREAKER_PAUSE_SECS: u64 = 300;

/// Minimum cNGN inventory before bot pauses for refill.
pub const MIN_CNGN_INVENTORY: f64 = 100_000.0;

/// Minimum counter-asset inventory before bot pauses for refill.
pub const MIN_COUNTER_INVENTORY: f64 = 100_000.0;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarketMakerConfig {
    /// Stellar Horizon URL.
    pub horizon_url: String,
    /// cNGN asset string, e.g. "cNGN:GISSUER..."
    pub cngn_asset: String,
    /// Counter asset, e.g. "XLM" or "USDC:GCIRCLE..."
    pub counter_asset: String,
    /// Market maker's Stellar account (public key).
    pub mm_account: String,
    /// Target half-spread (fraction).
    pub target_spread: f64,
    /// Number of ladder rungs per side.
    pub ladder_rungs: usize,
    /// Price step between rungs (fraction).
    pub ladder_step: f64,
    /// Re-quote interval in seconds.
    pub requote_interval_secs: u64,
    /// Minimum price move to trigger immediate re-quote.
    pub requote_threshold: f64,
}

impl Default for MarketMakerConfig {
    fn default() -> Self {
        Self {
            horizon_url: std::env::var("STELLAR_HORIZON_URL")
                .unwrap_or_else(|_| "https://horizon-testnet.stellar.org".into()),
            cngn_asset: std::env::var("CNGN_ASSET_STRING")
                .unwrap_or_else(|_| "cNGN:GCNGN_ISSUER_PLACEHOLDER".into()),
            counter_asset: std::env::var("MM_COUNTER_ASSET")
                .unwrap_or_else(|_| "XLM".into()),
            mm_account: std::env::var("MM_STELLAR_ACCOUNT")
                .unwrap_or_default(),
            target_spread: SPREAD_MIN,
            ladder_rungs: LADDER_RUNGS,
            ladder_step: LADDER_STEP,
            requote_interval_secs: REQUOTE_INTERVAL_SECS,
            requote_threshold: REQUOTE_THRESHOLD,
        }
    }
}
