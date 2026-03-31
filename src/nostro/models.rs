//! Nostro account data models

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::types::BigDecimal;
use uuid::Uuid;

/// A pre-funded foreign bank account (Nostro account)
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct NostroAccount {
    pub id: Uuid,
    /// e.g. "NG-KE", "NG-GH", "NG-ZA"
    pub corridor_id: String,
    /// ISO 4217 currency code of the destination country
    pub currency: String,
    /// Partner bank name (e.g. "KCB Kenya", "Zenith Ghana")
    pub bank_name: String,
    /// Account number or Virtual IBAN
    pub account_reference: String,
    /// Safety buffer as a fraction of average daily volume (e.g. 0.20 = 20%)
    pub safety_buffer_fraction: f64,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Real-time balance snapshot for a Nostro account
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct NostroBalance {
    pub id: Uuid,
    pub account_id: Uuid,
    pub cleared_balance: BigDecimal,
    pub pending_balance: BigDecimal,
    pub average_daily_volume: BigDecimal,
    pub polled_at: DateTime<Utc>,
    pub source: String, // "bank_api" | "manual"
}

/// Whether a corridor is available for new transactions
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CorridorStatus {
    Active,
    /// Disabled due to insufficient Nostro balance
    DisabledInsufficientFunds,
    /// Manually disabled by Treasury
    DisabledManual,
}

/// Alert sent to Treasury when balance drops below safety buffer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiquidityAlert {
    pub account_id: Uuid,
    pub corridor_id: String,
    pub currency: String,
    pub current_balance: BigDecimal,
    pub safety_buffer_amount: BigDecimal,
    pub shortfall: BigDecimal,
    pub alerted_at: DateTime<Utc>,
}

/// End-of-day reconciliation result
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct EodReconciliationResult {
    pub id: Uuid,
    pub account_id: Uuid,
    pub corridor_id: String,
    pub date: chrono::NaiveDate,
    /// Total cNGN burned/locked on-chain for this corridor
    pub onchain_burns: BigDecimal,
    /// Total fiat outflows recorded in shadow ledger
    pub fiat_outflows: BigDecimal,
    /// Difference (breakage)
    pub discrepancy: BigDecimal,
    pub status: String, // "matched" | "discrepant"
    pub created_at: DateTime<Utc>,
}
