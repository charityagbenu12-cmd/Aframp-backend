use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// The two pre-configured DEX operation templates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "intervention_operation_type", rename_all = "snake_case")]
pub enum OperationType {
    /// Buy cNGN from the DEX to restore peg (inject demand).
    MarketBuy,
    /// Sell cNGN into the DEX to absorb excess supply.
    MarketSell,
}

impl OperationType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MarketBuy => "market_buy",
            Self::MarketSell => "market_sell",
        }
    }
}

/// Lifecycle state of an intervention event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "intervention_status", rename_all = "snake_case")]
pub enum InterventionStatus {
    /// Trigger received, pre-flight checks running.
    Pending,
    /// Transaction submitted to Stellar.
    Executing,
    /// On-chain confirmation received.
    Confirmed,
    /// Execution failed; see `failure_reason`.
    Failed,
    /// System automatically reverted to Normal Mode (peg stable ≥ 30 min).
    Resolved,
}

/// A single emergency intervention record.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct InterventionRecord {
    pub id: Uuid,
    pub triggered_by: String,
    pub operation_type: OperationType,
    pub amount_cngn: String,
    pub source_account: String,
    pub stellar_tx_hash: Option<String>,
    pub status: InterventionStatus,
    pub failure_reason: Option<String>,
    /// Reserve capital consumed (populated post-confirmation).
    pub cost_of_stability_cngn: Option<String>,
    pub peg_deviation_at_trigger: String,
    pub crisis_report_hash: Option<String>,
    pub triggered_at: DateTime<Utc>,
    pub confirmed_at: Option<DateTime<Utc>>,
    pub resolved_at: Option<DateTime<Utc>>,
}

/// Request body for triggering an emergency intervention.
#[derive(Debug, Deserialize)]
pub struct TriggerInterventionRequest {
    /// "market_buy" | "market_sell"
    pub operation_type: OperationType,
    /// Amount of cNGN to inject / withdraw.
    pub amount_cngn: String,
    /// Hardware-token OTP (YubiKey HOTP/TOTP).
    pub hardware_token_otp: String,
    /// Current peg deviation (e.g. "0.85" = 0.85 % off peg).
    pub peg_deviation_percent: String,
}

/// Response returned immediately after trigger.
#[derive(Debug, Serialize)]
pub struct TriggerInterventionResponse {
    pub intervention_id: Uuid,
    pub status: InterventionStatus,
    pub stellar_tx_hash: Option<String>,
    pub message: String,
}

/// Post-intervention cost-of-stability report.
#[derive(Debug, Serialize)]
pub struct CrisisReport {
    pub intervention_id: Uuid,
    pub operation_type: OperationType,
    pub amount_cngn: String,
    pub cost_of_stability_cngn: String,
    pub peg_deviation_at_trigger: String,
    pub stellar_tx_hash: String,
    pub triggered_by: String,
    pub triggered_at: DateTime<Utc>,
    pub confirmed_at: DateTime<Utc>,
    /// SHA-256 of the serialised report — stored in tamper-evident log.
    pub report_hash: String,
}

/// System-wide intervention mode (stored in Redis / DB).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SystemMode {
    Normal,
    UnderIntervention,
}

/// Query params for listing interventions.
#[derive(Debug, Deserialize)]
pub struct ListInterventionsQuery {
    pub status: Option<InterventionStatus>,
    pub page: Option<i64>,
    pub page_size: Option<i64>,
}

impl ListInterventionsQuery {
    pub fn page(&self) -> i64 {
        self.page.unwrap_or(1).max(1)
    }
    pub fn page_size(&self) -> i64 {
        self.page_size.unwrap_or(20).clamp(1, 100)
    }
    pub fn offset(&self) -> i64 {
        (self.page() - 1) * self.page_size()
    }
}
