//! AML data models

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// AML flag severity levels (FATF-aligned)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "text")]
pub enum AmlFlagLevel {
    /// Level 1 — informational, log only
    Low,
    /// Level 2 — elevated, manual review recommended
    Medium,
    /// Level 3 — critical, instant alert to AML Officer
    Critical,
}

impl std::fmt::Display for AmlFlagLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AmlFlagLevel::Low => write!(f, "LOW"),
            AmlFlagLevel::Medium => write!(f, "MEDIUM"),
            AmlFlagLevel::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// Reason a transaction was flagged
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AmlFlag {
    /// Sender or recipient matched a sanctions list entry
    SanctionsHit { list: String, matched_name: String },
    /// Multiple small transactions to same recipient (smurfing)
    SmurfingDetected { tx_count: u32, window_hours: u32, total_amount: String },
    /// Funds on-ramped and immediately off-ramped to high-risk jurisdiction
    RapidFlip { on_ramp_tx_id: Uuid, off_ramp_corridor: String, elapsed_minutes: u32 },
    /// High corridor risk score
    HighCorridorRisk { corridor: String, risk_score: f64, reason: String },
}

/// Lifecycle state of an AML compliance case
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "text")]
pub enum AmlCaseStatus {
    /// Awaiting compliance officer review
    PendingComplianceReview,
    /// Cleared by compliance officer — transaction may proceed
    Cleared,
    /// Permanently blocked by compliance officer
    PermanentlyBlocked,
}

/// Input to the AML screening pipeline
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AmlScreeningRequest {
    pub transaction_id: Uuid,
    pub wallet_address: String,
    pub sender_name: String,
    pub sender_id: String,
    pub recipient_name: String,
    pub recipient_id: String,
    pub amount: String,
    pub from_currency: String,
    pub to_currency: String,
    /// ISO 3166-1 alpha-2 origin country
    pub origin_country: String,
    /// ISO 3166-1 alpha-2 destination country
    pub destination_country: String,
    pub created_at: DateTime<Utc>,
}

/// Result of the full AML screening pipeline
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AmlScreeningResult {
    pub transaction_id: Uuid,
    /// Composite risk score 0.0–1.0
    pub risk_score: f64,
    pub flag_level: Option<AmlFlagLevel>,
    pub flags: Vec<AmlFlag>,
    /// Whether the transaction is cleared to proceed
    pub cleared: bool,
    /// If not cleared, the case ID for compliance review
    pub case_id: Option<Uuid>,
    pub screened_at: DateTime<Utc>,
}

/// Per-corridor risk weight configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorridorRiskWeight {
    pub origin_country: String,
    pub destination_country: String,
    /// 0.0–1.0 weight applied to base risk score
    pub weight: f64,
    /// Human-readable reason (e.g. "FATF Grey List", "Basel AML Index High")
    pub reason: String,
}

/// Detected velocity pattern
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VelocityPattern {
    pub wallet_address: String,
    pub recipient_id: String,
    pub tx_count: u32,
    pub total_amount: String,
    pub window_hours: u32,
    pub detected_at: DateTime<Utc>,
}
