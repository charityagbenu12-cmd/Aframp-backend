//! Domain models for the Compliance Registry (Issue #2.02).

use chrono::{DateTime, NaiveDate, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "license_status", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum LicenseStatus {
    Active,
    Expired,
    Suspended,
    PendingRenewal,
    Revoked,
}

impl LicenseStatus {
    pub fn is_operable(&self) -> bool {
        matches!(self, LicenseStatus::Active)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            LicenseStatus::Active => "active",
            LicenseStatus::Expired => "expired",
            LicenseStatus::Suspended => "suspended",
            LicenseStatus::PendingRenewal => "pending_renewal",
            LicenseStatus::Revoked => "revoked",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "corridor_status", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum CorridorStatus {
    Active,
    Suspended,
    BlockedLicenseExpired,
    BlockedLicenseSuspended,
    BlockedRegulatory,
}

impl CorridorStatus {
    pub fn is_open(&self) -> bool {
        matches!(self, CorridorStatus::Active)
    }
}

// ---------------------------------------------------------------------------
// Core structs
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct PaymentCorridor {
    pub id: Uuid,
    pub source_country: String,
    pub destination_country: String,
    pub source_currency: String,
    pub destination_currency: String,
    pub status: CorridorStatus,
    pub status_reason: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub updated_by: Option<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct CorridorLicense {
    pub id: Uuid,
    pub corridor_id: Uuid,
    pub license_type: String,
    pub license_number: String,
    pub issuing_authority: String,
    pub issuing_country: String,
    pub issued_date: NaiveDate,
    pub expiry_date: NaiveDate,
    pub renewal_deadline: Option<NaiveDate>,
    pub status: LicenseStatus,
    pub document_url: Option<String>,
    pub notes: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub created_by: Option<Uuid>,
    pub updated_by: Option<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct RegulatoryRuleset {
    pub id: Uuid,
    pub corridor_id: Uuid,
    pub rule_name: String,
    pub rule_description: Option<String>,
    pub max_single_transaction: Option<Decimal>,
    pub max_daily_volume: Option<Decimal>,
    pub max_monthly_volume: Option<Decimal>,
    pub currency: String,
    pub mandated_by: String,
    pub is_active: bool,
    pub effective_from: DateTime<Utc>,
    pub effective_until: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub updated_by: Option<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct TransactionComplianceTag {
    pub id: Uuid,
    pub transaction_id: Uuid,
    pub corridor_id: Uuid,
    pub license_id: Option<Uuid>,
    pub ruleset_id: Option<Uuid>,
    pub tagged_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Request / Response DTOs
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct CreateCorridorRequest {
    pub source_country: String,
    pub destination_country: String,
    pub source_currency: String,
    pub destination_currency: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateLicenseRequest {
    pub corridor_id: Uuid,
    pub license_type: String,
    pub license_number: String,
    pub issuing_authority: String,
    pub issuing_country: String,
    pub issued_date: NaiveDate,
    pub expiry_date: NaiveDate,
    pub renewal_deadline: Option<NaiveDate>,
    pub document_url: Option<String>,
    pub notes: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateLicenseStatusRequest {
    pub status: LicenseStatus,
    pub reason: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreateRulesetRequest {
    pub corridor_id: Uuid,
    pub rule_name: String,
    pub rule_description: Option<String>,
    pub max_single_transaction: Option<Decimal>,
    pub max_daily_volume: Option<Decimal>,
    pub max_monthly_volume: Option<Decimal>,
    pub currency: String,
    pub mandated_by: String,
    pub effective_from: Option<DateTime<Utc>>,
    pub effective_until: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateRulesetRequest {
    pub rule_description: Option<String>,
    pub max_single_transaction: Option<Decimal>,
    pub max_daily_volume: Option<Decimal>,
    pub max_monthly_volume: Option<Decimal>,
    pub is_active: Option<bool>,
    pub effective_until: Option<DateTime<Utc>>,
}

/// Result of a compliance check for a transaction.
#[derive(Debug, Clone, Serialize)]
pub struct ComplianceCheckResult {
    pub allowed: bool,
    pub corridor_id: Uuid,
    pub license_id: Option<Uuid>,
    pub ruleset_id: Option<Uuid>,
    pub denial_reason: Option<String>,
}

/// Compliance Readiness Report for a corridor over a time range.
#[derive(Debug, Clone, Serialize)]
pub struct ComplianceReadinessReport {
    pub corridor: PaymentCorridor,
    pub licenses: Vec<CorridorLicense>,
    pub rulesets: Vec<RegulatoryRuleset>,
    pub is_compliant: bool,
    pub issues: Vec<String>,
    pub generated_at: DateTime<Utc>,
    pub period_from: DateTime<Utc>,
    pub period_to: DateTime<Utc>,
}
