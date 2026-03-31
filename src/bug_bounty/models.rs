use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::FromRow;
use std::collections::HashMap;
use thiserror::Error;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "bb_report_status", rename_all = "snake_case")]
pub enum ReportStatus {
    New,
    Acknowledged,
    Triaged,
    InRemediation,
    Resolved,
    Duplicate,
    OutOfScope,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "bb_severity", rename_all = "snake_case")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Informational,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "bb_programme_phase", rename_all = "snake_case")]
pub enum ProgrammePhase {
    Private,
    Public,
}

// ---------------------------------------------------------------------------
// Core domain structs
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct BugBountyReport {
    pub id: Uuid,
    pub researcher_id: String,
    pub severity: Severity,
    pub affected_component: String,
    pub vulnerability_type: String,
    pub title: String,
    pub description: String,
    pub proof_of_concept: Option<String>,
    pub submission_content: Value,
    pub status: ReportStatus,
    pub duplicate_of: Option<Uuid>,
    pub acknowledgement_sla_deadline: DateTime<Utc>,
    pub triage_sla_deadline: DateTime<Utc>,
    pub acknowledged_at: Option<DateTime<Utc>>,
    pub triaged_at: Option<DateTime<Utc>>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub coordinated_disclosure_date: Option<DateTime<Utc>>,
    pub remediation_ref: Option<String>,
    pub source: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct CommunicationLogEntry {
    pub id: Uuid,
    pub report_id: Uuid,
    pub direction: String,
    pub notification_type: String,
    pub content: Value,
    pub sent_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct RewardRecord {
    pub id: Uuid,
    pub report_id: Uuid,
    pub researcher_id: String,
    pub amount_usd: Decimal,
    pub justification: String,
    pub escalation_justification: Option<String>,
    pub payment_initiated_at: DateTime<Utc>,
    pub created_by: Uuid,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ResearcherInvitation {
    pub id: Uuid,
    pub researcher_id: String,
    pub status: String,
    pub created_by: Uuid,
    pub created_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub revoked_by: Option<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ProgrammeState {
    pub id: Uuid,
    pub phase: ProgrammePhase,
    pub launched_at: DateTime<Utc>,
    pub transitioned_to_public_at: Option<DateTime<Utc>>,
    pub transitioned_by: Option<Uuid>,
}

// ---------------------------------------------------------------------------
// DTOs
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateReportRequest {
    pub researcher_id: String,
    pub severity: Severity,
    pub affected_component: String,
    pub vulnerability_type: String,
    pub title: String,
    pub description: String,
    pub proof_of_concept: Option<String>,
    pub submission_content: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateReportRequest {
    pub status: Option<ReportStatus>,
    pub severity: Option<Severity>,
    pub remediation_ref: Option<String>,
    pub coordinated_disclosure_date: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordRewardRequest {
    pub amount_usd: Decimal,
    pub justification: String,
    pub escalation_justification: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateInvitationRequest {
    pub researcher_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsTrend {
    pub mean_time_to_acknowledge_delta_hours: f64,
    pub mean_time_to_triage_delta_hours: f64,
    pub mean_time_to_reward_delta_hours: f64,
    pub duplicate_rate_delta_percent: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgrammeMetrics {
    pub mean_time_to_acknowledge_hours: f64,
    pub mean_time_to_triage_hours: f64,
    pub mean_time_to_reward_hours: f64,
    pub duplicate_rate_percent: f64,
    pub valid_finding_rate_by_severity: HashMap<Severity, f64>,
    pub trend: MetricsTrend,
    pub open_reports_by_severity: HashMap<Severity, u64>,
    pub total_rewards_paid_usd: Decimal,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnmetCriterion {
    pub criterion: String,
    pub current_value: Value,
    pub required_value: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransitionResult {
    pub success: bool,
    pub unmet_criteria: Vec<UnmetCriterion>,
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct BugBountyConfig {
    // SLA
    pub acknowledgement_sla_hours: i64,
    pub triage_sla_hours: i64,
    pub sla_poll_interval_secs: u64,

    // Reward tiers (USD)
    pub reward_critical_min: u64,
    pub reward_critical_max: u64,
    pub reward_high_min: u64,
    pub reward_high_max: u64,
    pub reward_medium_min: u64,
    pub reward_medium_max: u64,
    pub reward_low_min: u64,
    pub reward_low_max: u64,
    // informational: always 0

    // Budget
    pub monthly_budget_threshold_usd: u64,

    // Transition criteria
    pub min_invited_researchers_participated: u32,
    pub min_valid_findings_processed: u32,
    pub min_remediation_rate_percent: f64,
    pub stabilisation_period_days: u64,
}

impl Default for BugBountyConfig {
    fn default() -> Self {
        Self {
            acknowledgement_sla_hours: 24,
            triage_sla_hours: 72,
            sla_poll_interval_secs: 300,
            reward_critical_min: 5000,
            reward_critical_max: 20000,
            reward_high_min: 1000,
            reward_high_max: 5000,
            reward_medium_min: 250,
            reward_medium_max: 1000,
            reward_low_min: 50,
            reward_low_max: 250,
            monthly_budget_threshold_usd: 50000,
            min_invited_researchers_participated: 5,
            min_valid_findings_processed: 3,
            min_remediation_rate_percent: 80.0,
            stabilisation_period_days: 30,
        }
    }
}

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum BugBountyError {
    #[error("report not found")]
    ReportNotFound,

    #[error("unauthorized")]
    Unauthorized,

    #[error("duplicate report: original is {original_id}")]
    DuplicateReport { original_id: Uuid },

    #[error("reward amount {amount} is out of tier for {severity:?} (min: {min}, max: {max})")]
    RewardOutOfTier {
        severity: Severity,
        amount: Decimal,
        min: u64,
        max: u64,
    },

    #[error("transition criteria not met")]
    TransitionCriteriaNotMet { unmet: Vec<UnmetCriterion> },

    #[error("invitation required for private programme")]
    InvitationRequired,

    #[error("database error: {0}")]
    DatabaseError(#[from] sqlx::Error),
}
