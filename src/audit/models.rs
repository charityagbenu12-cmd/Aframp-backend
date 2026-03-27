use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "audit_event_category", rename_all = "snake_case")]
pub enum AuditEventCategory {
    Authentication,
    Credential,
    FinancialTransaction,
    Configuration,
    Security,
    Admin,
    DataAccess,
}

impl AuditEventCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Authentication => "authentication",
            Self::Credential => "credential",
            Self::FinancialTransaction => "financial_transaction",
            Self::Configuration => "configuration",
            Self::Security => "security",
            Self::Admin => "admin",
            Self::DataAccess => "data_access",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "audit_actor_type", rename_all = "snake_case")]
pub enum AuditActorType {
    Consumer,
    Admin,
    Microservice,
    System,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "audit_outcome", rename_all = "snake_case")]
pub enum AuditOutcome {
    Success,
    Failure,
    Partial,
}

/// A single audit log entry — the canonical record of one API interaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogEntry {
    pub id: Uuid,
    pub event_type: String,
    pub event_category: AuditEventCategory,
    pub actor_type: AuditActorType,
    pub actor_id: Option<String>,
    pub actor_ip: Option<String>,
    pub actor_consumer_type: Option<String>,
    pub session_id: Option<String>,
    pub target_resource_type: Option<String>,
    pub target_resource_id: Option<String>,
    pub request_method: String,
    pub request_path: String,
    pub request_body_hash: Option<String>,
    pub response_status: i32,
    pub response_latency_ms: i64,
    pub outcome: AuditOutcome,
    pub failure_reason: Option<String>,
    pub environment: String,
    pub previous_entry_hash: Option<String>,
    pub current_entry_hash: String,
    pub created_at: DateTime<Utc>,
}

/// Pending entry before hash chain is computed — used by the middleware.
#[derive(Debug, Clone)]
pub struct PendingAuditEntry {
    pub event_type: String,
    pub event_category: AuditEventCategory,
    pub actor_type: AuditActorType,
    pub actor_id: Option<String>,
    pub actor_ip: Option<String>,
    pub actor_consumer_type: Option<String>,
    pub session_id: Option<String>,
    pub target_resource_type: Option<String>,
    pub target_resource_id: Option<String>,
    pub request_method: String,
    pub request_path: String,
    pub request_body_hash: Option<String>,
    pub response_status: i32,
    pub response_latency_ms: i64,
    pub outcome: AuditOutcome,
    pub failure_reason: Option<String>,
    pub environment: String,
}

// ── Query / filter types ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct AuditLogFilter {
    pub event_category: Option<AuditEventCategory>,
    pub actor_id: Option<String>,
    pub actor_type: Option<AuditActorType>,
    pub target_resource_type: Option<String>,
    pub target_resource_id: Option<String>,
    pub outcome: Option<AuditOutcome>,
    pub environment: Option<String>,
    pub date_from: Option<DateTime<Utc>>,
    pub date_to: Option<DateTime<Utc>>,
    pub page: Option<i64>,
    pub page_size: Option<i64>,
}

impl AuditLogFilter {
    pub fn page(&self) -> i64 {
        self.page.unwrap_or(1).max(1)
    }
    pub fn page_size(&self) -> i64 {
        self.page_size.unwrap_or(50).clamp(1, 200)
    }
    pub fn offset(&self) -> i64 {
        (self.page() - 1) * self.page_size()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditLogPage {
    pub entries: Vec<AuditLogEntry>,
    pub total: i64,
    pub page: i64,
    pub page_size: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct HashChainVerificationResult {
    pub valid: bool,
    pub total_checked: i64,
    pub first_sequence_id: Option<Uuid>,
    pub last_sequence_id: Option<Uuid>,
    pub tampered_entries: Vec<TamperedAuditEntry>,
    pub gaps_detected: Vec<String>,
    pub verified_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TamperedAuditEntry {
    pub entry_id: Uuid,
    pub expected_hash: String,
    pub actual_hash: String,
    pub created_at: DateTime<Utc>,
}
