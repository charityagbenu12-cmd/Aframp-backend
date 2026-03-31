use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ── Auditor account ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct AuditorAccount {
    pub id: Uuid,
    pub email: String,
    pub display_name: String,
    pub organisation: String,
    pub mfa_enabled: bool,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
}

// ── Access window ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct AuditorAccessWindow {
    pub id: Uuid,
    pub auditor_id: Uuid,
    pub scope_label: String,
    pub data_from: DateTime<Utc>,
    pub data_to: DateTime<Utc>,
    pub access_from: DateTime<Utc>,
    pub access_to: DateTime<Utc>,
}

// ── Session ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct AuditorSession {
    pub id: Uuid,
    pub auditor_id: Uuid,
    pub window_id: Uuid,
    pub session_token: String,
    pub ip_address: String,
    pub expires_at: DateTime<Utc>,
    pub data_from: DateTime<Utc>,
    pub data_to: DateTime<Utc>,
}

// ── Auth request / response ───────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct AuditorLoginRequest {
    pub email: String,
    pub password: String,
    pub totp_code: String,
}

#[derive(Debug, Serialize)]
pub struct AuditorLoginResponse {
    pub session_token: String,
    pub expires_at: DateTime<Utc>,
    pub scope_label: String,
    pub data_from: DateTime<Utc>,
    pub data_to: DateTime<Utc>,
}

// ── Export query ──────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct AuditExportQuery {
    pub date_from: Option<DateTime<Utc>>,
    pub date_to: Option<DateTime<Utc>>,
    pub event_type: Option<String>,
    pub redemption_id: Option<String>,
    pub min_amount: Option<f64>,
    pub max_amount: Option<f64>,
    /// "json" | "csv" | "pdf"  (pdf = JSON with checksum envelope)
    pub format: Option<String>,
    pub max_rows: Option<i64>,
}

// ── Quarterly packet ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct QuarterlyPacket {
    pub id: Uuid,
    pub quarter_label: String,
    pub data_from: DateTime<Utc>,
    pub data_to: DateTime<Utc>,
    pub checksum: String,
    pub row_count: i64,
    pub generated_at: DateTime<Utc>,
}

// ── Access log entry (audit-of-auditor) ──────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct AuditorAccessLogEntry {
    pub id: Uuid,
    pub session_id: Uuid,
    pub auditor_id: Uuid,
    pub action: String,
    pub query_params: Option<serde_json::Value>,
    pub row_count: Option<i64>,
    pub file_checksum: Option<String>,
    pub file_name: Option<String>,
    pub ip_address: String,
    pub created_at: DateTime<Utc>,
}

// ── Admin management requests ─────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct CreateAuditorRequest {
    pub email: String,
    pub display_name: String,
    pub organisation: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateAccessWindowRequest {
    pub auditor_id: Uuid,
    pub scope_label: String,
    pub data_from: DateTime<Utc>,
    pub data_to: DateTime<Utc>,
    pub access_from: DateTime<Utc>,
    pub access_to: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct AddIpWhitelistRequest {
    pub auditor_id: Uuid,
    pub cidr: String,
    pub label: Option<String>,
}
