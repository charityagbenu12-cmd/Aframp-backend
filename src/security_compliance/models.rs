//! Domain models for the security compliance framework.

use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Enumerations
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "vuln_severity", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum VulnSeverity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

impl VulnSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            VulnSeverity::Critical => "critical",
            VulnSeverity::High => "high",
            VulnSeverity::Medium => "medium",
            VulnSeverity::Low => "low",
            VulnSeverity::Informational => "informational",
        }
    }

    /// Base weight used in posture score calculation.
    /// Higher severity = higher weight.
    pub fn base_weight(&self) -> f64 {
        match self {
            VulnSeverity::Critical => 40.0,
            VulnSeverity::High => 15.0,
            VulnSeverity::Medium => 5.0,
            VulnSeverity::Low => 1.0,
            VulnSeverity::Informational => 0.2,
        }
    }

    /// SLA deadline in hours from discovery.
    pub fn sla_hours(&self) -> i64 {
        match self {
            VulnSeverity::Critical => 24,
            VulnSeverity::High => 7 * 24,
            VulnSeverity::Medium => 30 * 24,
            VulnSeverity::Low => 90 * 24,
            VulnSeverity::Informational => 365 * 24,
        }
    }
}

impl std::fmt::Display for VulnSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "vuln_status", rename_all = "lowercase")]
#[serde(rename_all = "snake_case")]
pub enum VulnStatus {
    Open,
    Acknowledged,
    Resolved,
    RiskAccepted,
}

impl VulnStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            VulnStatus::Open => "open",
            VulnStatus::Acknowledged => "acknowledged",
            VulnStatus::Resolved => "resolved",
            VulnStatus::RiskAccepted => "risk_accepted",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "vuln_source", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum VulnSource {
    CargoAudit,
    Sast,
    ContainerScan,
    SecretsDetection,
    OwaspApi,
    InfraConfig,
    Manual,
}

impl VulnSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            VulnSource::CargoAudit => "cargo_audit",
            VulnSource::Sast => "sast",
            VulnSource::ContainerScan => "container_scan",
            VulnSource::SecretsDetection => "secrets_detection",
            VulnSource::OwaspApi => "owasp_api",
            VulnSource::InfraConfig => "infra_config",
            VulnSource::Manual => "manual",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "scan_type", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum ScanType {
    Dependency,
    Sast,
    Container,
    Secrets,
    OwaspApi,
    InfraConfig,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "scan_result", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum ScanResult {
    Passed,
    Failed,
    Error,
}

// ---------------------------------------------------------------------------
// Core domain types
// ---------------------------------------------------------------------------

/// A discovered security vulnerability with full lifecycle state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    pub id: Uuid,
    pub title: String,
    pub description: String,
    pub severity: VulnSeverity,
    pub status: VulnStatus,
    pub source: VulnSource,
    pub affected_component: String,
    pub cve_reference: Option<String>,
    pub affected_versions: Option<String>,
    pub remediation_guidance: Option<String>,
    // SLA
    pub discovered_at: DateTime<Utc>,
    pub sla_deadline: DateTime<Utc>,
    // Acknowledgement
    pub acknowledged_at: Option<DateTime<Utc>>,
    pub acknowledged_by: Option<String>,
    pub remediation_plan: Option<String>,
    // Resolution
    pub resolved_at: Option<DateTime<Utc>>,
    pub resolved_by: Option<String>,
    pub remediation_notes: Option<String>,
    pub resolving_commit: Option<String>,
    // Risk acceptance
    pub risk_accepted_at: Option<DateTime<Utc>>,
    pub risk_accepted_by: Option<String>,
    pub risk_justification: Option<String>,
    pub risk_expiry_date: Option<DateTime<Utc>>,
    // Metadata
    pub raw_finding: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Vulnerability {
    /// Returns true if this vulnerability has breached its SLA deadline.
    pub fn is_sla_breached(&self) -> bool {
        matches!(self.status, VulnStatus::Open | VulnStatus::Acknowledged)
            && Utc::now() > self.sla_deadline
    }

    /// Hours remaining until SLA deadline (negative = already breached).
    pub fn hours_until_sla_breach(&self) -> i64 {
        let delta = self.sla_deadline - Utc::now();
        delta.num_hours()
    }
}

/// Immutable status-change record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnHistoryEntry {
    pub id: Uuid,
    pub vuln_id: Uuid,
    pub old_status: Option<VulnStatus>,
    pub new_status: VulnStatus,
    pub changed_by: String,
    pub notes: Option<String>,
    pub changed_at: DateTime<Utc>,
}

/// An entry in the vulnerability allowlist (acknowledged FP or accepted risk).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllowlistEntry {
    pub id: Uuid,
    /// Advisory identifier, e.g. "RUSTSEC-2024-0001" or "CVE-2024-12345".
    pub identifier: String,
    pub source: VulnSource,
    pub justification: String,
    pub added_by: String,
    pub expiry_date: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

impl AllowlistEntry {
    /// Returns true if this allowlist entry is still valid (not expired).
    pub fn is_active(&self) -> bool {
        Utc::now() < self.expiry_date
    }
}

/// A daily compliance posture snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompliancePosture {
    pub id: Uuid,
    pub snapshot_date: NaiveDate,
    /// Posture score 0–100 (100 = no open vulnerabilities).
    pub posture_score: f64,
    pub open_critical: i32,
    pub open_high: i32,
    pub open_medium: i32,
    pub open_low: i32,
    pub open_informational: i32,
    pub sla_breached_count: i32,
    /// Per-source breakdown: { "cargo_audit": { score_impact: 5.0, open: 2 }, ... }
    pub domain_breakdown: serde_json::Value,
    pub computed_at: DateTime<Utc>,
}

/// A monthly compliance report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceReport {
    pub id: Uuid,
    pub report_period_start: NaiveDate,
    pub report_period_end: NaiveDate,
    pub new_vulns_count: i32,
    pub remediated_count: i32,
    pub sla_breaches_count: i32,
    pub posture_score_start: Option<f64>,
    pub posture_score_end: Option<f64>,
    pub report_data: serde_json::Value,
    pub generated_at: DateTime<Utc>,
    pub generated_by: String,
}

/// A single scan execution record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRun {
    pub id: Uuid,
    pub scan_type: ScanType,
    pub result: ScanResult,
    pub findings_count: i32,
    pub new_critical: i32,
    pub new_high: i32,
    pub triggered_by: String,
    pub artifact_path: Option<String>,
    pub raw_output: Option<serde_json::Value>,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

// ---------------------------------------------------------------------------
// Request / response types for HTTP handlers
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct ListVulnsQuery {
    pub page: Option<i64>,
    pub per_page: Option<i64>,
    pub severity: Option<String>,
    pub status: Option<String>,
    pub source: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AcknowledgeRequest {
    pub assigned_owner: String,
    pub remediation_plan: String,
}

#[derive(Debug, Deserialize)]
pub struct ResolveRequest {
    pub remediation_notes: String,
    pub resolving_commit: Option<String>,
    pub resolved_by: String,
}

#[derive(Debug, Deserialize)]
pub struct AcceptRiskRequest {
    pub justification: String,
    /// ISO-8601 date string for mandatory expiry.
    pub expiry_date: String,
    pub accepted_by: String,
}

#[derive(Debug, Deserialize)]
pub struct IngestFindingRequest {
    pub title: String,
    pub description: String,
    pub severity: VulnSeverity,
    pub source: VulnSource,
    pub affected_component: String,
    pub cve_reference: Option<String>,
    pub affected_versions: Option<String>,
    pub remediation_guidance: Option<String>,
    pub raw_finding: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct AddAllowlistRequest {
    pub identifier: String,
    pub source: VulnSource,
    pub justification: String,
    pub added_by: String,
    /// ISO-8601 date string.
    pub expiry_date: String,
}
