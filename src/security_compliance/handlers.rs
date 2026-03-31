//! Admin HTTP handlers for the security compliance framework.
//!
//! Routes:
//!   GET    /api/admin/security/vulnerabilities
//!   GET    /api/admin/security/vulnerabilities/:vuln_id
//!   POST   /api/admin/security/vulnerabilities/:vuln_id/acknowledge
//!   POST   /api/admin/security/vulnerabilities/:vuln_id/resolve
//!   POST   /api/admin/security/vulnerabilities/:vuln_id/accept-risk
//!   GET    /api/admin/security/compliance/posture
//!   POST   /api/admin/security/findings/ingest
//!   POST   /api/admin/security/allowlist
//!   GET    /api/admin/security/allowlist
//!   GET    /api/admin/security/reports

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use chrono::{DateTime, Utc};
use std::sync::Arc;
use tracing::{info, warn};
use uuid::Uuid;

use crate::security_compliance::{
    config::SecurityComplianceConfig,
    metrics,
    models::{
        AcceptRiskRequest, AcknowledgeRequest, AddAllowlistRequest, IngestFindingRequest,
        ListVulnsQuery, ResolveRequest, VulnSeverity, VulnSource, VulnStatus, Vulnerability,
        AllowlistEntry,
    },
    repository::SecurityComplianceRepository,
    scoring::PostureScorer,
};

/// Shared state for security compliance admin handlers.
#[derive(Clone)]
pub struct SecurityComplianceState {
    pub repo: Arc<SecurityComplianceRepository>,
    pub config: Arc<SecurityComplianceConfig>,
}

// ---------------------------------------------------------------------------
// GET /api/admin/security/vulnerabilities
// ---------------------------------------------------------------------------

pub async fn list_vulnerabilities(
    State(state): State<SecurityComplianceState>,
    Query(query): Query<ListVulnsQuery>,
) -> Response {
    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.unwrap_or(20).min(100);
    let offset = (page - 1) * per_page;

    let status_filter = query.status.as_deref().and_then(parse_status);
    let severity_filter = query.severity.as_deref().and_then(parse_severity);
    let source_filter = query.source.as_deref().and_then(parse_source);

    let (rows, total) = tokio::join!(
        state.repo.list_vulnerabilities(
            status_filter,
            severity_filter,
            source_filter,
            per_page,
            offset,
        ),
        state.repo.count_vulnerabilities(status_filter, severity_filter, source_filter),
    );

    match (rows, total) {
        (Ok(rows), Ok(total)) => {
            let vulns: Vec<Vulnerability> = rows.into_iter().map(Into::into).collect();
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "data": vulns,
                    "pagination": {
                        "page": page,
                        "per_page": per_page,
                        "total": total,
                        "total_pages": (total as f64 / per_page as f64).ceil() as i64,
                    }
                })),
            )
                .into_response()
        }
        _ => internal_error("Failed to list vulnerabilities"),
    }
}

// ---------------------------------------------------------------------------
// GET /api/admin/security/vulnerabilities/:vuln_id
// ---------------------------------------------------------------------------

pub async fn get_vulnerability(
    State(state): State<SecurityComplianceState>,
    Path(vuln_id): Path<Uuid>,
) -> Response {
    match state.repo.get_vulnerability(vuln_id).await {
        Ok(Some(row)) => {
            let vuln: Vulnerability = row.into();
            (StatusCode::OK, Json(serde_json::json!({ "data": vuln }))).into_response()
        }
        Ok(None) => not_found("Vulnerability not found"),
        Err(e) => {
            warn!(error = %e, vuln_id = %vuln_id, "failed to fetch vulnerability");
            internal_error("Failed to fetch vulnerability")
        }
    }
}

// ---------------------------------------------------------------------------
// POST /api/admin/security/vulnerabilities/:vuln_id/acknowledge
// ---------------------------------------------------------------------------

pub async fn acknowledge_vulnerability(
    State(state): State<SecurityComplianceState>,
    Path(vuln_id): Path<Uuid>,
    Json(body): Json<AcknowledgeRequest>,
) -> Response {
    match state
        .repo
        .acknowledge_vulnerability(vuln_id, &body.assigned_owner, &body.remediation_plan)
        .await
    {
        Ok(true) => {
            info!(
                vuln_id = %vuln_id,
                owner = %body.assigned_owner,
                "vulnerability acknowledged"
            );
            metrics::vuln_events_total()
                .with_label_values(&["acknowledged", "unknown", "unknown"])
                .inc();
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "success": true,
                    "message": "Vulnerability acknowledged and owner assigned"
                })),
            )
                .into_response()
        }
        Ok(false) => not_found("Vulnerability not found or not in open status"),
        Err(e) => {
            warn!(error = %e, "failed to acknowledge vulnerability");
            internal_error("Failed to acknowledge vulnerability")
        }
    }
}

// ---------------------------------------------------------------------------
// POST /api/admin/security/vulnerabilities/:vuln_id/resolve
// ---------------------------------------------------------------------------

pub async fn resolve_vulnerability(
    State(state): State<SecurityComplianceState>,
    Path(vuln_id): Path<Uuid>,
    Json(body): Json<ResolveRequest>,
) -> Response {
    match state
        .repo
        .resolve_vulnerability(
            vuln_id,
            &body.resolved_by,
            &body.remediation_notes,
            body.resolving_commit.as_deref(),
        )
        .await
    {
        Ok(true) => {
            info!(
                vuln_id = %vuln_id,
                resolved_by = %body.resolved_by,
                commit = ?body.resolving_commit,
                "vulnerability resolved"
            );
            metrics::vuln_events_total()
                .with_label_values(&["resolved", "unknown", "unknown"])
                .inc();
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "success": true,
                    "message": "Vulnerability marked as resolved"
                })),
            )
                .into_response()
        }
        Ok(false) => not_found("Vulnerability not found or already resolved"),
        Err(e) => {
            warn!(error = %e, "failed to resolve vulnerability");
            internal_error("Failed to resolve vulnerability")
        }
    }
}

// ---------------------------------------------------------------------------
// POST /api/admin/security/vulnerabilities/:vuln_id/accept-risk
// ---------------------------------------------------------------------------

pub async fn accept_risk(
    State(state): State<SecurityComplianceState>,
    Path(vuln_id): Path<Uuid>,
    Json(body): Json<AcceptRiskRequest>,
) -> Response {
    let expiry_date = match DateTime::parse_from_rfc3339(&body.expiry_date) {
        Ok(dt) => dt.with_timezone(&Utc),
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": {
                        "code": "INVALID_DATE",
                        "message": "expiry_date must be a valid RFC-3339 datetime"
                    }
                })),
            )
                .into_response();
        }
    };

    if expiry_date <= Utc::now() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": {
                    "code": "EXPIRY_IN_PAST",
                    "message": "expiry_date must be in the future"
                }
            })),
        )
            .into_response();
    }

    match state
        .repo
        .accept_risk(vuln_id, &body.accepted_by, &body.justification, expiry_date)
        .await
    {
        Ok(true) => {
            info!(
                vuln_id = %vuln_id,
                accepted_by = %body.accepted_by,
                expiry = %expiry_date,
                "vulnerability risk accepted"
            );
            metrics::vuln_events_total()
                .with_label_values(&["risk_accepted", "unknown", "unknown"])
                .inc();
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "success": true,
                    "message": "Risk accepted",
                    "expiry_date": expiry_date
                })),
            )
                .into_response()
        }
        Ok(false) => not_found("Vulnerability not found or already resolved/accepted"),
        Err(e) => {
            warn!(error = %e, "failed to accept risk");
            internal_error("Failed to accept risk")
        }
    }
}

// ---------------------------------------------------------------------------
// GET /api/admin/security/compliance/posture
// ---------------------------------------------------------------------------

pub async fn get_posture(
    State(state): State<SecurityComplianceState>,
) -> Response {
    let open_rows = match state.repo.list_open_vulnerabilities().await {
        Ok(rows) => rows,
        Err(e) => {
            warn!(error = %e, "failed to fetch open vulnerabilities for posture");
            return internal_error("Failed to compute posture");
        }
    };

    let open_vulns: Vec<Vulnerability> = open_rows.into_iter().map(Into::into).collect();
    let scorer = PostureScorer::new(&state.config);
    let score = scorer.compute_score(&open_vulns);
    let counts = PostureScorer::count_by_severity(&open_vulns);
    let sla_breached = PostureScorer::count_sla_breached(&open_vulns);
    let breakdown = scorer.domain_breakdown(&open_vulns);

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "posture_score": (score * 100.0).round() / 100.0,
            "open_vulnerabilities": {
                "critical": counts.critical,
                "high": counts.high,
                "medium": counts.medium,
                "low": counts.low,
                "informational": counts.informational,
                "total": counts.critical + counts.high + counts.medium + counts.low + counts.informational,
            },
            "sla_breached_count": sla_breached,
            "domain_breakdown": breakdown,
            "computed_at": Utc::now(),
        })),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// POST /api/admin/security/findings/ingest
// (Called by CI/CD pipeline to ingest scan findings)
// ---------------------------------------------------------------------------

pub async fn ingest_finding(
    State(state): State<SecurityComplianceState>,
    Json(body): Json<IngestFindingRequest>,
) -> Response {
    // Check allowlist before persisting
    let identifier = body.cve_reference.clone().unwrap_or_default();
    if !identifier.is_empty() {
        match state.repo.is_allowlisted(&identifier).await {
            Ok(true) => {
                return (
                    StatusCode::OK,
                    Json(serde_json::json!({
                        "ingested": false,
                        "reason": "allowlisted",
                        "identifier": identifier
                    })),
                )
                    .into_response();
            }
            Ok(false) => {}
            Err(e) => warn!(error = %e, "allowlist check failed, proceeding with ingest"),
        }
    }

    let sla_hours = state.config.sla_hours_for(body.severity.as_str());
    let now = Utc::now();
    let sla_deadline = now + chrono::Duration::hours(sla_hours);

    let vuln = Vulnerability {
        id: Uuid::new_v4(),
        title: body.title,
        description: body.description,
        severity: body.severity,
        status: VulnStatus::Open,
        source: body.source,
        affected_component: body.affected_component,
        cve_reference: body.cve_reference,
        affected_versions: body.affected_versions,
        remediation_guidance: body.remediation_guidance,
        discovered_at: now,
        sla_deadline,
        acknowledged_at: None,
        acknowledged_by: None,
        remediation_plan: None,
        resolved_at: None,
        resolved_by: None,
        remediation_notes: None,
        resolving_commit: None,
        risk_accepted_at: None,
        risk_accepted_by: None,
        risk_justification: None,
        risk_expiry_date: None,
        raw_finding: body.raw_finding,
        created_at: now,
        updated_at: now,
    };

    match state.repo.insert_vulnerability(&vuln).await {
        Ok(()) => {
            info!(
                vuln_id = %vuln.id,
                severity = %vuln.severity,
                source = %vuln.source.as_str(),
                title = %vuln.title,
                "new vulnerability ingested"
            );

            metrics::vuln_events_total()
                .with_label_values(&["discovered", vuln.severity.as_str(), vuln.source.as_str()])
                .inc();

            metrics::open_vulns_by_severity()
                .with_label_values(&[vuln.severity.as_str()])
                .inc();

            (
                StatusCode::CREATED,
                Json(serde_json::json!({
                    "ingested": true,
                    "vuln_id": vuln.id,
                    "sla_deadline": sla_deadline,
                })),
            )
                .into_response()
        }
        Err(e) => {
            warn!(error = %e, "failed to ingest finding");
            internal_error("Failed to ingest finding")
        }
    }
}

// ---------------------------------------------------------------------------
// POST /api/admin/security/allowlist
// ---------------------------------------------------------------------------

pub async fn add_allowlist_entry(
    State(state): State<SecurityComplianceState>,
    Json(body): Json<AddAllowlistRequest>,
) -> Response {
    let expiry_date = match DateTime::parse_from_rfc3339(&body.expiry_date) {
        Ok(dt) => dt.with_timezone(&Utc),
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": { "code": "INVALID_DATE", "message": "expiry_date must be RFC-3339" }
                })),
            )
                .into_response();
        }
    };

    let entry = AllowlistEntry {
        id: Uuid::new_v4(),
        identifier: body.identifier.clone(),
        source: body.source,
        justification: body.justification,
        added_by: body.added_by,
        expiry_date,
        created_at: Utc::now(),
    };

    match state.repo.insert_allowlist_entry(&entry).await {
        Ok(()) => {
            info!(identifier = %entry.identifier, "allowlist entry added");
            (
                StatusCode::CREATED,
                Json(serde_json::json!({ "success": true, "id": entry.id })),
            )
                .into_response()
        }
        Err(e) => {
            warn!(error = %e, "failed to add allowlist entry");
            internal_error("Failed to add allowlist entry")
        }
    }
}

// ---------------------------------------------------------------------------
// GET /api/admin/security/allowlist
// ---------------------------------------------------------------------------

pub async fn list_allowlist(
    State(state): State<SecurityComplianceState>,
) -> Response {
    match state.repo.list_allowlist().await {
        Ok(rows) => (StatusCode::OK, Json(serde_json::json!({ "data": rows }))).into_response(),
        Err(e) => {
            warn!(error = %e, "failed to list allowlist");
            internal_error("Failed to list allowlist")
        }
    }
}

// ---------------------------------------------------------------------------
// GET /api/admin/security/reports
// ---------------------------------------------------------------------------

pub async fn list_reports(
    State(state): State<SecurityComplianceState>,
) -> Response {
    match state.repo.list_compliance_reports(12).await {
        Ok(rows) => (StatusCode::OK, Json(serde_json::json!({ "data": rows }))).into_response(),
        Err(e) => {
            warn!(error = %e, "failed to list compliance reports");
            internal_error("Failed to list compliance reports")
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn internal_error(msg: &str) -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(serde_json::json!({ "error": { "code": "INTERNAL_ERROR", "message": msg } })),
    )
        .into_response()
}

fn not_found(msg: &str) -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({ "error": { "code": "NOT_FOUND", "message": msg } })),
    )
        .into_response()
}

fn parse_status(s: &str) -> Option<VulnStatus> {
    match s {
        "open" => Some(VulnStatus::Open),
        "acknowledged" => Some(VulnStatus::Acknowledged),
        "resolved" => Some(VulnStatus::Resolved),
        "risk_accepted" => Some(VulnStatus::RiskAccepted),
        _ => None,
    }
}

fn parse_severity(s: &str) -> Option<VulnSeverity> {
    match s {
        "critical" => Some(VulnSeverity::Critical),
        "high" => Some(VulnSeverity::High),
        "medium" => Some(VulnSeverity::Medium),
        "low" => Some(VulnSeverity::Low),
        "informational" => Some(VulnSeverity::Informational),
        _ => None,
    }
}

fn parse_source(s: &str) -> Option<VulnSource> {
    match s {
        "cargo_audit" => Some(VulnSource::CargoAudit),
        "sast" => Some(VulnSource::Sast),
        "container_scan" => Some(VulnSource::ContainerScan),
        "secrets_detection" => Some(VulnSource::SecretsDetection),
        "owasp_api" => Some(VulnSource::OwaspApi),
        "infra_config" => Some(VulnSource::InfraConfig),
        "manual" => Some(VulnSource::Manual),
        _ => None,
    }
}
