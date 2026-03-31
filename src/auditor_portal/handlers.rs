//! HTTP handlers for the external auditor portal.
//!
//! Auditor-facing routes (require session token):
//!   POST   /auditor/login
//!   POST   /auditor/logout
//!   GET    /auditor/export          — evidence package (JSON/CSV)
//!   GET    /auditor/verify          — Stellar hash chain integrity
//!   GET    /auditor/packets         — list quarterly packets
//!
//! Admin-only routes (require admin session):
//!   POST   /admin/auditor/accounts
//!   POST   /admin/auditor/windows
//!   POST   /admin/auditor/whitelist
//!   GET    /admin/auditor/access-log

use crate::auditor_portal::{
    models::*,
    service::{sha256_hex, AuditorError, AuditorService},
};
use axum::{
    extract::{Query, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

// ── Shared state ──────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct AuditorPortalState {
    pub service: Arc<AuditorService>,
}

// ── Error helper ──────────────────────────────────────────────────────────────

fn err(e: AuditorError) -> Response {
    let status = e.status_code();
    (status, Json(serde_json::json!({ "error": e.to_string() }))).into_response()
}

// ── Session extraction helper ─────────────────────────────────────────────────

fn extract_bearer(req: &axum::http::request::Parts) -> Option<String> {
    req.headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|s| s.to_string())
}

fn extract_ip(req: &axum::http::request::Parts) -> String {
    req.headers
        .get("X-Forwarded-For")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .unwrap_or("127.0.0.1")
        .trim()
        .to_string()
}

// ── Login ─────────────────────────────────────────────────────────────────────

pub async fn login(
    State(state): State<Arc<AuditorPortalState>>,
    axum::extract::RawRequest(req): axum::extract::RawRequest,
    Json(body): Json<AuditorLoginRequest>,
) -> Response {
    let (parts, _) = req.into_parts();
    let ip = extract_ip(&parts);
    let ua = parts
        .headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    match state.service.login(&body, &ip, ua.as_deref()).await {
        Ok(resp) => (StatusCode::OK, Json(serde_json::json!({ "data": resp }))).into_response(),
        Err(e) => err(e),
    }
}

// ── Logout ────────────────────────────────────────────────────────────────────

pub async fn logout(
    State(state): State<Arc<AuditorPortalState>>,
    axum::extract::RawRequest(req): axum::extract::RawRequest,
) -> Response {
    let (parts, _) = req.into_parts();
    let ip = extract_ip(&parts);
    let token = match extract_bearer(&parts) {
        Some(t) => t,
        None => return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({ "error": "Missing token" }))).into_response(),
    };
    match state.service.validate_session(&token, &ip).await {
        Ok(session) => match state.service.logout(&session).await {
            Ok(_) => (StatusCode::OK, Json(serde_json::json!({ "message": "Logged out" }))).into_response(),
            Err(e) => err(e),
        },
        Err(e) => err(e),
    }
}

// ── Evidence export ───────────────────────────────────────────────────────────

pub async fn export_evidence(
    State(state): State<Arc<AuditorPortalState>>,
    axum::extract::RawRequest(req): axum::extract::RawRequest,
    Query(query): Query<AuditExportQuery>,
) -> Response {
    let (parts, _) = req.into_parts();
    let ip = extract_ip(&parts);
    let token = match extract_bearer(&parts) {
        Some(t) => t,
        None => return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({ "error": "Missing token" }))).into_response(),
    };

    let session = match state.service.validate_session(&token, &ip).await {
        Ok(s) => s,
        Err(e) => return err(e),
    };

    let format = query.format.as_deref().unwrap_or("json");

    match state.service.export_evidence(&session, &query).await {
        Ok((entries, checksum, filename)) => {
            if format == "csv" {
                // Minimal CSV: id, event_type, actor_id, request_path, response_status, created_at
                let mut csv = String::from("id,event_type,actor_id,request_path,response_status,created_at\n");
                for e in &entries {
                    csv.push_str(&format!(
                        "{},{},{},{},{},{}\n",
                        e.get("id").and_then(|v| v.as_str()).unwrap_or(""),
                        e.get("event_type").and_then(|v| v.as_str()).unwrap_or(""),
                        e.get("actor_id").and_then(|v| v.as_str()).unwrap_or(""),
                        e.get("request_path").and_then(|v| v.as_str()).unwrap_or(""),
                        e.get("response_status").and_then(|v| v.as_i64()).unwrap_or(0),
                        e.get("created_at").and_then(|v| v.as_str()).unwrap_or(""),
                    ));
                }
                let csv_checksum = sha256_hex(csv.as_bytes());
                (
                    StatusCode::OK,
                    [
                        (header::CONTENT_TYPE, "text/csv".to_string()),
                        (header::CONTENT_DISPOSITION, format!("attachment; filename=\"{}\"", filename.replace(".json", ".csv"))),
                        ("X-Checksum-SHA256".parse::<header::HeaderName>().unwrap(), csv_checksum),
                    ],
                    csv,
                ).into_response()
            } else {
                // JSON with checksum envelope
                let envelope = serde_json::json!({
                    "data": entries,
                    "count": entries.len(),
                    "checksum_sha256": checksum,
                    "filename": filename,
                    "exported_at": Utc::now(),
                });
                (
                    StatusCode::OK,
                    [(
                        "X-Checksum-SHA256".parse::<header::HeaderName>().unwrap(),
                        checksum,
                    )],
                    Json(envelope),
                ).into_response()
            }
        }
        Err(e) => err(e),
    }
}

// ── Hash chain verification ───────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct VerifyQuery {
    pub date_from: DateTime<Utc>,
    pub date_to: DateTime<Utc>,
}

pub async fn verify_hash_chain(
    State(state): State<Arc<AuditorPortalState>>,
    axum::extract::RawRequest(req): axum::extract::RawRequest,
    Query(params): Query<VerifyQuery>,
) -> Response {
    let (parts, _) = req.into_parts();
    let ip = extract_ip(&parts);
    let token = match extract_bearer(&parts) {
        Some(t) => t,
        None => return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({ "error": "Missing token" }))).into_response(),
    };

    let session = match state.service.validate_session(&token, &ip).await {
        Ok(s) => s,
        Err(e) => return err(e),
    };

    match state.service.verify_hash_chain(&session, params.date_from, params.date_to).await {
        Ok(result) => {
            let status = if result.valid { StatusCode::OK } else { StatusCode::CONFLICT };
            (status, Json(serde_json::json!({ "data": result }))).into_response()
        }
        Err(e) => err(e),
    }
}

// ── Quarterly packets ─────────────────────────────────────────────────────────

pub async fn list_quarterly_packets(
    State(state): State<Arc<AuditorPortalState>>,
    axum::extract::RawRequest(req): axum::extract::RawRequest,
) -> Response {
    let (parts, _) = req.into_parts();
    let ip = extract_ip(&parts);
    let token = match extract_bearer(&parts) {
        Some(t) => t,
        None => return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({ "error": "Missing token" }))).into_response(),
    };

    if let Err(e) = state.service.validate_session(&token, &ip).await {
        return err(e);
    }

    match state.service.list_quarterly_packets().await {
        Ok(packets) => (StatusCode::OK, Json(serde_json::json!({ "data": packets }))).into_response(),
        Err(e) => err(e),
    }
}

// ── Admin: create auditor account ─────────────────────────────────────────────

pub async fn admin_create_auditor(
    State(state): State<Arc<AuditorPortalState>>,
    Json(body): Json<CreateAuditorRequest>,
) -> Response {
    match state.service.create_auditor(&body).await {
        Ok(account) => (StatusCode::CREATED, Json(serde_json::json!({ "data": account }))).into_response(),
        Err(e) => err(e),
    }
}

// ── Admin: create access window ───────────────────────────────────────────────

#[derive(Deserialize)]
pub struct AdminCreateWindowRequest {
    #[serde(flatten)]
    pub window: CreateAccessWindowRequest,
    pub granted_by: Uuid,
}

pub async fn admin_create_window(
    State(state): State<Arc<AuditorPortalState>>,
    Json(body): Json<AdminCreateWindowRequest>,
) -> Response {
    match state.service.create_access_window(&body.window, body.granted_by).await {
        Ok(window) => (StatusCode::CREATED, Json(serde_json::json!({ "data": window }))).into_response(),
        Err(e) => err(e),
    }
}

// ── Admin: add IP whitelist entry ─────────────────────────────────────────────

pub async fn admin_add_ip_whitelist(
    State(state): State<Arc<AuditorPortalState>>,
    Json(body): Json<AddIpWhitelistRequest>,
) -> Response {
    match state.service.add_ip_whitelist(&body).await {
        Ok(_) => (StatusCode::CREATED, Json(serde_json::json!({ "message": "IP added to whitelist" }))).into_response(),
        Err(e) => err(e),
    }
}

// ── Admin: access log ─────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct AccessLogQuery {
    pub auditor_id: Option<Uuid>,
    pub session_id: Option<Uuid>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

pub async fn admin_list_access_log(
    State(state): State<Arc<AuditorPortalState>>,
    Query(params): Query<AccessLogQuery>,
) -> Response {
    let limit = params.limit.unwrap_or(100).min(500);
    let offset = params.offset.unwrap_or(0);
    match state.service.list_access_log(params.auditor_id, params.session_id, limit, offset).await {
        Ok(entries) => (StatusCode::OK, Json(serde_json::json!({ "data": entries }))).into_response(),
        Err(e) => err(e),
    }
}

// ── Admin: generate quarterly packet ─────────────────────────────────────────

#[derive(Deserialize)]
pub struct GeneratePacketRequest {
    pub quarter_label: String,
    pub generated_by: Option<String>,
}

pub async fn admin_generate_quarterly_packet(
    State(state): State<Arc<AuditorPortalState>>,
    Json(body): Json<GeneratePacketRequest>,
) -> Response {
    let by = body.generated_by.as_deref().unwrap_or("admin");
    match state.service.generate_quarterly_packet(&body.quarter_label, by).await {
        Ok(packet) => (StatusCode::OK, Json(serde_json::json!({ "data": packet }))).into_response(),
        Err(e) => err(e),
    }
}
