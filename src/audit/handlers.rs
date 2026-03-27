/// Admin audit log query, export, and hash chain verification endpoints.
///
/// GET /api/admin/audit/logs          — paginated query
/// GET /api/admin/audit/logs/:id      — single entry
/// GET /api/admin/audit/logs/export   — CSV/JSON export
/// GET /api/admin/audit/logs/verify   — hash chain integrity check
use crate::audit::{
    models::{AuditLogFilter, HashChainVerificationResult},
    repository::AuditLogRepository,
};
use axum::{
    extract::{Path, Query, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

pub struct AuditHandlerState {
    pub repo: Arc<AuditLogRepository>,
}

// ── Query ─────────────────────────────────────────────────────────────────────

pub async fn list_audit_logs(
    State(state): State<Arc<AuditHandlerState>>,
    Query(filter): Query<AuditLogFilter>,
) -> impl IntoResponse {
    match state.repo.query(&filter).await {
        Ok(page) => (StatusCode::OK, Json(serde_json::json!({ "data": page }))).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

pub async fn get_audit_log_entry(
    State(state): State<Arc<AuditHandlerState>>,
    Path(entry_id): Path<Uuid>,
) -> impl IntoResponse {
    match state.repo.get_by_id(entry_id).await {
        Ok(Some(entry)) => (StatusCode::OK, Json(serde_json::json!({ "data": entry }))).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "Audit log entry not found" })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

// ── Export ────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct ExportQuery {
    #[serde(flatten)]
    pub filter: AuditLogFilter,
    pub format: Option<String>, // "json" | "csv"
    pub max_rows: Option<i64>,
}

pub async fn export_audit_logs(
    State(state): State<Arc<AuditHandlerState>>,
    Query(params): Query<ExportQuery>,
) -> impl IntoResponse {
    let max_rows = params.max_rows.unwrap_or(5_000).min(10_000);
    let format = params.format.as_deref().unwrap_or("json");

    match state.repo.export(&params.filter, max_rows).await {
        Ok(entries) => {
            if format == "csv" {
                let mut csv = String::from(
                    "id,event_type,event_category,actor_type,actor_id,actor_ip,\
                     request_method,request_path,response_status,outcome,environment,created_at\n",
                );
                for e in &entries {
                    csv.push_str(&format!(
                        "{},{},{:?},{:?},{},{},{},{},{},{:?},{},{}\n",
                        e.id,
                        e.event_type,
                        e.event_category,
                        e.actor_type,
                        e.actor_id.as_deref().unwrap_or(""),
                        e.actor_ip.as_deref().unwrap_or(""),
                        e.request_method,
                        e.request_path,
                        e.response_status,
                        e.outcome,
                        e.environment,
                        e.created_at.to_rfc3339(),
                    ));
                }
                (
                    StatusCode::OK,
                    [(header::CONTENT_TYPE, "text/csv"),
                     (header::CONTENT_DISPOSITION, "attachment; filename=\"audit_export.csv\"")],
                    csv,
                )
                    .into_response()
            } else {
                (
                    StatusCode::OK,
                    Json(serde_json::json!({
                        "data": entries,
                        "count": entries.len(),
                        "truncated": entries.len() as i64 == max_rows,
                    })),
                )
                    .into_response()
            }
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

// ── Hash chain verification ───────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct VerifyQuery {
    pub date_from: DateTime<Utc>,
    pub date_to: DateTime<Utc>,
}

pub async fn verify_hash_chain(
    State(state): State<Arc<AuditHandlerState>>,
    Query(params): Query<VerifyQuery>,
) -> impl IntoResponse {
    match state
        .repo
        .verify_hash_chain(params.date_from, params.date_to)
        .await
    {
        Ok(result) => {
            // Alert if tampering detected
            if !result.valid {
                tracing::error!(
                    tampered_count = result.tampered_entries.len(),
                    gaps_count = result.gaps_detected.len(),
                    "AUDIT HASH CHAIN INTEGRITY FAILURE DETECTED"
                );
            }
            let status = if result.valid {
                StatusCode::OK
            } else {
                StatusCode::CONFLICT
            };
            (status, Json(serde_json::json!({ "data": result }))).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}
