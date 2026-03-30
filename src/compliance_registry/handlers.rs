//! HTTP handlers for the Compliance Registry API (Issue #2.02).

use crate::compliance_registry::models::*;
use crate::compliance_registry::repository::ComplianceRegistryRepository;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
};
use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

// ── Shared state ─────────────────────────────────────────────────────────────

pub struct ComplianceRegistryState {
    pub repo: ComplianceRegistryRepository,
}

// ── Generic response wrappers ─────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct ApiResponse<T: Serialize> {
    pub success: bool,
    pub data: T,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ApiError {
    pub success: bool,
    pub error: String,
}

fn ok<T: Serialize>(data: T) -> Json<ApiResponse<T>> {
    Json(ApiResponse {
        success: true,
        data,
        message: None,
    })
}

fn ok_msg<T: Serialize>(data: T, msg: &str) -> Json<ApiResponse<T>> {
    Json(ApiResponse {
        success: true,
        data,
        message: Some(msg.to_string()),
    })
}

// ── Query params ──────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ReportQuery {
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize)]
pub struct ComplianceCheckQuery {
    pub amount: Decimal,
    pub currency: String,
}

// ── Corridor handlers ─────────────────────────────────────────────────────────

pub async fn create_corridor_handler(
    State(state): State<Arc<ComplianceRegistryState>>,
    Json(req): Json<CreateCorridorRequest>,
) -> Result<(StatusCode, Json<ApiResponse<PaymentCorridor>>), (StatusCode, Json<ApiError>)> {
    state
        .repo
        .create_corridor(&req, None)
        .await
        .map(|c| (StatusCode::CREATED, ok_msg(c, "Corridor created")))
        .map_err(|e| db_err(e))
}

pub async fn list_corridors_handler(
    State(state): State<Arc<ComplianceRegistryState>>,
) -> Result<Json<ApiResponse<Vec<PaymentCorridor>>>, (StatusCode, Json<ApiError>)> {
    state
        .repo
        .list_corridors()
        .await
        .map(ok)
        .map_err(db_err)
}

pub async fn get_corridor_handler(
    State(state): State<Arc<ComplianceRegistryState>>,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<PaymentCorridor>>, (StatusCode, Json<ApiError>)> {
    state
        .repo
        .get_corridor(id)
        .await
        .map_err(db_err)?
        .map(ok)
        .ok_or_else(|| not_found("Corridor not found"))
}

pub async fn update_corridor_status_handler(
    State(state): State<Arc<ComplianceRegistryState>>,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateCorridorStatusRequest>,
) -> Result<Json<ApiResponse<()>>, (StatusCode, Json<ApiError>)> {
    // Audit: capture previous state
    let prev = state.repo.get_corridor(id).await.map_err(db_err)?;
    let prev_json = prev.as_ref().map(|c| serde_json::to_value(c).ok()).flatten();

    state
        .repo
        .update_corridor_status(id, req.status, req.reason.clone(), req.updated_by)
        .await
        .map_err(db_err)?;

    let new_json = serde_json::json!({ "status": req.status, "reason": req.reason });
    let _ = state
        .repo
        .write_audit_log(
            "payment_corridor",
            id,
            "status_changed",
            req.updated_by,
            None,
            prev_json,
            Some(new_json),
            req.reason.as_deref(),
        )
        .await;

    Ok(ok_msg((), "Corridor status updated"))
}

// ── License handlers ──────────────────────────────────────────────────────────

pub async fn create_license_handler(
    State(state): State<Arc<ComplianceRegistryState>>,
    Json(req): Json<CreateLicenseRequest>,
) -> Result<(StatusCode, Json<ApiResponse<CorridorLicense>>), (StatusCode, Json<ApiError>)> {
    let license = state
        .repo
        .create_license(&req, None)
        .await
        .map_err(db_err)?;

    let new_json = serde_json::to_value(&license).ok();
    let _ = state
        .repo
        .write_audit_log(
            "corridor_license",
            license.id,
            "created",
            None,
            None,
            None,
            new_json,
            None,
        )
        .await;

    Ok((StatusCode::CREATED, ok_msg(license, "License created")))
}

pub async fn list_licenses_handler(
    State(state): State<Arc<ComplianceRegistryState>>,
    Path(corridor_id): Path<Uuid>,
) -> Result<Json<ApiResponse<Vec<CorridorLicense>>>, (StatusCode, Json<ApiError>)> {
    state
        .repo
        .list_licenses_for_corridor(corridor_id)
        .await
        .map(ok)
        .map_err(db_err)
}

pub async fn update_license_status_handler(
    State(state): State<Arc<ComplianceRegistryState>>,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateLicenseStatusRequest>,
) -> Result<Json<ApiResponse<CorridorLicense>>, (StatusCode, Json<ApiError>)> {
    let prev = state.repo.get_license(id).await.map_err(db_err)?;
    let prev_json = prev.as_ref().map(|l| serde_json::to_value(l).ok()).flatten();

    let license = state
        .repo
        .update_license_status(id, req.status, None)
        .await
        .map_err(db_err)?;

    let new_json = serde_json::to_value(&license).ok();
    let _ = state
        .repo
        .write_audit_log(
            "corridor_license",
            id,
            "status_changed",
            None,
            None,
            prev_json,
            new_json,
            req.reason.as_deref(),
        )
        .await;

    // If license is now expired/suspended, auto-evaluate corridor stop-loss.
    if !req.status.is_operable() {
        if let Some(lic) = &prev {
            let _ = auto_block_corridor_if_needed(&state, lic.corridor_id).await;
        }
    }

    Ok(ok(license))
}

// ── Ruleset handlers ──────────────────────────────────────────────────────────

pub async fn create_ruleset_handler(
    State(state): State<Arc<ComplianceRegistryState>>,
    Json(req): Json<CreateRulesetRequest>,
) -> Result<(StatusCode, Json<ApiResponse<RegulatoryRuleset>>), (StatusCode, Json<ApiError>)> {
    let ruleset = state
        .repo
        .create_ruleset(&req, None)
        .await
        .map_err(db_err)?;

    let new_json = serde_json::to_value(&ruleset).ok();
    let _ = state
        .repo
        .write_audit_log(
            "regulatory_ruleset",
            ruleset.id,
            "created",
            None,
            None,
            None,
            new_json,
            None,
        )
        .await;

    Ok((StatusCode::CREATED, ok_msg(ruleset, "Ruleset created")))
}

pub async fn list_rulesets_handler(
    State(state): State<Arc<ComplianceRegistryState>>,
    Path(corridor_id): Path<Uuid>,
) -> Result<Json<ApiResponse<Vec<RegulatoryRuleset>>>, (StatusCode, Json<ApiError>)> {
    state
        .repo
        .list_rulesets_for_corridor(corridor_id, false)
        .await
        .map(ok)
        .map_err(db_err)
}

pub async fn update_ruleset_handler(
    State(state): State<Arc<ComplianceRegistryState>>,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateRulesetRequest>,
) -> Result<Json<ApiResponse<RegulatoryRuleset>>, (StatusCode, Json<ApiError>)> {
    let prev = state.repo.get_ruleset(id).await.map_err(db_err)?;
    let prev_json = prev.as_ref().map(|r| serde_json::to_value(r).ok()).flatten();

    let ruleset = state
        .repo
        .update_ruleset(id, &req, None)
        .await
        .map_err(db_err)?;

    let new_json = serde_json::to_value(&ruleset).ok();
    let _ = state
        .repo
        .write_audit_log(
            "regulatory_ruleset",
            id,
            "updated",
            None,
            None,
            prev_json,
            new_json,
            None,
        )
        .await;

    Ok(ok(ruleset))
}

// ── Compliance check handler ──────────────────────────────────────────────────

pub async fn compliance_check_handler(
    State(state): State<Arc<ComplianceRegistryState>>,
    Path(corridor_id): Path<Uuid>,
    Query(params): Query<ComplianceCheckQuery>,
) -> Result<Json<ApiResponse<ComplianceCheckResult>>, (StatusCode, Json<ApiError>)> {
    state
        .repo
        .check_compliance(corridor_id, params.amount, &params.currency)
        .await
        .map(ok)
        .map_err(db_err)
}

// ── Report handler ────────────────────────────────────────────────────────────

pub async fn readiness_report_handler(
    State(state): State<Arc<ComplianceRegistryState>>,
    Path(corridor_id): Path<Uuid>,
    Query(params): Query<ReportQuery>,
) -> Result<Json<ApiResponse<ComplianceReadinessReport>>, (StatusCode, Json<ApiError>)> {
    let from = params.from.unwrap_or_else(|| {
        Utc::now() - chrono::Duration::days(90)
    });
    let to = params.to.unwrap_or_else(Utc::now);

    state
        .repo
        .generate_readiness_report(corridor_id, from, to)
        .await
        .map(ok)
        .map_err(db_err)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn db_err(e: crate::database::error::DatabaseError) -> (StatusCode, Json<ApiError>) {
    tracing::error!(error = %e, "Compliance registry database error");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ApiError {
            success: false,
            error: e.to_string(),
        }),
    )
}

fn not_found(msg: &str) -> (StatusCode, Json<ApiError>) {
    (
        StatusCode::NOT_FOUND,
        Json(ApiError {
            success: false,
            error: msg.to_string(),
        }),
    )
}

/// Auto-block a corridor if it has no remaining active licenses (stop-loss).
async fn auto_block_corridor_if_needed(
    state: &ComplianceRegistryState,
    corridor_id: Uuid,
) {
    let licenses = match state.repo.list_licenses_for_corridor(corridor_id).await {
        Ok(l) => l,
        Err(_) => return,
    };

    let has_active = licenses.iter().any(|l| l.status.is_operable());
    if !has_active {
        let _ = state
            .repo
            .update_corridor_status(
                corridor_id,
                CorridorStatus::BlockedLicenseExpired,
                Some("All licenses expired or suspended — auto-blocked".to_string()),
                None,
            )
            .await;

        let _ = state
            .repo
            .write_audit_log(
                "payment_corridor",
                corridor_id,
                "status_changed",
                None,
                None,
                None,
                Some(serde_json::json!({ "status": "blocked_license_expired" })),
                Some("Automated stop-loss: no active licenses remain"),
            )
            .await;
    }
}

// ── Additional DTO for corridor status update ─────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct UpdateCorridorStatusRequest {
    pub status: CorridorStatus,
    pub reason: Option<String>,
    pub updated_by: Option<Uuid>,
}
