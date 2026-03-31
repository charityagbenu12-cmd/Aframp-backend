//! Admin API handlers for abuse case management

use super::case_management::{
    AbuseCase, AbuseCaseStatus, AbuseCaseSummary, CaseDismissalRequest, CaseEscalationRequest,
    CaseResolutionRequest,
};
use super::repository::AbuseDetectionRepository;
use super::response::ResponseTier;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

#[derive(Clone)]
pub struct AbuseHandlerState {
    pub repo: Arc<AbuseDetectionRepository>,
}

#[derive(Debug, Deserialize)]
pub struct ListCasesQuery {
    pub status: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub data: T,
    pub message: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PaginatedResponse<T> {
    pub success: bool,
    pub data: Vec<T>,
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
}

/// GET /api/admin/abuse/cases - List all abuse cases
pub async fn list_cases_handler(
    State(state): State<AbuseHandlerState>,
    Query(query): Query<ListCasesQuery>,
) -> Result<Json<PaginatedResponse<AbuseCaseSummary>>, StatusCode> {
    let status_filter = query.status.and_then(|s| match s.as_str() {
        "open" => Some(AbuseCaseStatus::Open),
        "escalated" => Some(AbuseCaseStatus::Escalated),
        "dismissed" => Some(AbuseCaseStatus::Dismissed),
        "resolved" => Some(AbuseCaseStatus::Resolved),
        _ => None,
    });

    let limit = query.limit.unwrap_or(50);
    let offset = query.offset.unwrap_or(0);

    let cases = state
        .repo
        .list_cases(status_filter, limit, offset)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let summaries: Vec<AbuseCaseSummary> = cases.into_iter().map(Into::into).collect();
    let total = summaries.len() as i64;

    Ok(Json(PaginatedResponse {
        success: true,
        data: summaries,
        total,
        limit,
        offset,
    }))
}

/// GET /api/admin/abuse/cases/:case_id - Get full abuse case detail
pub async fn get_case_handler(
    State(state): State<AbuseHandlerState>,
    Path(case_id): Path<Uuid>,
) -> Result<Json<ApiResponse<AbuseCase>>, StatusCode> {
    let case = state
        .repo
        .get_case(case_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    Ok(Json(ApiResponse {
        success: true,
        data: case,
        message: None,
    }))
}

/// POST /api/admin/abuse/cases/:case_id/escalate - Escalate abuse case
pub async fn escalate_case_handler(
    State(state): State<AbuseHandlerState>,
    Path(case_id): Path<Uuid>,
    Json(request): Json<CaseEscalationRequest>,
) -> Result<Json<ApiResponse<()>>, StatusCode> {
    let mut case = state
        .repo
        .get_case(case_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    // TODO: Get admin_id from auth context
    let admin_id = Uuid::new_v4();

    case.escalate(admin_id, request.new_tier);

    state
        .repo
        .update_case(&case)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(ApiResponse {
        success: true,
        data: (),
        message: Some("Case escalated successfully".to_string()),
    }))
}

/// POST /api/admin/abuse/cases/:case_id/dismiss - Dismiss false positive
pub async fn dismiss_case_handler(
    State(state): State<AbuseHandlerState>,
    Path(case_id): Path<Uuid>,
    Json(request): Json<CaseDismissalRequest>,
) -> Result<Json<ApiResponse<()>>, StatusCode> {
    let mut case = state
        .repo
        .get_case(case_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    // TODO: Get admin_id from auth context
    let admin_id = Uuid::new_v4();

    case.dismiss(admin_id, request.reason, request.whitelist_signal_types);

    state
        .repo
        .update_case(&case)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(ApiResponse {
        success: true,
        data: (),
        message: Some("Case dismissed successfully".to_string()),
    }))
}

/// POST /api/admin/abuse/cases/:case_id/resolve - Resolve abuse case
pub async fn resolve_case_handler(
    State(state): State<AbuseHandlerState>,
    Path(case_id): Path<Uuid>,
    Json(request): Json<CaseResolutionRequest>,
) -> Result<Json<ApiResponse<()>>, StatusCode> {
    let mut case = state
        .repo
        .get_case(case_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    // TODO: Get admin_id from auth context
    let admin_id = Uuid::new_v4();

    case.resolve(admin_id, request.notes);

    state
        .repo
        .update_case(&case)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(ApiResponse {
        success: true,
        data: (),
        message: Some("Case resolved successfully".to_string()),
    }))
}
