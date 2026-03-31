//! AML HTTP handlers — compliance officer interface

use super::case_management::AmlCaseManager;
use super::repository::AmlRepository;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct CaseDecisionRequest {
    pub officer_id: String,
    pub notes: String,
}

#[derive(Debug, Serialize)]
pub struct CaseDecisionResponse {
    pub case_id: Uuid,
    pub status: String,
    pub message: String,
}

/// GET /v1/aml/cases/pending — list all pending compliance cases
pub async fn list_pending_cases(
    State(repo): State<Arc<AmlRepository>>,
) -> impl IntoResponse {
    match repo.get_pending_cases().await {
        Ok(cases) => (StatusCode::OK, Json(serde_json::json!({ "cases": cases }))).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

/// POST /v1/aml/cases/:case_id/clear — compliance officer clears a case
pub async fn clear_case(
    State(manager): State<Arc<AmlCaseManager>>,
    Path(case_id): Path<Uuid>,
    Json(body): Json<CaseDecisionRequest>,
) -> impl IntoResponse {
    match manager.clear_case(case_id, &body.officer_id, &body.notes).await {
        Ok(case) => (
            StatusCode::OK,
            Json(CaseDecisionResponse {
                case_id,
                status: case.status,
                message: "Transaction cleared for processing".into(),
            }),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

/// POST /v1/aml/cases/:case_id/block — compliance officer permanently blocks
pub async fn block_case(
    State(manager): State<Arc<AmlCaseManager>>,
    Path(case_id): Path<Uuid>,
    Json(body): Json<CaseDecisionRequest>,
) -> impl IntoResponse {
    match manager.block_case(case_id, &body.officer_id, &body.notes).await {
        Ok(case) => (
            StatusCode::OK,
            Json(CaseDecisionResponse {
                case_id,
                status: case.status,
                message: "Transaction permanently blocked".into(),
            }),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}
