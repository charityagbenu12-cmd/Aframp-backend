//! Nostro HTTP handlers — Treasury operator interface

use super::repository::NostroRepository;
use super::shadow_ledger::ShadowLedger;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

/// GET /v1/treasury/liquidity — global liquidity map
pub async fn global_liquidity_map(
    State(ledger): State<Arc<ShadowLedger>>,
) -> impl IntoResponse {
    match ledger.global_liquidity_map().await {
        Ok(map) => (StatusCode::OK, Json(serde_json::json!({ "corridors": map }))).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

/// GET /v1/treasury/corridors/:corridor_id/status — check corridor availability
pub async fn corridor_status(
    State(repo): State<Arc<NostroRepository>>,
    Path(corridor_id): Path<String>,
) -> impl IntoResponse {
    match repo.get_corridor_status(&corridor_id).await {
        Ok(status) => (
            StatusCode::OK,
            Json(serde_json::json!({ "corridor_id": corridor_id, "status": format!("{:?}", status) })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}
