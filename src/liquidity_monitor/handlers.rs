use crate::liquidity_monitor::engine::LiquidityEngine;
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use std::sync::Arc;

pub type EngineState = Arc<LiquidityEngine>;

/// GET /liquidity/depth
/// Live market depth summary for the Market Operations Dashboard.
pub async fn get_market_depth(State(engine): State<EngineState>) -> impl IntoResponse {
    match engine.latest_summary().await {
        Ok(summary) => (StatusCode::OK, Json(summary)).into_response(),
        Err(e) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "error": e })),
        )
            .into_response(),
    }
}
