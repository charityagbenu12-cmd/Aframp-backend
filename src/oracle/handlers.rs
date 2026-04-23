//! GET /v1/oracle/price — internal endpoint for other services.

use super::{service::OracleService, types::OracleState};
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::Serialize;
use std::sync::Arc;

#[derive(Serialize)]
pub struct PriceResponse {
    pub pair: String,
    pub price: f64,
    pub sources_used: usize,
    pub fetched_at: chrono::DateTime<chrono::Utc>,
    pub state: OracleState,
}

#[derive(Serialize)]
struct ErrorBody {
    error: &'static str,
    state: OracleState,
}

pub async fn get_oracle_price(State(svc): State<Arc<OracleService>>) -> impl IntoResponse {
    let state = svc.get_state().await;

    match svc.get_price().await {
        Some(p) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "pair": p.pair,
                "price": p.price,
                "sources_used": p.sources_used,
                "fetched_at": p.fetched_at,
                "state": state,
            })),
        )
            .into_response(),
        None => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": "price_frozen",
                "message": "All oracle sources are unavailable. Automated trading is halted.",
                "state": state,
            })),
        )
            .into_response(),
    }
}
