use axum::{routing::{get, post}, Router};
use std::sync::Arc;

use crate::dex_market_maker::bot::MarketMakerBot;
use crate::dex_market_maker::handlers::{get_status, reset_circuit_breaker};

pub fn router(bot: Arc<MarketMakerBot>) -> Router {
    Router::new()
        .route("/market-maker/status", get(get_status))
        .route("/market-maker/circuit-breaker/reset", post(reset_circuit_breaker))
        .with_state(bot)
}
