use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use std::sync::Arc;

use crate::dex_market_maker::bot::MarketMakerBot;
use crate::dex_market_maker::models::MarketMakerStatus;

/// GET /market-maker/status
///
/// Returns the current state of the market maker for the Market Operations
/// Dashboard (#1.08).
pub async fn get_status(
    State(bot): State<Arc<MarketMakerBot>>,
) -> impl IntoResponse {
    let open_offers = bot.open_offers.read().await.len();
    let last_price = *bot.last_price.read().await;
    let inventory = bot.last_inventory.read().await;
    let half_spread = bot.config.target_spread / 2.0;

    let status = MarketMakerStatus {
        active: !bot.circuit_breaker.is_tripped(),
        circuit_breaker_tripped: bot.circuit_breaker.is_tripped(),
        last_cycle_at: None, // populated from DB in production
        current_spread_pct: bot.config.target_spread * 100.0,
        bid_price: if last_price > 0.0 { last_price * (1.0 - half_spread) } else { 0.0 },
        ask_price: if last_price > 0.0 { last_price * (1.0 + half_spread) } else { 0.0 },
        open_orders: open_offers,
        inventory_cngn: inventory.cngn,
        inventory_counter: inventory.counter,
    };

    (StatusCode::OK, Json(status))
}

/// POST /market-maker/circuit-breaker/reset
///
/// Admin endpoint to manually reset the circuit breaker.
pub async fn reset_circuit_breaker(
    State(bot): State<Arc<MarketMakerBot>>,
) -> impl IntoResponse {
    bot.circuit_breaker.reset();
    tracing::info!("Circuit breaker manually reset by admin");
    StatusCode::NO_CONTENT
}
