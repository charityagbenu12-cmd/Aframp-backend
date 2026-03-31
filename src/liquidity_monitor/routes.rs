use crate::liquidity_monitor::handlers::{get_market_depth, EngineState};
use axum::{routing::get, Router};

pub fn liquidity_routes() -> Router<EngineState> {
    Router::new().route("/depth", get(get_market_depth))
}
