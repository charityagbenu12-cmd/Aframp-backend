use super::{handlers::get_oracle_price, service::OracleService};
use axum::{routing::get, Router};
use std::sync::Arc;

pub fn oracle_routes(svc: Arc<OracleService>) -> Router {
    Router::new()
        .route("/v1/oracle/price", get(get_oracle_price))
        .with_state(svc)
}
