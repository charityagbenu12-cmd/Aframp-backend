use crate::analytics::handlers::*;
use crate::analytics::AnalyticsState;
use crate::admin::middleware::admin_auth_middleware;
use crate::admin::models::AdminAuthState;
use axum::{middleware, routing::get, Router};
use std::sync::Arc;

/// All analytics routes are nested under `/api/admin/analytics` and protected
/// by the same admin JWT middleware used across the admin module.
pub fn analytics_routes(auth_state: Arc<AdminAuthState>) -> Router<Arc<AnalyticsState>> {
    Router::new()
        .route("/transactions/volume", get(transaction_volume_handler))
        .route("/cngn/conversions", get(cngn_conversions_handler))
        .route("/providers/performance", get(provider_performance_handler))
        .route("/summary", get(summary_handler))
        .layer(middleware::from_fn_with_state(auth_state, admin_auth_middleware))
}
