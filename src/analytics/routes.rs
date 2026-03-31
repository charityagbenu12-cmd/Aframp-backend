
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

use super::handlers::*;
use axum::{
    routing::get,
    Router,
};
use std::sync::Arc;

pub fn consumer_analytics_routes() -> Router<Arc<AnalyticsRepository>> {
    Router::new()
        .route("/usage/summary", get(get_usage_summary))
        .route("/usage/endpoints", get(get_endpoint_usage))
        .route("/usage/features", get(get_feature_adoption))
}

pub fn admin_analytics_routes() -> Router<Arc<AnalyticsRepository>> {
    Router::new()
        .route("/consumers/overview", get(get_consumer_overview))
        .route("/consumers/health", get(get_at_risk_consumers))
        .route("/consumers/:consumer_id/detail", get(get_consumer_detail))
        .route("/reports", get(get_platform_reports))

}
