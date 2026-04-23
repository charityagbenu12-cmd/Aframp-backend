/// Route registration for the Smart Treasury Allocation Engine.
///
/// Internal routes require the treasury-operator RBAC middleware (injected
/// by the caller via `layer()`).  The public route is unauthenticated.
use super::handlers::*;
use axum::{
    routing::{get, post},
    Router,
};

/// Returns the router for internal treasury-operator endpoints.
/// Mount at `/treasury/allocation` behind your auth middleware.
pub fn internal_router(state: AllocationState) -> Router {
    Router::new()
        // Allocation recording + monitor
        .route("/record", post(record_allocation))
        .route("/monitor", get(get_allocation_monitor))
        // Alerts
        .route("/alerts", get(list_alerts))
        // RWA
        .route("/rwa/latest", get(get_latest_rwa))
        .route("/rwa/calculate", post(calculate_rwa))
        // Transfer orders
        .route("/orders", get(list_transfer_orders))
        .route("/orders/:id", get(get_transfer_order))
        .route("/orders/:id/decision", post(decide_transfer_order))
        .route("/orders/:id/complete", post(complete_transfer_order))
        // Custodian management
        .route("/custodians/:id/rating", post(update_custodian_rating))
        .with_state(state)
}

/// Returns the router for the public transparency endpoint.
/// Mount at `/treasury/allocation` without auth middleware.
pub fn public_router(state: AllocationState) -> Router {
    Router::new()
        .route("/public", get(public_reserve_dashboard))
        .with_state(state)
}
