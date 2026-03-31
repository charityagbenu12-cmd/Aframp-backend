//! Route definitions for the Corridor Router.

use crate::corridors::router::handlers::*;
use axum::{
    routing::{get, patch, post},
    Router,
};
use std::sync::Arc;

/// Public routes — route lookup and corridor listing.
pub fn corridor_router_public(state: Arc<CorridorRouterState>) -> Router {
    Router::new()
        .route("/route", post(resolve_route_handler))
        .route("/", get(list_corridors_handler))
        .route("/:id", get(get_corridor_handler))
        .route("/:id/health", get(get_health_handler))
        .with_state(state)
}

/// Admin routes — create, update, kill-switch.
pub fn corridor_router_admin(state: Arc<CorridorRouterState>) -> Router {
    Router::new()
        .route("/", post(create_corridor_handler))
        .route("/:id", patch(update_corridor_handler))
        .route("/:id/toggle", post(toggle_corridor_handler))
        .with_state(state)
}
