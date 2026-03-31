//! Router configuration for service authentication admin endpoints

use axum::{
    routing::{get, post},
    Router,
};
use std::sync::Arc;

use crate::api::service_admin::{
    add_permission, get_service, list_allowlist, list_service_allowlist, list_services,
    register_service, remove_permission, rotate_secret, ServiceAdminState,
};

/// Build the service admin router
///
/// Mount this at `/admin/services`
pub fn service_admin_router(state: ServiceAdminState) -> Router {
    Router::new()
        // Service management
        .route("/register", post(register_service))
        .route("/", get(list_services))
        .route("/:service_name", get(get_service))
        .route("/:service_name/rotate-secret", post(rotate_secret))
        // Allowlist management
        .route("/allowlist", get(list_allowlist))
        .route("/allowlist/:service_name", get(list_service_allowlist))
        .route("/allowlist/add", post(add_permission))
        .route("/allowlist/remove", post(remove_permission))
        .with_state(state)
}
