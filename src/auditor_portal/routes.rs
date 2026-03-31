use crate::auditor_portal::handlers::*;
use axum::{
    routing::{get, post},
    Router,
};
use std::sync::Arc;

/// Auditor-facing routes — no admin auth required (session token enforced per-handler).
pub fn auditor_routes(state: Arc<AuditorPortalState>) -> Router {
    Router::new()
        .route("/auditor/login", post(login))
        .route("/auditor/logout", post(logout))
        .route("/auditor/export", get(export_evidence))
        .route("/auditor/verify", get(verify_hash_chain))
        .route("/auditor/packets", get(list_quarterly_packets))
        .with_state(state)
}

/// Admin-only routes — caller must apply admin auth middleware before mounting.
pub fn admin_auditor_routes(state: Arc<AuditorPortalState>) -> Router {
    Router::new()
        .route("/admin/auditor/accounts", post(admin_create_auditor))
        .route("/admin/auditor/windows", post(admin_create_window))
        .route("/admin/auditor/whitelist", post(admin_add_ip_whitelist))
        .route("/admin/auditor/access-log", get(admin_list_access_log))
        .route("/admin/auditor/packets/generate", post(admin_generate_quarterly_packet))
        .with_state(state)
}
