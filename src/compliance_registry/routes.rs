//! Axum route definitions for the Compliance Registry (Issue #2.02).

use crate::compliance_registry::handlers::*;
use axum::{
    routing::{get, patch, post},
    Router,
};
use std::sync::Arc;

pub fn compliance_registry_router(state: Arc<ComplianceRegistryState>) -> Router {
    Router::new()
        // Corridors
        .route("/corridors", post(create_corridor_handler))
        .route("/corridors", get(list_corridors_handler))
        .route("/corridors/:id", get(get_corridor_handler))
        .route("/corridors/:id/status", patch(update_corridor_status_handler))
        // Licenses
        .route("/licenses", post(create_license_handler))
        .route("/corridors/:corridor_id/licenses", get(list_licenses_handler))
        .route("/licenses/:id/status", patch(update_license_status_handler))
        // Rulesets
        .route("/rulesets", post(create_ruleset_handler))
        .route("/corridors/:corridor_id/rulesets", get(list_rulesets_handler))
        .route("/rulesets/:id", patch(update_ruleset_handler))
        // Compliance check (transaction gate)
        .route("/corridors/:corridor_id/check", get(compliance_check_handler))
        // Readiness report
        .route("/corridors/:corridor_id/report", get(readiness_report_handler))
        .with_state(state)
}
