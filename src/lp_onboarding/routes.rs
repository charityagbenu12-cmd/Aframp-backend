use super::handlers::*;
use axum::{
    routing::{delete, get, patch, post},
    Router,
};

/// Partner-facing routes (authenticated LP user)
pub fn partner_routes(state: LpOnboardingState) -> Router {
    Router::new()
        .route("/api/lp/register", post(register_partner))
        .route("/api/lp/partners/:partner_id/dashboard", get(get_dashboard))
        .route("/api/lp/partners/:partner_id/documents", post(upload_document))
        .route("/api/lp/partners/:partner_id/stellar-keys", post(add_stellar_key))
        .with_state(state)
}

/// Admin-only routes (require admin auth middleware applied by caller)
pub fn admin_routes(state: LpOnboardingState) -> Router {
    Router::new()
        .route("/api/admin/lp/partners", get(list_partners))
        .route("/api/admin/lp/partners/:partner_id/tier", patch(update_tier))
        .route("/api/admin/lp/partners/:partner_id/revoke", post(revoke_partner))
        .route("/api/admin/lp/partners/:partner_id/kyb-passed", post(mark_kyb_passed))
        .route("/api/admin/lp/partners/:partner_id/agreements", post(send_agreement))
        .route(
            "/api/admin/lp/partners/:partner_id/documents/:document_id/review",
            post(review_document),
        )
        .route(
            "/api/admin/lp/partners/:partner_id/stellar-keys/:key_id/revoke",
            delete(revoke_stellar_key),
        )
        .with_state(state)
}

/// DocuSign webhook receiver (unauthenticated, verified by HMAC in middleware)
pub fn webhook_routes(state: LpOnboardingState) -> Router {
    Router::new()
        .route("/webhooks/docusign/lp-agreement", post(docusign_webhook))
        .with_state(state)
}
