use crate::bug_bounty::handlers::{
    create_invitation, create_report, get_metrics, get_report, list_invitations, list_reports,
    record_reward, transition_to_public, update_report, BugBountyState,
};
use axum::{
    routing::{get, patch, post},
    Router,
};

/// Registers all bug bounty routes under `/api/admin/security/bug-bounty`.
///
/// All endpoints are protected by the existing admin authentication middleware
/// (HTTP 403 for non-Admin principals).
pub fn bug_bounty_routes(state: BugBountyState) -> Router {
    Router::new()
        // Reports
        .route(
            "/api/admin/security/bug-bounty/reports",
            post(create_report).get(list_reports),
        )
        .route(
            "/api/admin/security/bug-bounty/reports/:report_id",
            get(get_report).patch(update_report),
        )
        .route(
            "/api/admin/security/bug-bounty/reports/:report_id/reward",
            post(record_reward),
        )
        // Metrics
        .route(
            "/api/admin/security/bug-bounty/metrics",
            get(get_metrics),
        )
        // Invitations
        .route(
            "/api/admin/security/bug-bounty/invitations",
            post(create_invitation).get(list_invitations),
        )
        // Private-to-public transition
        .route(
            "/api/admin/security/bug-bounty/transition-to-public",
            post(transition_to_public),
        )
        .with_state(state)
}
