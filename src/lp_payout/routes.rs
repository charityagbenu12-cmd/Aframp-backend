use crate::lp_payout::handlers::{get_accrued_vs_paid, list_epochs, LpPayoutState};
use axum::{routing::get, Router};

pub fn lp_payout_routes(state: LpPayoutState) -> Router {
    Router::new()
        .route("/api/lp/rewards/{lp_provider_id}", get(get_accrued_vs_paid))
        .route("/api/lp/epochs", get(list_epochs))
        .with_state(state)
}
