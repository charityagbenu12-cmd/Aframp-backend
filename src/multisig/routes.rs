//! Route registration for the Multi-Sig Governance API.
//!
//! Mount these routes under `/api/v1` in main.rs.
//!
//! # Endpoints
//!
//! | Method | Path                                    | Description                              |
//! |--------|-----------------------------------------|------------------------------------------|
//! | POST   | /governance/proposals                   | Create a new treasury operation proposal |
//! | GET    | /governance/proposals                   | List proposals (filterable)              |
//! | GET    | /governance/proposals/:id               | Get proposal detail + XDR                |
//! | POST   | /governance/proposals/:id/sign          | Submit a cryptographic signature         |
//! | POST   | /governance/proposals/:id/submit        | Submit signed XDR to Stellar Horizon     |
//! | POST   | /governance/proposals/:id/reject        | Reject a proposal                        |
//! | GET    | /governance/proposals/:id/log           | Governance audit log for a proposal      |

use crate::multisig::handlers::{
    get_governance_log, get_proposal, list_proposals, propose, reject_proposal,
    sign_proposal, submit_proposal, MultiSigState,
};
use axum::{
    routing::{get, post},
    Router,
};

/// Build the governance router.
///
/// # Usage
/// ```rust,ignore
/// let app = Router::new()
///     .nest("/api/v1", multisig::routes::governance_router(multisig_state));
/// ```
pub fn governance_router(state: MultiSigState) -> Router {
    Router::new()
        .route(
            "/governance/proposals",
            post(propose).get(list_proposals),
        )
        .route(
            "/governance/proposals/:id",
            get(get_proposal),
        )
        .route(
            "/governance/proposals/:id/sign",
            post(sign_proposal),
        )
        .route(
            "/governance/proposals/:id/submit",
            post(submit_proposal),
        )
        .route(
            "/governance/proposals/:id/reject",
            post(reject_proposal),
        )
        .route(
            "/governance/proposals/:id/log",
            get(get_governance_log),
        )
        .with_state(state)
}
