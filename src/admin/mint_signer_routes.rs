use crate::admin::mint_signer_handlers::*;
use crate::admin::mint_signer_service::MintSignerService;
use axum::{routing::{get, patch, post}, Router};
use std::sync::Arc;

pub fn mint_signer_routes() -> Router<Arc<MintSignerService>> {
    Router::new()
        .route("/signers",                              post(initiate_onboarding).get(list_signers))
        .route("/signers/complete-onboarding",          post(complete_onboarding))
        .route("/signers/:id",                          get(get_signer))
        .route("/signers/:id/challenge",                post(request_challenge))
        .route("/signers/:id/confirm-identity",         post(confirm_identity))
        .route("/signers/:id/rotate-key",               post(rotate_key))
        .route("/signers/:id/rotate-key/challenge",     post(request_rotation_challenge))
        .route("/signers/:id/suspend",                  post(suspend_signer))
        .route("/signers/:id/remove",                   post(remove_signer))
        .route("/signers/:id/activity",                 get(get_signer_activity))
        .route("/quorum",                               get(get_quorum).patch(update_quorum))
}
