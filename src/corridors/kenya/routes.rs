//! Route definitions for the Nigeria → Kenya corridor.

use crate::corridors::kenya::handlers::*;
use crate::corridors::kenya::webhook::{handle_mpesa_kenya_webhook, KenyaWebhookState};
use axum::{routing::{get, post}, Router};
use std::sync::Arc;

pub fn kenya_corridor_router(state: Arc<KenyaCorridorState>) -> Router {
    Router::new()
        .route("/quote", get(get_quote_handler))
        .route("/transfer", post(initiate_transfer_handler))
        .route("/transfer/:id", get(get_transfer_handler))
        .with_state(state)
}

pub fn kenya_webhook_router(state: Arc<KenyaWebhookState>) -> Router {
    Router::new()
        .route("/mpesa_kenya", post(handle_mpesa_kenya_webhook))
        .with_state(state)
}
