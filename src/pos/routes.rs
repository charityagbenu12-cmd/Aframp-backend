use crate::pos::handlers::{
    cancel_payment, create_payment_intent, generate_proof_of_payment, get_payment_status,
    legacy_check_status, legacy_create_payment, verify_proof_of_payment, PosState,
};
use crate::pos::websocket::websocket_handler;
use axum::{
    routing::{delete, get, post},
    Router,
};

/// Build POS payment routes
pub fn pos_routes(state: PosState) -> Router {
    Router::new()
        // Core POS payment endpoints
        .route("/v1/pos/payments", post(create_payment_intent))
        .route("/v1/pos/payments/:payment_id", get(get_payment_status))
        .route("/v1/pos/payments/:payment_id", delete(cancel_payment))
        
        // Legacy POS integration endpoints
        .route("/v1/pos/legacy/payments", post(legacy_create_payment))
        .route("/v1/pos/legacy/payments/:payment_id/status", get(legacy_check_status))
        
        // Proof of payment endpoints
        .route("/v1/pos/proof/:payment_id", get(generate_proof_of_payment))
        .route("/v1/pos/proof/:payment_id/verify", post(verify_proof_of_payment))
        
        // WebSocket endpoint for real-time notifications
        .route("/v1/pos/ws/:payment_id", get(websocket_handler))
        
        .with_state(state)
}
