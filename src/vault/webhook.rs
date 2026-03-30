use crate::vault::{
    service::VaultService,
    types::{InboundDepositEvent, VaultError},
};
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use chrono::Utc;
use rust_decimal::Decimal;
use serde::Deserialize;
use std::sync::Arc;
use tracing::warn;

/// Raw webhook payload from the custodian (bank-specific shape).
/// Normalised into `InboundDepositEvent` before processing.
#[derive(Debug, Deserialize)]
pub struct CustodianWebhookPayload {
    pub event_id: String,
    pub account_id: String,
    pub amount: Decimal,
    pub currency: String,
    pub sender_name: Option<String>,
    pub sender_account: Option<String>,
    pub reference: String,
}

/// POST /vault/webhooks/inbound-deposit
///
/// Receives custodian webhook for inbound NGN transfers.
/// Validates the HMAC signature header, normalises the payload,
/// and hands off to `VaultService::handle_inbound_deposit`.
pub async fn inbound_deposit_handler(
    State(vault): State<Arc<VaultService>>,
    headers: HeaderMap,
    Json(payload): Json<CustodianWebhookPayload>,
) -> impl IntoResponse {
    // Signature verification: the custodian signs the body with a shared secret.
    // The actual HMAC check is delegated to the existing HmacSigningMiddleware
    // (src/middleware/hmac_signing) which runs before this handler.
    // If we reach here, the signature is already verified.

    if payload.amount <= Decimal::ZERO {
        warn!(event_id = %payload.event_id, "inbound deposit with non-positive amount rejected");
        return StatusCode::BAD_REQUEST.into_response();
    }

    let event = InboundDepositEvent {
        event_id: payload.event_id,
        account_id: payload.account_id,
        amount: payload.amount,
        currency: payload.currency,
        sender_name: payload.sender_name,
        sender_account: payload.sender_account,
        reference: payload.reference,
        received_at: Utc::now(),
    };

    match vault.handle_inbound_deposit(event).await {
        Ok(()) => StatusCode::OK.into_response(),
        Err(e) => {
            warn!(error = %e, "failed to process inbound deposit webhook");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}
