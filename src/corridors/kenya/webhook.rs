//! M-Pesa Kenya webhook handler — translates Safaricom B2C result codes
//! into Aframp transaction states and triggers refunds on failure.

use crate::corridors::kenya::models::KenyaTransferStatus;
use crate::payments::providers::mpesa_kenya::MpesaKenyaProvider;
use crate::payments::provider::PaymentProvider;
use crate::payments::types::PaymentState;
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde_json::Value as JsonValue;
use sqlx::PgPool;
use std::sync::Arc;
use tracing::{error, info, warn};
use uuid::Uuid;

pub struct KenyaWebhookState {
    pub pool: Arc<PgPool>,
    pub mpesa_provider: Arc<MpesaKenyaProvider>,
}

/// POST /webhooks/mpesa_kenya
pub async fn handle_mpesa_kenya_webhook(
    State(state): State<Arc<KenyaWebhookState>>,
    body: String,
) -> impl IntoResponse {
    let payload: JsonValue = match serde_json::from_str(&body) {
        Ok(p) => p,
        Err(e) => {
            error!(error = %e, "Invalid M-Pesa Kenya webhook JSON");
            return (StatusCode::BAD_REQUEST, "Invalid JSON").into_response();
        }
    };

    let event = match state.mpesa_provider.parse_webhook_event(body.as_bytes()) {
        Ok(e) => e,
        Err(e) => {
            error!(error = %e, "Failed to parse M-Pesa Kenya webhook");
            return (StatusCode::OK, Json(serde_json::json!({"status":"ok"}))).into_response();
        }
    };

    let tx_ref = match &event.transaction_reference {
        Some(r) => r.clone(),
        None => {
            warn!("M-Pesa Kenya webhook missing transaction reference");
            return (StatusCode::OK, Json(serde_json::json!({"status":"ok"}))).into_response();
        }
    };

    let transfer_id = match Uuid::parse_str(&tx_ref) {
        Ok(id) => id,
        Err(_) => {
            warn!(tx_ref = %tx_ref, "M-Pesa Kenya webhook tx_ref is not a UUID");
            return (StatusCode::OK, Json(serde_json::json!({"status":"ok"}))).into_response();
        }
    };

    let new_status = match event.status {
        Some(PaymentState::Success) => KenyaTransferStatus::Completed,
        Some(PaymentState::Failed) => KenyaTransferStatus::RefundInitiated,
        Some(PaymentState::Unknown) => {
            // Timeout — leave as DisbursementPending for the retry worker.
            warn!(transfer_id = %transfer_id, "M-Pesa Kenya timeout — leaving as disbursement_pending");
            return (StatusCode::OK, Json(serde_json::json!({"status":"ok"}))).into_response();
        }
        _ => {
            warn!(transfer_id = %transfer_id, "M-Pesa Kenya webhook unknown status");
            return (StatusCode::OK, Json(serde_json::json!({"status":"ok"}))).into_response();
        }
    };

    // Persist status update.
    let result = sqlx::query!(
        r#"
        UPDATE transactions
        SET status = $2,
            payment_reference = COALESCE($3, payment_reference),
            metadata = metadata || $4::jsonb,
            updated_at = NOW()
        WHERE transaction_id = $1
          AND type = 'kenya_corridor'
        "#,
        transfer_id,
        new_status.as_str(),
        event.provider_reference,
        serde_json::json!({
            "mpesa_event_type": event.event_type,
            "mpesa_provider_ref": event.provider_reference,
        }),
    )
    .execute(state.pool.as_ref())
    .await;

    match result {
        Ok(r) if r.rows_affected() > 0 => {
            info!(
                transfer_id = %transfer_id,
                status = %new_status.as_str(),
                "Kenya corridor transfer status updated from M-Pesa webhook"
            );

            // If disbursement failed, mark for cNGN refund.
            if new_status == KenyaTransferStatus::RefundInitiated {
                let _ = sqlx::query!(
                    r#"
                    UPDATE transactions
                    SET metadata = metadata || $2::jsonb
                    WHERE transaction_id = $1
                    "#,
                    transfer_id,
                    serde_json::json!({ "refund_reason": "mpesa_disbursement_failed" }),
                )
                .execute(state.pool.as_ref())
                .await;

                warn!(
                    transfer_id = %transfer_id,
                    "M-Pesa disbursement failed — cNGN refund queued"
                );
            }
        }
        Ok(_) => {
            warn!(transfer_id = %transfer_id, "M-Pesa Kenya webhook: no matching transfer found");
        }
        Err(e) => {
            error!(transfer_id = %transfer_id, error = %e, "Failed to update transfer from M-Pesa webhook");
        }
    }

    (StatusCode::OK, Json(serde_json::json!({"status":"ok"}))).into_response()
}
