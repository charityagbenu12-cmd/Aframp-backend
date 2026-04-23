use crate::error::AppError;
use crate::pos::legacy_bridge::{LegacyBridge, LegacyPaymentRequest};
use crate::pos::lobby_service::LobbyService;
use crate::pos::payment_intent::PaymentIntentService;
use crate::pos::proof_of_payment::ProofOfPayment;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{info, instrument};
use uuid::Uuid;

/// Shared state for POS handlers
#[derive(Clone)]
pub struct PosState {
    pub payment_intent_service: Arc<PaymentIntentService>,
    pub lobby_service: Arc<LobbyService>,
    pub legacy_bridge: Arc<LegacyBridge>,
    pub proof_of_payment: Arc<ProofOfPayment>,
}

/// Create new payment intent
#[instrument(skip(state))]
pub async fn create_payment_intent(
    State(state): State<PosState>,
    Json(request): Json<CreatePaymentIntentRequest>,
) -> Result<Json<CreatePaymentIntentResponse>, AppError> {
    let payment_intent = state.payment_intent_service
        .create_payment_intent(
            request.merchant_id,
            request.order_id,
            request.amount_cngn,
        )
        .await?;

    // Register for real-time monitoring
    let _rx = state.lobby_service
        .register_payment(payment_intent.id, payment_intent.memo.clone())
        .await?;

    let response = CreatePaymentIntentResponse {
        payment_id: payment_intent.id,
        order_id: payment_intent.order_id,
        qr_code_svg: payment_intent.qr_code_data,
        amount_cngn: payment_intent.amount_cngn,
        expires_at: payment_intent.expires_at,
        status: format!("{:?}", payment_intent.status).to_lowercase(),
    };

    info!(payment_id = %payment_intent.id, "Payment intent created via API");
    Ok(Json(response))
}

/// Get payment intent status
#[instrument(skip(state))]
pub async fn get_payment_status(
    State(state): State<PosState>,
    Path(payment_id): Path<Uuid>,
) -> Result<Json<PaymentStatusResponse>, AppError> {
    let payment = state.payment_intent_service
        .get_payment_intent(payment_id)
        .await?;

    let response = PaymentStatusResponse {
        payment_id: payment.id,
        order_id: payment.order_id,
        status: format!("{:?}", payment.status).to_lowercase(),
        amount_expected: payment.amount_cngn,
        amount_received: payment.actual_amount_received,
        stellar_tx_hash: payment.stellar_tx_hash,
        confirmed_at: payment.confirmed_at,
        is_complete: matches!(
            payment.status,
            crate::pos::models::PosPaymentStatus::Confirmed
        ),
        has_discrepancy: matches!(
            payment.status,
            crate::pos::models::PosPaymentStatus::Discrepancy
        ),
    };

    Ok(Json(response))
}

/// Cancel payment intent
#[instrument(skip(state))]
pub async fn cancel_payment(
    State(state): State<PosState>,
    Path(payment_id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    state.payment_intent_service
        .cancel_payment_intent(payment_id)
        .await?;

    info!(payment_id = %payment_id, "Payment cancelled via API");
    Ok(StatusCode::OK)
}

/// Legacy POS integration endpoint
#[instrument(skip(state))]
pub async fn legacy_create_payment(
    State(state): State<PosState>,
    Json(request): Json<LegacyPaymentRequest>,
) -> Result<Json<crate::pos::legacy_bridge::LegacyPaymentResponse>, AppError> {
    let response = state.legacy_bridge
        .create_payment_from_legacy(request)
        .await?;

    Ok(Json(response))
}

/// Legacy POS status check endpoint
#[instrument(skip(state))]
pub async fn legacy_check_status(
    State(state): State<PosState>,
    Path(payment_id): Path<Uuid>,
) -> Result<Json<crate::pos::legacy_bridge::LegacyPaymentStatusResponse>, AppError> {
    let response = state.legacy_bridge
        .check_payment_status(payment_id)
        .await?;

    Ok(Json(response))
}

/// Generate proof of payment
#[instrument(skip(state))]
pub async fn generate_proof_of_payment(
    State(state): State<PosState>,
    Path(payment_id): Path<Uuid>,
) -> Result<Json<crate::pos::proof_of_payment::ProofOfPaymentDisplay>, AppError> {
    let proof = state.proof_of_payment
        .generate_proof(payment_id)
        .await?;

    let qr_code = state.proof_of_payment
        .generate_proof_qr(&proof)?;

    let display = crate::pos::proof_of_payment::ProofOfPaymentDisplay::from_record(
        proof,
        qr_code,
    );

    Ok(Json(display))
}

/// Verify proof of payment
#[instrument(skip(state))]
pub async fn verify_proof_of_payment(
    State(state): State<PosState>,
    Path(payment_id): Path<Uuid>,
    Json(request): Json<VerifyProofRequest>,
) -> Result<Json<VerifyProofResponse>, AppError> {
    let is_valid = state.proof_of_payment
        .verify_proof(payment_id, &request.verification_code)
        .await?;

    Ok(Json(VerifyProofResponse { is_valid }))
}

// ============================================================================
// Request/Response Types
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct CreatePaymentIntentRequest {
    pub merchant_id: Uuid,
    pub order_id: String,
    pub amount_cngn: Decimal,
}

#[derive(Debug, Serialize)]
pub struct CreatePaymentIntentResponse {
    pub payment_id: Uuid,
    pub order_id: String,
    pub qr_code_svg: String,
    pub amount_cngn: Decimal,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub status: String,
}

#[derive(Debug, Serialize)]
pub struct PaymentStatusResponse {
    pub payment_id: Uuid,
    pub order_id: String,
    pub status: String,
    pub amount_expected: Decimal,
    pub amount_received: Option<Decimal>,
    pub stellar_tx_hash: Option<String>,
    pub confirmed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub is_complete: bool,
    pub has_discrepancy: bool,
}

#[derive(Debug, Deserialize)]
pub struct VerifyProofRequest {
    pub verification_code: String,
}

#[derive(Debug, Serialize)]
pub struct VerifyProofResponse {
    pub is_valid: bool,
}
