//! HTTP handlers for Merchant Gateway API

use crate::error::AppError;
use crate::merchant_gateway::models::*;
use crate::merchant_gateway::service::MerchantGatewayService;
use crate::middleware::api_key::AuthenticatedKey;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Extension, Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{info, instrument};
use uuid::Uuid;

// ============================================================================
// REQUEST/RESPONSE TYPES
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct PaginationQuery {
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

fn default_limit() -> i64 {
    50
}

#[derive(Debug, Serialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub data: T,
}

#[derive(Debug, Serialize)]
pub struct ApiError {
    pub success: bool,
    pub error: ErrorDetail,
}

#[derive(Debug, Serialize)]
pub struct ErrorDetail {
    pub code: String,
    pub message: String,
}

// ============================================================================
// HANDLERS
// ============================================================================

/// Create a new payment intent
/// POST /api/v1/merchant/payment-intents
#[instrument(skip(service, auth))]
pub async fn create_payment_intent(
    State(service): State<Arc<MerchantGatewayService>>,
    Extension(auth): Extension<AuthenticatedKey>,
    Json(request): Json<CreatePaymentIntentRequest>,
) -> Result<Json<ApiResponse<PaymentIntentResponse>>, AppError> {
    // Extract merchant_id from authenticated API key
    let merchant_id = auth.consumer_id; // Assuming consumer_id is merchant_id

    let response = service.create_payment_intent(merchant_id, request).await?;

    info!(
        payment_intent_id = %response.payment_intent_id,
        merchant_id = %merchant_id,
        "Payment intent created via API"
    );

    Ok(Json(ApiResponse {
        success: true,
        data: response,
    }))
}

/// Get payment intent by ID
/// GET /api/v1/merchant/payment-intents/:id
#[instrument(skip(service, auth))]
pub async fn get_payment_intent(
    State(service): State<Arc<MerchantGatewayService>>,
    Extension(auth): Extension<AuthenticatedKey>,
    Path(payment_intent_id): Path<Uuid>,
) -> Result<Json<ApiResponse<MerchantPaymentIntent>>, AppError> {
    let merchant_id = auth.consumer_id;

    let payment_intent = service
        .get_payment_intent(merchant_id, payment_intent_id)
        .await?;

    Ok(Json(ApiResponse {
        success: true,
        data: payment_intent,
    }))
}

/// List payment intents for merchant
/// GET /api/v1/merchant/payment-intents
#[instrument(skip(service, auth))]
pub async fn list_payment_intents(
    State(service): State<Arc<MerchantGatewayService>>,
    Extension(auth): Extension<AuthenticatedKey>,
    Query(pagination): Query<PaginationQuery>,
) -> Result<Json<ApiResponse<Vec<MerchantPaymentIntent>>>, AppError> {
    let merchant_id = auth.consumer_id;

    let payment_intents = service
        .list_payment_intents(merchant_id, pagination.limit, pagination.offset)
        .await?;

    Ok(Json(ApiResponse {
        success: true,
        data: payment_intents,
    }))
}

/// Cancel a payment intent
/// POST /api/v1/merchant/payment-intents/:id/cancel
#[instrument(skip(service, auth))]
pub async fn cancel_payment_intent(
    State(service): State<Arc<MerchantGatewayService>>,
    Extension(auth): Extension<AuthenticatedKey>,
    Path(payment_intent_id): Path<Uuid>,
) -> Result<Json<ApiResponse<MerchantPaymentIntent>>, AppError> {
    let merchant_id = auth.consumer_id;

    let payment_intent = service
        .cancel_payment_intent(merchant_id, payment_intent_id)
        .await?;

    Ok(Json(ApiResponse {
        success: true,
        data: payment_intent,
    }))
}

/// Verify webhook signature (utility endpoint for merchants)
/// POST /api/v1/merchant/webhooks/verify
#[derive(Debug, Deserialize)]
pub struct VerifyWebhookRequest {
    pub payload: serde_json::Value,
    pub signature: String,
    pub webhook_secret: String,
}

#[derive(Debug, Serialize)]
pub struct VerifyWebhookResponse {
    pub valid: bool,
}

pub async fn verify_webhook_signature(
    Json(request): Json<VerifyWebhookRequest>,
) -> Result<Json<ApiResponse<VerifyWebhookResponse>>, AppError> {
    let valid = crate::merchant_gateway::webhook_engine::WebhookEngine::verify_signature(
        &request.webhook_secret,
        &request.payload,
        &request.signature,
    )
    .unwrap_or(false);

    Ok(Json(ApiResponse {
        success: true,
        data: VerifyWebhookResponse { valid },
    }))
}

// ============================================================================
// ERROR HANDLING
// ============================================================================

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, code, message) = match self {
            AppError::NotFound(msg) => (StatusCode::NOT_FOUND, "NOT_FOUND", msg),
            AppError::BadRequest(msg) => (StatusCode::BAD_REQUEST, "BAD_REQUEST", msg),
            AppError::Forbidden(msg) => (StatusCode::FORBIDDEN, "FORBIDDEN", msg),
            AppError::DatabaseError(msg) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "DATABASE_ERROR", msg)
            }
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "An internal error occurred".to_string(),
            ),
        };

        let body = Json(ApiError {
            success: false,
            error: ErrorDetail {
                code: code.to_string(),
                message,
            },
        });

        (status, body).into_response()
    }
}
