use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use bigdecimal::BigDecimal;
use std::collections::HashMap;

use crate::auth::AuthenticatedConsumer;
use crate::database::kyc_repository::{KycTier, KycStatus, DocumentType};
use crate::kyc::service::{KycService, KycServiceError};
use crate::error::ApiError;

#[derive(Debug, Serialize, Deserialize)]
pub struct InitiateKycRequest {
    pub target_tier: KycTier,
    pub callback_url: String,
    pub redirect_url: Option<String>,
    pub language: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InitiateKycResponse {
    pub session_id: String,
    pub session_url: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub status: KycStatus,
    pub target_tier: KycTier,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SubmitDocumentRequest {
    pub session_id: String,
    pub document_type: DocumentType,
    pub front_image_base64: String,
    pub back_image_base64: Option<String>,
    pub document_number: Option<String>,
    pub issuing_country: Option<String>,
    pub expiry_date: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SubmitDocumentResponse {
    pub document_id: String,
    pub status: KycStatus,
    pub extraction_data: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SubmitSelfieRequest {
    pub session_id: String,
    pub selfie_image_base64: String,
    pub liveness_check: Option<bool>,
    pub match_with_document: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SubmitSelfieResponse {
    pub selfie_id: String,
    pub status: KycStatus,
    pub liveness_score: Option<f64>,
    pub face_match_score: Option<f64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KycStatusResponse {
    pub status: KycStatus,
    pub tier: Option<KycTier>,
    pub effective_tier: KycTier,
    pub session_id: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub completed_steps: Vec<String>,
    pub pending_steps: Vec<String>,
    pub decision_reason: Option<String>,
    pub resubmission_allowed_at: Option<DateTime<Utc>>,
    pub enhanced_due_diligence_active: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TransactionLimitsResponse {
    pub tier: KycTier,
    pub effective_tier: KycTier,
    pub max_transaction_amount: BigDecimal,
    pub daily_volume_limit: BigDecimal,
    pub monthly_volume_limit: BigDecimal,
    pub daily_volume_used: BigDecimal,
    pub monthly_volume_used: BigDecimal,
    pub daily_remaining: BigDecimal,
    pub monthly_remaining: BigDecimal,
    pub single_transaction_remaining: BigDecimal,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WebhookPayload {
    pub provider: String,
    pub event_type: String,
    pub session_id: String,
    pub consumer_id: Uuid,
    pub status: KycStatus,
    pub decision: Option<KycDecisionData>,
    pub risk_score: Option<i32>,
    pub risk_flags: Option<Vec<String>>,
    pub timestamp: DateTime<Utc>,
    pub signature: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KycDecisionData {
    pub decision: KycStatus,
    pub reason: String,
    pub tier: Option<KycTier>,
    pub reviewer_notes: Option<String>,
    pub provider_reference: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
    pub message: String,
    pub details: Option<HashMap<String, serde_json::Value>>,
}

pub fn kyc_routes() -> Router<KycService> {
    Router::new()
        .route("/initiate", post(initiate_kyc_session))
        .route("/documents", post(submit_document))
        .route("/selfie", post(submit_selfie))
        .route("/status", get(get_kyc_status))
        .route("/limits", get(get_transaction_limits))
        .route("/webhook", post(handle_webhook))
}

async fn initiate_kyc_session(
    State(kyc_service): State<KycService>,
    auth: AuthenticatedConsumer,
    Json(request): Json<InitiateKycRequest>,
) -> Result<Json<InitiateKycResponse>, ApiError> {
    let response = kyc_service
        .initiate_kyc_session(
            auth.consumer_id,
            request.target_tier,
            request.callback_url,
            request.redirect_url,
            request.language,
        )
        .await
        .map_err(|e| match e {
            KycServiceError::SessionAlreadyActive => ApiError::Conflict("KYC session already active".to_string()),
            KycServiceError::ProviderError(e) => ApiError::BadRequest(format!("Provider error: {}", e)),
            KycServiceError::ConfigurationError(e) => ApiError::InternalServerError(format!("Configuration error: {}", e)),
            _ => ApiError::InternalServerError("Failed to initiate KYC session".to_string()),
        })?;

    Ok(Json(InitiateKycResponse {
        session_id: response.session_id.clone(),
        session_url: response.session_url,
        expires_at: response.expires_at,
        status: response.status,
        target_tier: request.target_tier,
    }))
}

async fn submit_document(
    State(kyc_service): State<KycService>,
    auth: AuthenticatedConsumer,
    Json(request): Json<SubmitDocumentRequest>,
) -> Result<Json<SubmitDocumentResponse>, ApiError> {
    let response = kyc_service
        .submit_document(
            &request.session_id,
            request.document_type,
            request.front_image_base64,
            request.back_image_base64,
            request.document_number,
            request.issuing_country,
            request.expiry_date,
        )
        .await
        .map_err(|e| match e {
            KycServiceError::SessionNotFound => ApiError::NotFound("KYC session not found".to_string()),
            KycServiceError::SessionExpired => ApiError::BadRequest("KYC session has expired".to_string()),
            KycServiceError::ProviderError(e) => ApiError::BadRequest(format!("Provider error: {}", e)),
            _ => ApiError::InternalServerError("Failed to submit document".to_string()),
        })?;

    Ok(Json(SubmitDocumentResponse {
        document_id: response.document_id,
        status: response.status,
        extraction_data: response.extraction_data,
    }))
}

async fn submit_selfie(
    State(kyc_service): State<KycService>,
    auth: AuthenticatedConsumer,
    Json(request): Json<SubmitSelfieRequest>,
) -> Result<Json<SubmitSelfieResponse>, ApiError> {
    let response = kyc_service
        .submit_selfie(
            &request.session_id,
            request.selfie_image_base64,
            request.liveness_check.unwrap_or(true),
            request.match_with_document.unwrap_or(true),
        )
        .await
        .map_err(|e| match e {
            KycServiceError::SessionNotFound => ApiError::NotFound("KYC session not found".to_string()),
            KycServiceError::SessionExpired => ApiError::BadRequest("KYC session has expired".to_string()),
            KycServiceError::ProviderError(e) => ApiError::BadRequest(format!("Provider error: {}", e)),
            _ => ApiError::InternalServerError("Failed to submit selfie".to_string()),
        })?;

    Ok(Json(SubmitSelfieResponse {
        selfie_id: response.selfie_id,
        status: response.status,
        liveness_score: response.liveness_score,
        face_match_score: response.face_match_score,
    }))
}

async fn get_kyc_status(
    State(kyc_service): State<KycService>,
    auth: AuthenticatedConsumer,
) -> Result<Json<KycStatusResponse>, ApiError> {
    let response = kyc_service
        .get_kyc_status(auth.consumer_id)
        .await
        .map_err(|e| match e {
            KycServiceError::KycRecordNotFound => ApiError::NotFound("KYC record not found".to_string()),
            _ => ApiError::InternalServerError("Failed to get KYC status".to_string()),
        })?;

    // Get additional details from database
    let kyc_record = kyc_service.repository
        .get_kyc_record_by_consumer(auth.consumer_id)
        .await
        .map_err(|e| ApiError::InternalServerError(format!("Database error: {}", e)))?
        .ok_or_else(|| ApiError::NotFound("KYC record not found".to_string()))?;

    Ok(Json(KycStatusResponse {
        status: response.status,
        tier: response.tier,
        effective_tier: kyc_record.effective_tier,
        session_id: Some(response.session_id),
        expires_at: Some(response.expires_at),
        completed_steps: response.completed_steps,
        pending_steps: response.pending_steps,
        decision_reason: kyc_record.decision_reason,
        resubmission_allowed_at: kyc_record.resubmission_allowed_at,
        enhanced_due_diligence_active: kyc_record.enhanced_due_diligence_active,
    }))
}

async fn get_transaction_limits(
    State(kyc_service): State<KycService>,
    auth: AuthenticatedConsumer,
) -> Result<Json<TransactionLimitsResponse>, ApiError> {
    let remaining_limits = kyc_service
        .get_transaction_limits(auth.consumer_id)
        .await
        .map_err(|e| match e {
            KycServiceError::KycRecordNotFound => ApiError::NotFound("KYC record not found".to_string()),
            _ => ApiError::InternalServerError("Failed to get transaction limits".to_string()),
        })?;

    // Get current KYC record for tier info
    let kyc_record = kyc_service.repository
        .get_kyc_record_by_consumer(auth.consumer_id)
        .await
        .map_err(|e| ApiError::InternalServerError(format!("Database error: {}", e)))?
        .ok_or_else(|| ApiError::NotFound("KYC record not found".to_string()))?;

    // Get tier definition for limits
    let tier_def = crate::kyc::tier_requirements::KycTierRequirements::get_tier_definition(kyc_record.effective_tier);

    Ok(Json(TransactionLimitsResponse {
        tier: kyc_record.tier,
        effective_tier: kyc_record.effective_tier,
        max_transaction_amount: tier_def.max_transaction_amount,
        daily_volume_limit: tier_def.daily_volume_limit,
        monthly_volume_limit: tier_def.monthly_volume_limit,
        daily_volume_used: &tier_def.daily_volume_limit - &remaining_limits.daily_volume,
        monthly_volume_used: &tier_def.monthly_volume_limit - &remaining_limits.monthly_volume,
        daily_remaining: remaining_limits.daily_volume,
        monthly_remaining: remaining_limits.monthly_volume,
        single_transaction_remaining: remaining_limits.single_transaction,
    }))
}

async fn handle_webhook(
    State(kyc_service): State<KycService>,
    Json(payload): Json<WebhookPayload>,
) -> Result<StatusCode, ApiError> {
    // Convert webhook payload to internal format
    let decision = payload.decision.map(|d| crate::kyc::provider::KycDecision {
        decision: d.decision,
        reason: d.reason,
        tier: d.tier,
        reviewer_notes: d.reviewer_notes,
        provider_reference: d.provider_reference,
    });

    let internal_payload = crate::kyc::provider::ProviderWebhookPayload {
        provider: payload.provider,
        event_type: payload.event_type,
        session_id: payload.session_id,
        consumer_id: payload.consumer_id,
        status: payload.status,
        decision,
        risk_score: payload.risk_score,
        risk_flags: payload.risk_flags,
        timestamp: payload.timestamp,
        signature: payload.signature,
    };

    kyc_service
        .handle_webhook(internal_payload)
        .await
        .map_err(|e| match e {
            KycServiceError::WebhookSignatureInvalid => ApiError::Unauthorized("Invalid webhook signature".to_string()),
            KycServiceError::KycRecordNotFound => ApiError::NotFound("KYC record not found".to_string()),
            KycServiceError::ProviderError(e) => ApiError::BadRequest(format!("Provider error: {}", e)),
            _ => ApiError::InternalServerError("Failed to process webhook".to_string()),
        })?;

    Ok(StatusCode::OK)
}

// Helper functions for error handling
impl From<KycServiceError> for ApiError {
    fn from(error: KycServiceError) -> Self {
        match error {
            KycServiceError::SessionAlreadyActive => ApiError::Conflict(error.to_string()),
            KycServiceError::SessionNotFound | KycServiceError::KycRecordNotFound => {
                ApiError::NotFound(error.to_string())
            }
            KycServiceError::SessionExpired => ApiError::BadRequest(error.to_string()),
            KycServiceError::ProviderNotFound(_) => ApiError::InternalServerError(error.to_string()),
            KycServiceError::ConfigurationError(_) => ApiError::InternalServerError(error.to_string()),
            KycServiceError::InvalidDecision(_) => ApiError::BadRequest(error.to_string()),
            KycServiceError::WebhookSignatureInvalid => ApiError::Unauthorized(error.to_string()),
            KycServiceError::ProviderError(e) => {
                match e {
                    crate::kyc::provider::KycProviderError::InvalidRequest(_) => {
                        ApiError::BadRequest(error.to_string())
                    }
                    crate::kyc::provider::KycProviderError::AuthenticationError(_) => {
                        ApiError::Unauthorized(error.to_string())
                    }
                    crate::kyc::provider::KycProviderError::RateLimitExceeded => {
                        ApiError::TooManyRequests(error.to_string())
                    }
                    _ => ApiError::InternalServerError(error.to_string()),
                }
            }
            KycServiceError::DatabaseError(_) | KycServiceError::RedisError(_) => {
                ApiError::InternalServerError(error.to_string())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum_test::TestServer;
    use serde_json::json;

    #[tokio::test]
    async fn test_initiate_kyc_session() {
        // This would require setting up a test KYC service
        // Implementation would depend on your test setup
    }
}
