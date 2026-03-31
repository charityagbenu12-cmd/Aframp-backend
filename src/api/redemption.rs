use crate::database::models::redemption::{
    BatchRedemptionRequest, BatchRedemptionResponse, CreateRedemptionRequest,
    DisbursementReceipt, RedemptionConfig, RedemptionError, RedemptionRequestResponse,
    RedemptionStatusResponse, SettlementHealthResponse,
};
use crate::services::batch_processor::{BatchProcessor, BatchProcessingResult};
use crate::services::burn_service::BurnService;
use crate::services::disbursement_service::DisbursementService;
use crate::services::redemption_service::{
    RequestContext, RedemptionAuthorizationService, RedemptionRequestService,
};
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{error, info, instrument, warn};
use utoipa::path;
use utoipa::{OpenApi, ToSchema};
use utoipa_swagger_ui::SwaggerUi;

#[derive(Debug, Clone, ToSchema)]
pub struct RedemptionApiState {
    pub redemption_request_service: Arc<dyn RedemptionRequestService>,
    pub authorization_service: Arc<dyn RedemptionAuthorizationService>,
    pub burn_service: Arc<dyn BurnService>,
    pub disbursement_service: Arc<dyn DisbursementService>,
    pub batch_processor: Arc<dyn BatchProcessor>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SubmitRedemptionRequest {
    pub amount_cngn: f64,
    pub bank_code: String,
    pub bank_name: String,
    pub account_number: String,
    pub account_name: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct BatchRedemptionQuery {
    pub redemption_ids: Vec<String>,
    pub batch_type: String, // "TIME_BASED" | "COUNT_BASED" | "MANUAL"
    pub trigger_reason: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct RedemptionHistoryQuery {
    pub limit: Option<i32>,
    pub offset: Option<i32>,
    pub status: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct DisbursementReceiptQuery {
    pub format: Option<String>, // "json" | "pdf"
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub data: Option<T>,
    pub error: Option<String>,
    pub message: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl<T> ApiResponse<T> {
    pub fn success(data: T, message: &str) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
            message: message.to_string(),
            timestamp: chrono::Utc::now(),
        }
    }

    pub fn error(message: &str) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(message.to_string()),
            message: message.to_string(),
            timestamp: chrono::Utc::now(),
        }
    }
}

#[utoipa::path(
    post,
    path = "/redemption/request",
    tag = "redemption",
    summary = "Submit a redemption request",
    description = "Submit a new cNGN redemption request to burn tokens and receive NGN",
    request_body = SubmitRedemptionRequest,
    responses(
        (status = 200, description = "Redemption request submitted successfully", body = ApiResponse<RedemptionRequestResponse>),
        (status = 400, description = "Invalid request", body = ApiResponse<()>),
        (status = 401, description = "Unauthorized", body = ApiResponse<()>),
        (status = 429, description = "Rate limit exceeded", body = ApiResponse<()>),
        (status = 500, description = "Internal server error", body = ApiResponse<()>)
    ),
    security(
        ("bearer_auth" = [])
    )
)]
#[instrument(skip(state), fields(user_id = "extract_from_jwt"))]
pub async fn submit_redemption_request(
    State(state): State<Arc<RedemptionApiState>>,
    Json(request): Json<SubmitRedemptionRequest>,
) -> Result<Json<ApiResponse<RedemptionRequestResponse>>, StatusCode> {
    // Extract user_id from JWT (simplified for this example)
    let user_id = "mock-user-123"; // In production, extract from authentication middleware

    let context = RequestContext {
        ip_address: Some("127.0.0.1".to_string()), // Extract from request
        user_agent: Some("Mozilla/5.0".to_string()), // Extract from request
        request_id: format!("req-{}", uuid::Uuid::new_v4()),
        timestamp: chrono::Utc::now(),
    };

    let create_request = CreateRedemptionRequest {
        amount_cngn: request.amount_cngn,
        bank_code: request.bank_code,
        bank_name: request.bank_name,
        account_number: request.account_number,
        account_name: request.account_name,
    };

    match state
        .redemption_request_service
        .submit_redemption_request(user_id, create_request, context)
        .await
    {
        Ok(response) => {
            info!(
                redemption_id = %response.redemption_id,
                user_id = %user_id,
                "Redemption request submitted successfully"
            );
            Ok(Json(ApiResponse::success(response, "Redemption request submitted successfully")))
        }
        Err(e) => {
            error!(
                user_id = %user_id,
                error = %e,
                "Failed to submit redemption request"
            );
            let status_code = match e {
                RedemptionError::ValidationError(_) => StatusCode::BAD_REQUEST,
                RedemptionError::RateLimitExceeded => StatusCode::TOO_MANY_REQUESTS,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };
            Err(status_code)
        }
    }
}

#[utoipa::path(
    get,
    path = "/redemption/status/{redemption_id}",
    tag = "redemption",
    summary = "Get redemption status",
    description = "Get the current status of a redemption request",
    params(
        ("redemption_id" = String, Path, description = "Redemption ID")
    ),
    responses(
        (status = 200, description = "Redemption status retrieved", body = ApiResponse<RedemptionStatusResponse>),
        (status = 404, description = "Redemption not found", body = ApiResponse<()>),
        (status = 401, description = "Unauthorized", body = ApiResponse<()>),
        (status = 500, description = "Internal server error", body = ApiResponse<()>)
    ),
    security(
        ("bearer_auth" = [])
    )
)]
#[instrument(skip(state), fields(redemption_id = %redemption_id, user_id = "extract_from_jwt"))]
pub async fn get_redemption_status(
    State(state): State<Arc<RedemptionApiState>>,
    Path(redemption_id): Path<String>,
) -> Result<Json<ApiResponse<RedemptionStatusResponse>>, StatusCode> {
    let user_id = "mock-user-123"; // Extract from JWT

    match state
        .redemption_request_service
        .get_redemption_status(&redemption_id, user_id)
        .await
    {
        Ok(response) => Ok(Json(ApiResponse::success(response, "Redemption status retrieved"))),
        Err(e) => {
            warn!(
                redemption_id = %redemption_id,
                user_id = %user_id,
                error = %e,
                "Failed to get redemption status"
            );
            let status_code = match e {
                RedemptionError::ValidationError(_) => StatusCode::NOT_FOUND,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };
            Err(status_code)
        }
    }
}

#[utoipa::path(
    post,
    path = "/redemption/cancel/{redemption_id}",
    tag = "redemption",
    summary = "Cancel redemption request",
    description = "Cancel a pending redemption request",
    params(
        ("redemption_id" = String, Path, description = "Redemption ID")
    ),
    responses(
        (status = 200, description = "Redemption cancelled", body = ApiResponse<bool>),
        (status = 400, description = "Cannot cancel redemption", body = ApiResponse<()>),
        (status = 404, description = "Redemption not found", body = ApiResponse<()>),
        (status = 401, description = "Unauthorized", body = ApiResponse<()>),
        (status = 500, description = "Internal server error", body = ApiResponse<()>)
    ),
    security(
        ("bearer_auth" = [])
    )
)]
#[instrument(skip(state), fields(redemption_id = %redemption_id, user_id = "extract_from_jwt"))]
pub async fn cancel_redemption_request(
    State(state): State<Arc<RedemptionApiState>>,
    Path(redemption_id): Path<String>,
) -> Result<Json<ApiResponse<bool>>, StatusCode> {
    let user_id = "mock-user-123"; // Extract from JWT

    match state
        .redemption_request_service
        .cancel_redemption_request(&redemption_id, user_id)
        .await
    {
        Ok(cancelled) => {
            if cancelled {
                info!(
                    redemption_id = %redemption_id,
                    user_id = %user_id,
                    "Redemption request cancelled successfully"
                );
                Ok(Json(ApiResponse::success(true, "Redemption cancelled successfully")))
            } else {
                Ok(Json(ApiResponse::success(false, "Redemption could not be cancelled")))
            }
        }
        Err(e) => {
            warn!(
                redemption_id = %redemption_id,
                user_id = %user_id,
                error = %e,
                "Failed to cancel redemption request"
            );
            let status_code = match e {
                RedemptionError::ValidationError(_) => StatusCode::BAD_REQUEST,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };
            Err(status_code)
        }
    }
}

#[utoipa::path(
    get,
    path = "/redemption/history",
    tag = "redemption",
    summary = "Get user redemption history",
    description = "Get the redemption history for the authenticated user",
    params(
        ("limit" = Option<i32>, Query, description = "Maximum number of records to return"),
        ("offset" = Option<i32>, Query, description = "Number of records to skip"),
        ("status" = Option<String>, Query, description = "Filter by status")
    ),
    responses(
        (status = 200, description = "Redemption history retrieved", body = ApiResponse<Vec<RedemptionStatusResponse>>),
        (status = 401, description = "Unauthorized", body = ApiResponse<()>),
        (status = 500, description = "Internal server error", body = ApiResponse<()>)
    ),
    security(
        ("bearer_auth" = [])
    )
)]
#[instrument(skip(state), fields(user_id = "extract_from_jwt"))]
pub async fn get_redemption_history(
    State(state): State<Arc<RedemptionApiState>>,
    Query(query): Query<RedemptionHistoryQuery>,
) -> Result<Json<ApiResponse<Vec<RedemptionStatusResponse>>>, StatusCode> {
    let user_id = "mock-user-123"; // Extract from JWT

    match state
        .redemption_request_service
        .get_user_redemption_history(user_id, query.limit)
        .await
    {
        Ok(history) => Ok(Json(ApiResponse::success(history, "Redemption history retrieved"))),
        Err(e) => {
            error!(
                user_id = %user_id,
                error = %e,
                "Failed to get redemption history"
            );
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

#[utoipa::path(
    post,
    path = "/redemption/batch",
    tag = "redemption",
    summary = "Create batch redemption",
    description = "Create a batch redemption for multiple requests",
    request_body = BatchRedemptionQuery,
    responses(
        (status = 200, description = "Batch created", body = ApiResponse<BatchRedemptionResponse>),
        (status = 400, description = "Invalid request", body = ApiResponse<()>),
        (status = 401, description = "Unauthorized", body = ApiResponse<()>),
        (status = 500, description = "Internal server error", body = ApiResponse<()>)
    ),
    security(
        ("bearer_auth" = [])
    )
)]
#[instrument(skip(state))]
pub async fn create_batch_redemption(
    State(state): State<Arc<RedemptionApiState>>,
    Json(query): Json<BatchRedemptionQuery>,
) -> Result<Json<ApiResponse<BatchRedemptionResponse>>, StatusCode> {
    match query.batch_type.as_str() {
        "MANUAL" => {
            let trigger_reason = query.trigger_reason.unwrap_or_else(|| "Manual batch creation".to_string());
            
            match state
                .batch_processor
                .create_manual_batch(query.redemption_ids, trigger_reason)
                .await
            {
                Ok(batch_id) => {
                    info!(batch_id = %batch_id, "Manual batch created successfully");
                    let response = BatchRedemptionResponse {
                        batch_id,
                        total_requests: query.redemption_ids.len(),
                        total_amount_cngn: 0.0, // Would be calculated from actual requests
                        total_amount_ngn: 0.0,
                        status: "PENDING".to_string(),
                        created_at: chrono::Utc::now(),
                        estimated_completion_time: Some(chrono::Utc::now() + chrono::Duration::minutes(30)),
                    };
                    Ok(Json(ApiResponse::success(response, "Batch created successfully")))
                }
                Err(e) => {
                    error!(error = %e, "Failed to create manual batch");
                    Err(StatusCode::BAD_REQUEST)
                }
            }
        }
        "TIME_BASED" => {
            match state.batch_processor.create_time_based_batch().await {
                Ok(Some(batch_id)) => {
                    info!(batch_id = %batch_id, "Time-based batch created successfully");
                    let response = BatchRedemptionResponse {
                        batch_id,
                        total_requests: 0, // Would be calculated from actual requests
                        total_amount_cngn: 0.0,
                        total_amount_ngn: 0.0,
                        status: "PENDING".to_string(),
                        created_at: chrono::Utc::now(),
                        estimated_completion_time: Some(chrono::Utc::now() + chrono::Duration::minutes(30)),
                    };
                    Ok(Json(ApiResponse::success(response, "Time-based batch created")))
                }
                Ok(None) => {
                    Ok(Json(ApiResponse::error("No eligible requests for time-based batch")))
                }
                Err(e) => {
                    error!(error = %e, "Failed to create time-based batch");
                    Err(StatusCode::INTERNAL_SERVER_ERROR)
                }
            }
        }
        "COUNT_BASED" => {
            match state.batch_processor.create_count_based_batch().await {
                Ok(Some(batch_id)) => {
                    info!(batch_id = %batch_id, "Count-based batch created successfully");
                    let response = BatchRedemptionResponse {
                        batch_id,
                        total_requests: 0, // Would be calculated from actual requests
                        total_amount_cngn: 0.0,
                        total_amount_ngn: 0.0,
                        status: "PENDING".to_string(),
                        created_at: chrono::Utc::now(),
                        estimated_completion_time: Some(chrono::Utc::now() + chrono::Duration::minutes(30)),
                    };
                    Ok(Json(ApiResponse::success(response, "Count-based batch created")))
                }
                Ok(None) => {
                    Ok(Json(ApiResponse::error("No eligible requests for count-based batch")))
                }
                Err(e) => {
                    error!(error = %e, "Failed to create count-based batch");
                    Err(StatusCode::INTERNAL_SERVER_ERROR)
                }
            }
        }
        _ => {
            warn!(batch_type = %query.batch_type, "Invalid batch type");
            Err(StatusCode::BAD_REQUEST)
        }
    }
}

#[utoipa::path(
    post,
    path = "/redemption/batch/{batch_id}/process",
    tag = "redemption",
    summary = "Process batch redemption",
    description = "Process a pending batch redemption",
    params(
        ("batch_id" = String, Path, description = "Batch ID")
    ),
    responses(
        (status = 200, description = "Batch processed", body = ApiResponse<BatchProcessingResult>),
        (status = 404, description = "Batch not found", body = ApiResponse<()>),
        (status = 400, description = "Batch cannot be processed", body = ApiResponse<()>),
        (status = 401, description = "Unauthorized", body = ApiResponse<()>),
        (status = 500, description = "Internal server error", body = ApiResponse<()>)
    ),
    security(
        ("bearer_auth" = [])
    )
)]
#[instrument(skip(state), fields(batch_id = %batch_id))]
pub async fn process_batch_redemption(
    State(state): State<Arc<RedemptionApiState>>,
    Path(batch_id): Path<String>,
) -> Result<Json<ApiResponse<BatchProcessingResult>>, StatusCode> {
    match state.batch_processor.process_batch(&batch_id).await {
        Ok(result) => {
            info!(
                batch_id = %batch_id,
                successful = %result.successful_requests,
                failed = %result.failed_requests,
                "Batch processed successfully"
            );
            Ok(Json(ApiResponse::success(result, "Batch processed successfully")))
        }
        Err(e) => {
            error!(
                batch_id = %batch_id,
                error = %e,
                "Failed to process batch"
            );
            Err(StatusCode::BAD_REQUEST)
        }
    }
}

#[utoipa::path(
    get,
    path = "/redemption/receipt/{redemption_id}",
    tag = "redemption",
    summary = "Get redemption receipt",
    description = "Get the receipt for a completed redemption",
    params(
        ("redemption_id" = String, Path, description = "Redemption ID"),
        ("format" = Option<String>, Query, description = "Receipt format (json|pdf)")
    ),
    responses(
        (status = 200, description = "Receipt retrieved", body = ApiResponse<DisbursementReceipt>),
        (status = 404, description = "Redemption not found or not completed", body = ApiResponse<()>),
        (status = 401, description = "Unauthorized", body = ApiResponse<()>),
        (status = 500, description = "Internal server error", body = ApiResponse<()>)
    ),
    security(
        ("bearer_auth" = [])
    )
)]
#[instrument(skip(state), fields(redemption_id = %redemption_id, user_id = "extract_from_jwt"))]
pub async fn get_redemption_receipt(
    State(state): State<Arc<RedemptionApiState>>,
    Path(redemption_id): Path<String>,
    Query(query): Query<DisbursementReceiptQuery>,
) -> Result<Json<ApiResponse<DisbursementReceipt>>, StatusCode> {
    let user_id = "mock-user-123"; // Extract from JWT

    // First check if redemption exists and belongs to user
    match state
        .redemption_request_service
        .get_redemption_status(&redemption_id, user_id)
        .await
    {
        Ok(_) => {
            // Generate receipt
            match state.disbursement_service.generate_receipt(&redemption_id).await {
                Ok(receipt_data) => {
                    // Parse receipt data and convert to DisbursementReceipt format
                    // This is simplified - in production, parse the actual receipt data
                    let receipt = DisbursementReceipt {
                        redemption_id: redemption_id.clone(),
                        provider_reference: "PROV-12345".to_string(), // Extract from receipt
                        amount_ngn: 75000.0, // Extract from receipt
                        bank_details: crate::database::models::redemption::BankDetails {
                            bank_code: "057".to_string(),
                            bank_name: "Zenith Bank".to_string(),
                            account_number: "1234567890".to_string(),
                            account_name: "John Doe".to_string(),
                            account_name_verified: true,
                        },
                        status: "COMPLETED".to_string(),
                        completed_at: chrono::Utc::now(),
                        receipt_url: Some(format!("https://api.aframp.com/receipts/{}", redemption_id)),
                        pdf_base64: if query.format.as_deref() == Some("pdf") {
                            Some("base64-encoded-pdf-data".to_string()) // In production, generate actual PDF
                        } else {
                            None
                        },
                    };

                    info!(
                        redemption_id = %redemption_id,
                        user_id = %user_id,
                        "Redemption receipt generated successfully"
                    );

                    Ok(Json(ApiResponse::success(receipt, "Receipt retrieved successfully")))
                }
                Err(e) => {
                    error!(
                        redemption_id = %redemption_id,
                        error = %e,
                        "Failed to generate receipt"
                    );
                    Err(StatusCode::INTERNAL_SERVER_ERROR)
                }
            }
        }
        Err(e) => {
            warn!(
                redemption_id = %redemption_id,
                user_id = %user_id,
                error = %e,
                "Failed to get redemption status for receipt"
            );
            Err(StatusCode::NOT_FOUND)
        }
    }
}

#[utoipa::path(
    get,
    path = "/redemption/settlement/health",
    tag = "redemption",
    summary = "Get settlement account health",
    description = "Get the health status of settlement accounts",
    responses(
        (status = 200, description = "Settlement health retrieved", body = ApiResponse<SettlementHealthResponse>),
        (status = 401, description = "Unauthorized", body = ApiResponse<()>),
        (status = 500, description = "Internal server error", body = ApiResponse<()>)
    ),
    security(
        ("bearer_auth" = [])
    )
)]
#[instrument(skip(state))]
pub async fn get_settlement_health(
    State(_state): State<Arc<RedemptionApiState>>,
) -> Result<Json<ApiResponse<SettlementHealthResponse>>, StatusCode> {
    // This would query the settlement accounts from the repository
    // For now, return mock data
    let health_response = SettlementHealthResponse {
        accounts: vec![
            crate::database::models::redemption::SettlementAccountHealth {
                account_name: "Primary Reserve Account".to_string(),
                account_type: "RESERVE".to_string(),
                current_balance: 100_000_000.0,
                available_balance: 95_000_000.0,
                pending_debits: 5_000_000.0,
                is_healthy: true,
                last_balance_check: Some(chrono::Utc::now()),
            },
        ],
        overall_health: true,
        total_available_balance: 95_000_000.0,
        total_pending_debits: 5_000_000.0,
        last_updated: chrono::Utc::now(),
    };

    Ok(Json(ApiResponse::success(health_response, "Settlement health retrieved")))
}

pub fn create_redemption_router(state: Arc<RedemptionApiState>) -> Router {
    Router::new()
        .route("/request", post(submit_redemption_request))
        .route("/status/:redemption_id", get(get_redemption_status))
        .route("/cancel/:redemption_id", post(cancel_redemption_request))
        .route("/history", get(get_redemption_history))
        .route("/batch", post(create_batch_redemption))
        .route("/batch/:batch_id/process", post(process_batch_redemption))
        .route("/receipt/:redemption_id", get(get_redemption_receipt))
        .route("/settlement/health", get(get_settlement_health))
        .with_state(state)
}

#[derive(OpenApi)]
#[openapi(
    paths(
        submit_redemption_request,
        get_redemption_status,
        cancel_redemption_request,
        get_redemption_history,
        create_batch_redemption,
        process_batch_redemption,
        get_redemption_receipt,
        get_settlement_health,
    ),
    components(
        schemas(
            SubmitRedemptionRequest,
            RedemptionRequestResponse,
            RedemptionStatusResponse,
            BatchRedemptionQuery,
            BatchRedemptionResponse,
            DisbursementReceipt,
            SettlementHealthResponse,
            ApiResponse<RedemptionRequestResponse>,
            ApiResponse<RedemptionStatusResponse>,
            ApiResponse<Vec<RedemptionStatusResponse>>,
            ApiResponse<BatchRedemptionResponse>,
            ApiResponse<DisbursementReceipt>,
            ApiResponse<SettlementHealthResponse>,
            ApiResponse<bool>,
            ApiResponse<BatchProcessingResult>,
        )
    ),
    tags(
        (name = "redemption", description = "cNGN redemption management API")
    ),
    info(
        title = "cNGN Redemption API",
        description = "API for managing cNGN token redemptions and fiat disbursements",
        version = "1.0.0",
        contact(
            name = "Aframp Support",
            email = "support@aframp.com"
        )
    )
)]
pub struct RedemptionApiDoc;

pub fn create_redemption_api_with_docs(state: Arc<RedemptionApiState>) -> Router {
    let redemption_router = create_redemption_router(state);
    
    redemption_router.merge(
        SwaggerUi::new("/redemption/docs")
            .url("/api/redemption/docs/openapi.json", RedemptionApiDoc::openapi()),
    )
}
