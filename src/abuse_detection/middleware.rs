//! Middleware for abuse detection integration

use super::detector::AbuseDetector;
use super::repository::AbuseDetectionRepository;
use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::sync::Arc;
use tracing::{info, warn};

#[derive(Clone)]
pub struct AbuseDetectionState {
    pub detector: Arc<AbuseDetector>,
    pub repo: Arc<AbuseDetectionRepository>,
}

/// Middleware to check if consumer has active abuse response actions
pub async fn abuse_check_middleware(
    State(state): State<AbuseDetectionState>,
    req: Request,
    next: Next,
) -> Response {
    // Extract consumer_id from request extensions (set by auth middleware)
    let consumer_id = req
        .extensions()
        .get::<crate::middleware::api_key::AuthenticatedKey>()
        .map(|auth| auth.consumer_id);

    if let Some(consumer_id) = consumer_id {
        // Check for active response actions
        match state.repo.get_active_responses(consumer_id).await {
            Ok(responses) => {
                for response in responses {
                    match response.tier {
                        super::response::ResponseTier::Monitor => {
                            // Log but allow
                            info!(
                                consumer_id = %consumer_id,
                                case_id = %response.evidence_case_id,
                                "Consumer under monitoring for abuse"
                            );
                        }
                        super::response::ResponseTier::Soft => {
                            // Rate limit is already tightened, allow but log
                            info!(
                                consumer_id = %consumer_id,
                                case_id = %response.evidence_case_id,
                                "Consumer under soft response (rate limit tightened)"
                            );
                        }
                        super::response::ResponseTier::Hard | super::response::ResponseTier::Critical => {
                            // Block the request
                            warn!(
                                consumer_id = %consumer_id,
                                case_id = %response.evidence_case_id,
                                tier = ?response.tier,
                                "Blocking request due to active abuse response"
                            );

                            return (
                                StatusCode::FORBIDDEN,
                                axum::Json(serde_json::json!({
                                    "error": {
                                        "code": "ACCOUNT_SUSPENDED",
                                        "message": "Your account has been suspended due to abuse detection",
                                        "reason": response.reason,
                                        "case_id": response.evidence_case_id,
                                        "appeal_url": format!("/api/admin/abuse/cases/{}/appeal", response.evidence_case_id)
                                    }
                                })),
                            )
                                .into_response();
                        }
                    }
                }
            }
            Err(e) => {
                warn!(error = %e, "Failed to check abuse responses");
                // Fail open - allow request but log error
            }
        }
    }

    next.run(req).await
}
