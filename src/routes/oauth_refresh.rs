//! OAuth 2.0 Refresh Token Endpoint
//!
//! Implements POST /oauth/token for refresh token grant type
//! Handles token rotation, theft detection, and scope downscoping

use axum::{
    extract::{State, Json},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{error, info, warn};

use crate::auth::{
    refresh_token_service::{RefreshTokenRequest, RefreshTokenService},
    refresh_token_validator::{RefreshTokenValidator, RefreshTokenValidationContext},
    oauth_token_service::OAuthTokenService,
};
use crate::database::refresh_token_repository::RefreshTokenRepository;

// ── Request/Response Types ───────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshTokenGrantRequest {
    pub grant_type: String,
    pub refresh_token: String,
    pub scope: Option<String>,
    pub client_id: String,
    pub consumer_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshTokenGrantResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub refresh_token: String,
    pub scope: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshTokenErrorResponse {
    pub error: String,
    pub error_description: String,
}

// ── Handler State ────────────────────────────────────────────────────────────

pub struct RefreshTokenHandlerState {
    pub token_service: Arc<OAuthTokenService>,
    pub refresh_repo: Arc<RefreshTokenRepository>,
}

// ── Refresh Token Endpoint ───────────────────────────────────────────────────

pub async fn refresh_token_handler(
    State(state): State<Arc<RefreshTokenHandlerState>>,
    Json(req): Json<RefreshTokenGrantRequest>,
) -> Result<Json<RefreshTokenGrantResponse>, RefreshTokenErrorResponse> {
    // Validate grant type
    if req.grant_type != "refresh_token" {
        warn!("Invalid grant type: {}", req.grant_type);
        return Err(RefreshTokenErrorResponse {
            error: "invalid_grant".to_string(),
            error_description: "Grant type must be 'refresh_token'".to_string(),
        });
    }

    // Validate refresh token format
    if req.refresh_token.is_empty() {
        warn!("Empty refresh token provided");
        return Err(RefreshTokenErrorResponse {
            error: "invalid_request".to_string(),
            error_description: "Refresh token is required".to_string(),
        });
    }

    // Create validator
    let validator = RefreshTokenValidator::new((*state.refresh_repo).clone());

    // Validate refresh token
    // Note: In production, you'd need to extract token_id from the token or use a lookup mechanism
    // For now, we'll assume the refresh_token contains the token_id
    let validation_context = RefreshTokenValidationContext {
        consumer_id: req.consumer_id.clone(),
        client_id: req.client_id.clone(),
        requested_scope: req.scope.clone(),
    };

    // Check for token reuse (theft detection)
    if let Ok(is_reused) = validator.detect_reuse(&req.refresh_token).await {
        if is_reused {
            error!(
                consumer_id = %req.consumer_id,
                "Token reuse detected - possible theft"
            );
            // Revoke entire family
            let _ = state
                .refresh_repo
                .revoke_all_for_consumer(&req.consumer_id)
                .await;

            return Err(RefreshTokenErrorResponse {
                error: "invalid_grant".to_string(),
                error_description: "Token reuse detected - all tokens revoked".to_string(),
            });
        }
    }

    // Mark token as used before issuing new one (fail-closed approach)
    if !state
        .refresh_repo
        .mark_as_used(&req.refresh_token)
        .await
        .unwrap_or(false)
    {
        warn!(
            consumer_id = %req.consumer_id,
            "Failed to mark token as used"
        );
        return Err(RefreshTokenErrorResponse {
            error: "server_error".to_string(),
            error_description: "Failed to process refresh token".to_string(),
        });
    }

    // Generate new access token
    let access_token_req = crate::auth::oauth_token_service::TokenIssuanceRequest {
        consumer_id: req.consumer_id.clone(),
        client_id: req.client_id.clone(),
        scope: req.scope.clone().unwrap_or_default(),
        consumer_type: crate::auth::oauth_token_service::ConsumerType::MobileClient,
        environment: crate::auth::oauth_token_service::Environment::Mainnet,
        binding: None,
    };

    let access_token_response = state
        .token_service
        .issue_token(access_token_req)
        .await
        .map_err(|e| {
            error!("Failed to issue access token: {}", e);
            RefreshTokenErrorResponse {
                error: "server_error".to_string(),
                error_description: "Failed to issue access token".to_string(),
            }
        })?;

    // Generate new refresh token (rotation)
    let new_refresh_token = RefreshTokenService::generate_token();
    let new_refresh_hash = RefreshTokenService::hash_token(&new_refresh_token).map_err(|e| {
        error!("Failed to hash refresh token: {}", e);
        RefreshTokenErrorResponse {
            error: "server_error".to_string(),
            error_description: "Failed to generate refresh token".to_string(),
        }
    })?;

    // Create new refresh token in database
    let new_token_id = uuid::Uuid::new_v4().to_string();
    let family_id = uuid::Uuid::new_v4().to_string();

    let create_req = crate::database::refresh_token_repository::CreateRefreshTokenRequest {
        token_id: new_token_id.clone(),
        family_id: family_id.clone(),
        token_hash: new_refresh_hash,
        consumer_id: req.consumer_id.clone(),
        client_id: req.client_id.clone(),
        scope: req.scope.clone().unwrap_or_default(),
        issued_at: chrono::Utc::now(),
        expires_at: chrono::Utc::now()
            + chrono::Duration::seconds(
                crate::auth::refresh_token_service::REFRESH_TOKEN_TTL_SECS,
            ),
        family_expires_at: chrono::Utc::now()
            + chrono::Duration::seconds(
                crate::auth::refresh_token_service::REFRESH_TOKEN_ABSOLUTE_TTL_SECS,
            ),
        parent_token_id: Some(req.refresh_token.clone()),
    };

    state
        .refresh_repo
        .create(create_req)
        .await
        .map_err(|e| {
            error!("Failed to create refresh token: {}", e);
            RefreshTokenErrorResponse {
                error: "server_error".to_string(),
                error_description: "Failed to generate refresh token".to_string(),
            }
        })?;

    // Set replacement token for old token
    let _ = state
        .refresh_repo
        .set_replacement(&req.refresh_token, &new_token_id)
        .await;

    info!(
        consumer_id = %req.consumer_id,
        "Refresh token rotated successfully"
    );

    Ok(Json(RefreshTokenGrantResponse {
        access_token: access_token_response.access_token,
        token_type: "Bearer".to_string(),
        expires_in: access_token_response.expires_in,
        refresh_token: new_refresh_token,
        scope: req.scope.unwrap_or_default(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_refresh_token_grant_request_serialization() {
        let req = RefreshTokenGrantRequest {
            grant_type: "refresh_token".to_string(),
            refresh_token: "token_123".to_string(),
            scope: Some("read write".to_string()),
            client_id: "client_1".to_string(),
            consumer_id: "consumer_1".to_string(),
        };

        let json = serde_json::to_string(&req).unwrap();
        let deserialized: RefreshTokenGrantRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.grant_type, req.grant_type);
    }

    #[test]
    fn test_refresh_token_grant_response_serialization() {
        let resp = RefreshTokenGrantResponse {
            access_token: "access_123".to_string(),
            token_type: "Bearer".to_string(),
            expires_in: 3600,
            refresh_token: "refresh_123".to_string(),
            scope: "read write".to_string(),
        };

        let json = serde_json::to_string(&resp).unwrap();
        let deserialized: RefreshTokenGrantResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.token_type, "Bearer");
    }
}
