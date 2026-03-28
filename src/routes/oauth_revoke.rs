//! OAuth 2.0 Token Revocation Endpoint
//!
//! Implements POST /oauth/token/revoke for revoking tokens
//! Supports both access tokens and refresh tokens

use axum::{
    extract::{State, Json},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{error, info, warn};

use crate::database::refresh_token_repository::RefreshTokenRepository;

// ── Request/Response Types ───────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenRevocationRequest {
    pub token: String,
    pub token_type_hint: Option<String>, // "access_token" or "refresh_token"
    pub client_id: String,
    pub consumer_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenRevocationResponse {
    pub success: bool,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenRevocationErrorResponse {
    pub error: String,
    pub error_description: String,
}

// ── Handler State ────────────────────────────────────────────────────────────

pub struct TokenRevocationHandlerState {
    pub refresh_repo: Arc<RefreshTokenRepository>,
}

// ── Token Revocation Endpoint ────────────────────────────────────────────────

pub async fn revoke_token_handler(
    State(state): State<Arc<TokenRevocationHandlerState>>,
    Json(req): Json<TokenRevocationRequest>,
) -> Result<(StatusCode, Json<TokenRevocationResponse>), TokenRevocationErrorResponse> {
    // Validate token
    if req.token.is_empty() {
        warn!("Empty token provided for revocation");
        return Err(TokenRevocationErrorResponse {
            error: "invalid_request".to_string(),
            error_description: "Token is required".to_string(),
        });
    }

    // Determine token type
    let token_type_hint = req.token_type_hint.as_deref().unwrap_or("refresh_token");

    match token_type_hint {
        "refresh_token" => {
            // Revoke refresh token
            match state.refresh_repo.revoke(&req.token).await {
                Ok(true) => {
                    info!(
                        consumer_id = %req.consumer_id,
                        "Refresh token revoked successfully"
                    );
                    Ok((
                        StatusCode::OK,
                        Json(TokenRevocationResponse {
                            success: true,
                            message: "Token revoked successfully".to_string(),
                        }),
                    ))
                }
                Ok(false) => {
                    warn!(
                        consumer_id = %req.consumer_id,
                        "Token not found or already revoked"
                    );
                    // RFC 7009: Return 200 even if token not found
                    Ok((
                        StatusCode::OK,
                        Json(TokenRevocationResponse {
                            success: true,
                            message: "Token revocation processed".to_string(),
                        }),
                    ))
                }
                Err(e) => {
                    error!("Failed to revoke refresh token: {}", e);
                    Err(TokenRevocationErrorResponse {
                        error: "server_error".to_string(),
                        error_description: "Failed to revoke token".to_string(),
                    })
                }
            }
        }
        "access_token" => {
            // Access tokens are stateless, but we can log the revocation intent
            info!(
                consumer_id = %req.consumer_id,
                "Access token revocation requested (stateless token)"
            );
            Ok((
                StatusCode::OK,
                Json(TokenRevocationResponse {
                    success: true,
                    message: "Access token revocation processed".to_string(),
                }),
            ))
        }
        _ => {
            warn!("Unknown token type hint: {}", token_type_hint);
            Err(TokenRevocationErrorResponse {
                error: "unsupported_token_type".to_string(),
                error_description: format!("Token type '{}' is not supported", token_type_hint),
            })
        }
    }
}

/// Revoke all tokens for a consumer (logout)
pub async fn revoke_all_tokens_handler(
    State(state): State<Arc<TokenRevocationHandlerState>>,
    Json(req): Json<RevokeAllTokensRequest>,
) -> Result<(StatusCode, Json<RevokeAllTokensResponse>), TokenRevocationErrorResponse> {
    match state.refresh_repo.revoke_all_for_consumer(&req.consumer_id).await {
        Ok(count) => {
            info!(
                consumer_id = %req.consumer_id,
                revoked_count = count,
                "All tokens revoked for consumer"
            );
            Ok((
                StatusCode::OK,
                Json(RevokeAllTokensResponse {
                    success: true,
                    revoked_count: count,
                    message: format!("Revoked {} tokens", count),
                }),
            ))
        }
        Err(e) => {
            error!("Failed to revoke all tokens: {}", e);
            Err(TokenRevocationErrorResponse {
                error: "server_error".to_string(),
                error_description: "Failed to revoke tokens".to_string(),
            })
        }
    }
}

// ── Revoke All Tokens Types ─────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokeAllTokensRequest {
    pub consumer_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokeAllTokensResponse {
    pub success: bool,
    pub revoked_count: u64,
    pub message: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_revocation_request_serialization() {
        let req = TokenRevocationRequest {
            token: "token_123".to_string(),
            token_type_hint: Some("refresh_token".to_string()),
            client_id: "client_1".to_string(),
            consumer_id: "consumer_1".to_string(),
        };

        let json = serde_json::to_string(&req).unwrap();
        let deserialized: TokenRevocationRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.token, req.token);
    }

    #[test]
    fn test_token_revocation_response_serialization() {
        let resp = TokenRevocationResponse {
            success: true,
            message: "Token revoked".to_string(),
        };

        let json = serde_json::to_string(&resp).unwrap();
        let deserialized: TokenRevocationResponse = serde_json::from_str(&json).unwrap();
        assert!(deserialized.success);
    }

    #[test]
    fn test_revoke_all_tokens_request_serialization() {
        let req = RevokeAllTokensRequest {
            consumer_id: "consumer_1".to_string(),
        };

        let json = serde_json::to_string(&req).unwrap();
        let deserialized: RevokeAllTokensRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.consumer_id, req.consumer_id);
    }
}
