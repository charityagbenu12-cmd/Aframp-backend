//! OAuth 2.0 Refresh Token Validator
//!
//! Validates refresh tokens for:
//! - Expiry and family expiry
//! - Token status (active, used, revoked)
//! - Scope validity
//! - Theft detection (reuse detection)

use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::database::refresh_token_repository::{RefreshToken, RefreshTokenRepository};
use super::refresh_token_service::{RefreshTokenError, RefreshTokenService, RefreshTokenStatus};

// ── Validation context ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshTokenValidationContext {
    pub consumer_id: String,
    pub client_id: String,
    pub requested_scope: Option<String>,
}

// ── Validation result ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshTokenValidationResult {
    pub is_valid: bool,
    pub token_id: String,
    pub family_id: String,
    pub consumer_id: String,
    pub client_id: String,
    pub scope: String,
    pub requested_scope: Option<String>,
    pub error: Option<String>,
}

// ── Refresh token validator ──────────────────────────────────────────────────

pub struct RefreshTokenValidator {
    repo: RefreshTokenRepository,
}

impl RefreshTokenValidator {
    pub fn new(repo: RefreshTokenRepository) -> Self {
        Self { repo }
    }

    /// Validate a refresh token
    pub async fn validate(
        &self,
        token: &str,
        context: RefreshTokenValidationContext,
    ) -> Result<RefreshTokenValidationResult, RefreshTokenError> {
        // Find token by token_id (we need to search by hash in real scenario)
        // For now, we'll assume token_id is passed separately or we need to iterate
        // In production, you'd have a lookup mechanism
        
        // This is a placeholder - actual implementation would:
        // 1. Hash the token
        // 2. Search for matching hash in database
        // 3. Validate all conditions
        
        Err(RefreshTokenError::Internal(
            "Token lookup not implemented - use validate_by_id instead".to_string(),
        ))
    }

    /// Validate a refresh token by token_id
    pub async fn validate_by_id(
        &self,
        token_id: &str,
        token_plaintext: &str,
        context: RefreshTokenValidationContext,
    ) -> Result<RefreshTokenValidationResult, RefreshTokenError> {
        // Fetch token from database
        let db_token = self
            .repo
            .find_by_token_id(token_id)
            .await
            .map_err(|e| RefreshTokenError::Internal(e.to_string()))?
            .ok_or(RefreshTokenError::Internal("Token not found".to_string()))?;

        // Verify token hash
        let is_valid_hash = RefreshTokenService::verify_token(token_plaintext, &db_token.token_hash)
            .map_err(|e| RefreshTokenError::Internal(e.to_string()))?;

        if !is_valid_hash {
            return Ok(RefreshTokenValidationResult {
                is_valid: false,
                token_id: token_id.to_string(),
                family_id: db_token.family_id.clone(),
                consumer_id: db_token.consumer_id.clone(),
                client_id: db_token.client_id.clone(),
                scope: db_token.scope.clone(),
                requested_scope: context.requested_scope.clone(),
                error: Some("Token verification failed".to_string()),
            });
        }

        // Validate consumer and client match
        if db_token.consumer_id != context.consumer_id || db_token.client_id != context.client_id {
            return Ok(RefreshTokenValidationResult {
                is_valid: false,
                token_id: token_id.to_string(),
                family_id: db_token.family_id.clone(),
                consumer_id: db_token.consumer_id.clone(),
                client_id: db_token.client_id.clone(),
                scope: db_token.scope.clone(),
                requested_scope: context.requested_scope.clone(),
                error: Some("Consumer or client mismatch".to_string()),
            });
        }

        // Check token status
        match db_token.status.as_str() {
            "revoked" => {
                return Ok(RefreshTokenValidationResult {
                    is_valid: false,
                    token_id: token_id.to_string(),
                    family_id: db_token.family_id.clone(),
                    consumer_id: db_token.consumer_id.clone(),
                    client_id: db_token.client_id.clone(),
                    scope: db_token.scope.clone(),
                    requested_scope: context.requested_scope.clone(),
                    error: Some("Token has been revoked".to_string()),
                });
            }
            "used" => {
                // Token reuse detected - possible theft
                return Ok(RefreshTokenValidationResult {
                    is_valid: false,
                    token_id: token_id.to_string(),
                    family_id: db_token.family_id.clone(),
                    consumer_id: db_token.consumer_id.clone(),
                    client_id: db_token.client_id.clone(),
                    scope: db_token.scope.clone(),
                    requested_scope: context.requested_scope.clone(),
                    error: Some("Token reuse detected - possible theft".to_string()),
                });
            }
            "expired" => {
                return Ok(RefreshTokenValidationResult {
                    is_valid: false,
                    token_id: token_id.to_string(),
                    family_id: db_token.family_id.clone(),
                    consumer_id: db_token.consumer_id.clone(),
                    client_id: db_token.client_id.clone(),
                    scope: db_token.scope.clone(),
                    requested_scope: context.requested_scope.clone(),
                    error: Some("Token has expired".to_string()),
                });
            }
            _ => {}
        }

        // Check token expiry
        if RefreshTokenService::is_expired(db_token.expires_at) {
            return Ok(RefreshTokenValidationResult {
                is_valid: false,
                token_id: token_id.to_string(),
                family_id: db_token.family_id.clone(),
                consumer_id: db_token.consumer_id.clone(),
                client_id: db_token.client_id.clone(),
                scope: db_token.scope.clone(),
                requested_scope: context.requested_scope.clone(),
                error: Some("Token has expired".to_string()),
            });
        }

        // Check family expiry
        if RefreshTokenService::is_family_expired(db_token.family_expires_at) {
            return Ok(RefreshTokenValidationResult {
                is_valid: false,
                token_id: token_id.to_string(),
                family_id: db_token.family_id.clone(),
                consumer_id: db_token.consumer_id.clone(),
                client_id: db_token.client_id.clone(),
                scope: db_token.scope.clone(),
                requested_scope: context.requested_scope.clone(),
                error: Some("Token family has expired".to_string()),
            });
        }

        // Validate scope downscoping if requested
        if let Some(requested_scope) = &context.requested_scope {
            RefreshTokenService::validate_scope_downscoping(&db_token.scope, requested_scope)?;
        }

        Ok(RefreshTokenValidationResult {
            is_valid: true,
            token_id: token_id.to_string(),
            family_id: db_token.family_id.clone(),
            consumer_id: db_token.consumer_id.clone(),
            client_id: db_token.client_id.clone(),
            scope: db_token.scope.clone(),
            requested_scope: context.requested_scope.clone(),
            error: None,
        })
    }

    /// Detect token reuse (theft detection)
    pub async fn detect_reuse(&self, token_id: &str) -> Result<bool, RefreshTokenError> {
        self.repo
            .is_used(token_id)
            .await
            .map_err(|e| RefreshTokenError::Internal(e.to_string()))
    }

    /// Check if token is revoked
    pub async fn is_revoked(&self, token_id: &str) -> Result<bool, RefreshTokenError> {
        self.repo
            .is_revoked(token_id)
            .await
            .map_err(|e| RefreshTokenError::Internal(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validation_result_serialization() {
        let result = RefreshTokenValidationResult {
            is_valid: true,
            token_id: "token_123".to_string(),
            family_id: "family_123".to_string(),
            consumer_id: "consumer_1".to_string(),
            client_id: "client_1".to_string(),
            scope: "read write".to_string(),
            requested_scope: Some("read".to_string()),
            error: None,
        };

        let json = serde_json::to_string(&result).unwrap();
        let deserialized: RefreshTokenValidationResult = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.is_valid, result.is_valid);
        assert_eq!(deserialized.token_id, result.token_id);
    }

    #[test]
    fn test_validation_context_serialization() {
        let context = RefreshTokenValidationContext {
            consumer_id: "consumer_1".to_string(),
            client_id: "client_1".to_string(),
            requested_scope: Some("read".to_string()),
        };

        let json = serde_json::to_string(&context).unwrap();
        let deserialized: RefreshTokenValidationContext = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.consumer_id, context.consumer_id);
    }
}
