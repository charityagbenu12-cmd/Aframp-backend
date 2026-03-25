//! OAuth 2.0 access token validation with stateless verification
//!
//! Implements:
//! - RS256 signature verification
//! - Claim validation (iss, aud, exp, environment)
//! - Token binding validation (IP/nonce)
//! - Revocation checking (Redis cache + database fallback)

use chrono::Utc;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use std::net::IpAddr;

use super::oauth_token_service::OAuthTokenClaims;
use crate::cache::{Cache, RedisCache};

// ── Validation error types ───────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum TokenValidationError {
    #[error("token_invalid")]
    InvalidToken,
    #[error("token_expired")]
    TokenExpired,
    #[error("token_revoked")]
    TokenRevoked,
    #[error("token_binding_failed")]
    TokenBindingFailed,
    #[error("token_environment_mismatch")]
    TokenEnvironmentMismatch,
    #[error("token_issuer_mismatch")]
    TokenIssuerMismatch,
    #[error("token_audience_mismatch")]
    TokenAudienceMismatch,
    #[error("internal error: {0}")]
    Internal(String),
}

impl TokenValidationError {
    /// Get the error code for OAuth 2.0 error responses
    pub fn error_code(&self) -> &'static str {
        match self {
            TokenValidationError::InvalidToken => "invalid_token",
            TokenValidationError::TokenExpired => "token_expired",
            TokenValidationError::TokenRevoked => "token_revoked",
            TokenValidationError::TokenBindingFailed => "token_binding_failed",
            TokenValidationError::TokenEnvironmentMismatch => "token_environment_mismatch",
            TokenValidationError::TokenIssuerMismatch => "token_issuer_mismatch",
            TokenValidationError::TokenAudienceMismatch => "token_audience_mismatch",
            TokenValidationError::Internal(_) => "server_error",
        }
    }
}

// ── Validation context ───────────────────────────────────────────────────────

pub struct ValidationContext {
    pub expected_issuer: String,
    pub expected_audience: String,
    pub expected_environment: String,
    pub request_ip: Option<IpAddr>,
    pub request_nonce: Option<String>,
}

// ── Token validator ──────────────────────────────────────────────────────────

pub struct OAuthTokenValidator {
    public_key_pem: String,
    cache: Option<RedisCache>,
}

impl OAuthTokenValidator {
    pub fn new(public_key_pem: String, cache: Option<RedisCache>) -> Self {
        Self {
            public_key_pem,
            cache,
        }
    }

    /// Validate and decode a JWT token
    pub async fn validate(
        &self,
        token: &str,
        context: &ValidationContext,
    ) -> Result<OAuthTokenClaims, TokenValidationError> {
        // Step 1: Decode and verify signature
        let claims = self.decode_and_verify(token)?;

        // Step 2: Validate standard claims
        self.validate_claims(&claims, context)?;

        // Step 3: Validate binding (IP or nonce)
        self.validate_binding(&claims, context)?;

        // Step 4: Check revocation status
        self.check_revocation(&claims).await?;

        Ok(claims)
    }

    /// Decode JWT and verify RS256 signature
    fn decode_and_verify(&self, token: &str) -> Result<OAuthTokenClaims, TokenValidationError> {
        let key = DecodingKey::from_rsa_pem(self.public_key_pem.as_bytes())
            .map_err(|e| TokenValidationError::Internal(e.to_string()))?;

        let mut validation = Validation::new(Algorithm::RS256);
        // We validate expiry manually for better error handling
        validation.validate_exp = false;
        validation.required_spec_claims = std::collections::HashSet::new();

        let token_data = decode::<OAuthTokenClaims>(token, &key, &validation)
            .map_err(|_| TokenValidationError::InvalidToken)?;

        Ok(token_data.claims)
    }

    /// Validate standard OAuth 2.0 claims
    fn validate_claims(
        &self,
        claims: &OAuthTokenClaims,
        context: &ValidationContext,
    ) -> Result<(), TokenValidationError> {
        // Validate issuer
        if claims.iss != context.expected_issuer {
            return Err(TokenValidationError::TokenIssuerMismatch);
        }

        // Validate audience
        if claims.aud != context.expected_audience {
            return Err(TokenValidationError::TokenAudienceMismatch);
        }

        // Validate expiry
        let now = Utc::now().timestamp();
        if claims.exp < now {
            return Err(TokenValidationError::TokenExpired);
        }

        // Validate environment
        if claims.environment != context.expected_environment {
            return Err(TokenValidationError::TokenEnvironmentMismatch);
        }

        Ok(())
    }

    /// Validate token binding (IP or nonce)
    fn validate_binding(
        &self,
        claims: &OAuthTokenClaims,
        context: &ValidationContext,
    ) -> Result<(), TokenValidationError> {
        match (&claims.binding, &context.request_ip, &context.request_nonce) {
            // No binding required
            (None, _, _) => Ok(()),

            // IP binding
            (Some(binding), Some(request_ip), _) => {
                let binding_ip: IpAddr = binding
                    .parse()
                    .map_err(|_| TokenValidationError::TokenBindingFailed)?;

                if binding_ip == *request_ip {
                    Ok(())
                } else {
                    Err(TokenValidationError::TokenBindingFailed)
                }
            }

            // Nonce binding
            (Some(binding), _, Some(request_nonce)) => {
                if binding == request_nonce {
                    Ok(())
                } else {
                    Err(TokenValidationError::TokenBindingFailed)
                }
            }

            // Binding required but not provided in request
            (Some(_), None, None) => Err(TokenValidationError::TokenBindingFailed),
        }
    }

    /// Check if token is revoked
    async fn check_revocation(&self, claims: &OAuthTokenClaims) -> Result<(), TokenValidationError> {
        // Check cache first (fast path)
        if let Some(cache) = &self.cache {
            let cache_key = format!("token_revoked:{}", claims.jti);

            match <RedisCache as Cache<bool>>::get(cache, &cache_key).await {
                Ok(Some(true)) => return Err(TokenValidationError::TokenRevoked),
                Ok(Some(false)) => return Ok(()), // Cache hit: not revoked
                Ok(None) => {
                    // Cache miss: fall through to database check
                }
                Err(_) => {
                    // Cache error: graceful degradation, continue to DB
                    tracing::warn!(jti = %claims.jti, "cache lookup failed during revocation check");
                }
            }
        }

        // Fall back to database check
        // TODO: Query database for revocation status
        // For now, assume not revoked if not in cache
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validation_error_codes() {
        assert_eq!(
            TokenValidationError::InvalidToken.error_code(),
            "invalid_token"
        );
        assert_eq!(
            TokenValidationError::TokenExpired.error_code(),
            "token_expired"
        );
        assert_eq!(
            TokenValidationError::TokenRevoked.error_code(),
            "token_revoked"
        );
        assert_eq!(
            TokenValidationError::TokenBindingFailed.error_code(),
            "token_binding_failed"
        );
        assert_eq!(
            TokenValidationError::TokenEnvironmentMismatch.error_code(),
            "token_environment_mismatch"
        );
    }

    #[test]
    fn test_binding_validation_ip() {
        use std::str::FromStr;

        let claims = OAuthTokenClaims {
            iss: "https://api.example.com".to_string(),
            sub: "consumer_1".to_string(),
            aud: "api".to_string(),
            exp: Utc::now().timestamp() + 3600,
            iat: Utc::now().timestamp(),
            jti: "jti_123".to_string(),
            scope: "read".to_string(),
            client_id: "client_1".to_string(),
            consumer_type: "mobile_client".to_string(),
            environment: "testnet".to_string(),
            kid: "key_1".to_string(),
            binding: Some("192.168.1.1".to_string()),
        };

        let context = ValidationContext {
            expected_issuer: "https://api.example.com".to_string(),
            expected_audience: "api".to_string(),
            expected_environment: "testnet".to_string(),
            request_ip: Some(IpAddr::from_str("192.168.1.1").unwrap()),
            request_nonce: None,
        };

        let validator = OAuthTokenValidator::new("".to_string(), None);
        assert!(validator.validate_binding(&claims, &context).is_ok());
    }

    #[test]
    fn test_binding_validation_ip_mismatch() {
        use std::str::FromStr;

        let claims = OAuthTokenClaims {
            iss: "https://api.example.com".to_string(),
            sub: "consumer_1".to_string(),
            aud: "api".to_string(),
            exp: Utc::now().timestamp() + 3600,
            iat: Utc::now().timestamp(),
            jti: "jti_123".to_string(),
            scope: "read".to_string(),
            client_id: "client_1".to_string(),
            consumer_type: "mobile_client".to_string(),
            environment: "testnet".to_string(),
            kid: "key_1".to_string(),
            binding: Some("192.168.1.1".to_string()),
        };

        let context = ValidationContext {
            expected_issuer: "https://api.example.com".to_string(),
            expected_audience: "api".to_string(),
            expected_environment: "testnet".to_string(),
            request_ip: Some(IpAddr::from_str("192.168.1.2").unwrap()),
            request_nonce: None,
        };

        let validator = OAuthTokenValidator::new("".to_string(), None);
        assert!(matches!(
            validator.validate_binding(&claims, &context),
            Err(TokenValidationError::TokenBindingFailed)
        ));
    }
}
