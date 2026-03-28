//! OAuth 2.0 Refresh Token Service
//!
//! Implements secure refresh token generation, hashing, and rotation.
//! Uses Argon2id for hashing and maintains token families for theft detection.

use argon2::{
    password_hash::{Ident, ParamString, PasswordHash, PasswordHasher, SaltString},
    Argon2, PasswordHash as ArgonPasswordHash, PasswordVerifier,
};
use chrono::{DateTime, Duration, Utc};
use rand::Rng;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ── Refresh Token Constants ──────────────────────────────────────────────────

pub const REFRESH_TOKEN_LENGTH_BYTES: usize = 32; // 256-bit entropy
pub const REFRESH_TOKEN_TTL_SECS: i64 = 7 * 24 * 60 * 60; // 7 days
pub const REFRESH_TOKEN_ABSOLUTE_TTL_SECS: i64 = 30 * 24 * 60 * 60; // 30 days (family lifetime)

// ── Refresh Token Status ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RefreshTokenStatus {
    Active,
    Used,
    Revoked,
    Expired,
}

impl RefreshTokenStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            RefreshTokenStatus::Active => "active",
            RefreshTokenStatus::Used => "used",
            RefreshTokenStatus::Revoked => "revoked",
            RefreshTokenStatus::Expired => "expired",
        }
    }
}

// ── Refresh Token Metadata ───────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshTokenMetadata {
    pub token_id: String,
    pub family_id: String,
    pub consumer_id: String,
    pub client_id: String,
    pub scope: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub family_expires_at: DateTime<Utc>,
    pub parent_token_id: Option<String>,
    pub replacement_token_id: Option<String>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub status: RefreshTokenStatus,
}

// ── Refresh Token Generation Request ─────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshTokenRequest {
    pub consumer_id: String,
    pub client_id: String,
    pub scope: String,
    pub family_id: Option<String>, // For rotation
    pub parent_token_id: Option<String>, // For rotation
}

// ── Refresh Token Response ───────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshTokenResponse {
    pub token: String,
    pub token_id: String,
    pub family_id: String,
    pub expires_in: i64,
}

// ── Refresh Token Service ────────────────────────────────────────────────────

pub struct RefreshTokenService;

impl RefreshTokenService {
    /// Generate a new refresh token with secure random bytes
    pub fn generate_token() -> String {
        let mut rng = rand::thread_rng();
        let random_bytes: Vec<u8> = (0..REFRESH_TOKEN_LENGTH_BYTES)
            .map(|_| rng.gen())
            .collect();

        // Encode as base64url for safe transmission
        base64_url::encode(&random_bytes)
    }

    /// Hash a refresh token using Argon2id
    pub fn hash_token(token: &str) -> Result<String, RefreshTokenError> {
        let salt = SaltString::generate(rand::thread_rng());
        let argon2 = Argon2::default();

        let password_hash = argon2
            .hash_password(token.as_bytes(), &salt)
            .map_err(|e| RefreshTokenError::HashingFailed(e.to_string()))?
            .to_string();

        Ok(password_hash)
    }

    /// Verify a refresh token against its hash
    pub fn verify_token(token: &str, hash: &str) -> Result<bool, RefreshTokenError> {
        let parsed_hash = PasswordHash::new(hash)
            .map_err(|e| RefreshTokenError::InvalidHash(e.to_string()))?;

        let argon2 = Argon2::default();
        let is_valid = argon2
            .verify_password(token.as_bytes(), &parsed_hash)
            .is_ok();

        Ok(is_valid)
    }

    /// Create a new refresh token
    pub fn create_token(request: RefreshTokenRequest) -> Result<RefreshTokenResponse, RefreshTokenError> {
        let token = Self::generate_token();
        let token_id = Uuid::new_v4().to_string();
        let family_id = request.family_id.unwrap_or_else(|| Uuid::new_v4().to_string());

        let now = Utc::now();
        let expires_in = REFRESH_TOKEN_TTL_SECS;

        Ok(RefreshTokenResponse {
            token,
            token_id,
            family_id,
            expires_in,
        })
    }

    /// Create metadata for a refresh token
    pub fn create_metadata(
        token_id: String,
        family_id: String,
        request: RefreshTokenRequest,
        parent_token_id: Option<String>,
    ) -> RefreshTokenMetadata {
        let now = Utc::now();
        let expires_at = now + Duration::seconds(REFRESH_TOKEN_TTL_SECS);
        let family_expires_at = now + Duration::seconds(REFRESH_TOKEN_ABSOLUTE_TTL_SECS);

        RefreshTokenMetadata {
            token_id,
            family_id,
            consumer_id: request.consumer_id,
            client_id: request.client_id,
            scope: request.scope,
            issued_at: now,
            expires_at,
            family_expires_at,
            parent_token_id,
            replacement_token_id: None,
            last_used_at: None,
            status: RefreshTokenStatus::Active,
        }
    }

    /// Validate token expiry
    pub fn is_expired(expires_at: DateTime<Utc>) -> bool {
        Utc::now() > expires_at
    }

    /// Validate family expiry
    pub fn is_family_expired(family_expires_at: DateTime<Utc>) -> bool {
        Utc::now() > family_expires_at
    }

    /// Check if scope downscoping is valid
    pub fn validate_scope_downscoping(
        original_scope: &str,
        requested_scope: &str,
    ) -> Result<(), RefreshTokenError> {
        let original_scopes: std::collections::HashSet<&str> =
            original_scope.split_whitespace().collect();
        let requested_scopes: std::collections::HashSet<&str> =
            requested_scope.split_whitespace().collect();

        // Requested scopes must be subset of original scopes
        if !requested_scopes.is_subset(&original_scopes) {
            return Err(RefreshTokenError::ScopeExpansionAttempted {
                original: original_scope.to_string(),
                requested: requested_scope.to_string(),
            });
        }

        Ok(())
    }
}

// ── Error Types ──────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum RefreshTokenError {
    #[error("failed to hash token: {0}")]
    HashingFailed(String),
    #[error("invalid hash format: {0}")]
    InvalidHash(String),
    #[error("token verification failed")]
    VerificationFailed,
    #[error("token has expired")]
    TokenExpired,
    #[error("token family has expired")]
    FamilyExpired,
    #[error("token has been revoked")]
    TokenRevoked,
    #[error("token has been used (possible theft)")]
    TokenAlreadyUsed,
    #[error("scope expansion attempted: original {original}, requested {requested}")]
    ScopeExpansionAttempted { original: String, requested: String },
    #[error("internal error: {0}")]
    Internal(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_generation() {
        let token1 = RefreshTokenService::generate_token();
        let token2 = RefreshTokenService::generate_token();

        assert!(!token1.is_empty());
        assert!(!token2.is_empty());
        assert_ne!(token1, token2); // Should be different
    }

    #[test]
    fn test_token_hashing() {
        let token = RefreshTokenService::generate_token();
        let hash = RefreshTokenService::hash_token(&token).unwrap();

        assert!(!hash.is_empty());
        assert_ne!(token, hash); // Hash should be different from token
    }

    #[test]
    fn test_token_verification() {
        let token = RefreshTokenService::generate_token();
        let hash = RefreshTokenService::hash_token(&token).unwrap();

        let is_valid = RefreshTokenService::verify_token(&token, &hash).unwrap();
        assert!(is_valid);

        let is_invalid = RefreshTokenService::verify_token("wrong_token", &hash).unwrap();
        assert!(!is_invalid);
    }

    #[test]
    fn test_token_expiry() {
        let now = Utc::now();
        let future = now + Duration::hours(1);
        let past = now - Duration::hours(1);

        assert!(!RefreshTokenService::is_expired(future));
        assert!(RefreshTokenService::is_expired(past));
    }

    #[test]
    fn test_scope_downscoping_valid() {
        let original = "wallet:read onramp:quote bills:pay";
        let requested = "wallet:read onramp:quote";

        assert!(RefreshTokenService::validate_scope_downscoping(original, requested).is_ok());
    }

    #[test]
    fn test_scope_downscoping_invalid() {
        let original = "wallet:read onramp:quote";
        let requested = "wallet:read onramp:quote admin:transactions";

        assert!(RefreshTokenService::validate_scope_downscoping(original, requested).is_err());
    }

    #[test]
    fn test_refresh_token_request() {
        let request = RefreshTokenRequest {
            consumer_id: "consumer_123".to_string(),
            client_id: "client_123".to_string(),
            scope: "wallet:read onramp:quote".to_string(),
            family_id: None,
            parent_token_id: None,
        };

        let response = RefreshTokenService::create_token(request).unwrap();
        assert!(!response.token.is_empty());
        assert!(!response.token_id.is_empty());
        assert!(!response.family_id.is_empty());
        assert_eq!(response.expires_in, REFRESH_TOKEN_TTL_SECS);
    }

    #[test]
    fn test_refresh_token_metadata() {
        let request = RefreshTokenRequest {
            consumer_id: "consumer_123".to_string(),
            client_id: "client_123".to_string(),
            scope: "wallet:read".to_string(),
            family_id: None,
            parent_token_id: None,
        };

        let token_id = Uuid::new_v4().to_string();
        let family_id = Uuid::new_v4().to_string();

        let metadata = RefreshTokenService::create_metadata(
            token_id.clone(),
            family_id.clone(),
            request,
            None,
        );

        assert_eq!(metadata.token_id, token_id);
        assert_eq!(metadata.family_id, family_id);
        assert_eq!(metadata.status, RefreshTokenStatus::Active);
        assert!(metadata.parent_token_id.is_none());
    }
}
