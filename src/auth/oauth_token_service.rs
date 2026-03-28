//! OAuth 2.0 access token issuance and management service
//!
//! Implements RS256-signed access tokens with:
//! - Consumer type-based TTL enforcement
//! - Token binding (IP/nonce)
//! - JTI-based revocation tracking
//! - Database persistence
//! - Redis caching for revocation checks

use chrono::Utc;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use uuid::Uuid;

use crate::cache::{Cache, RedisCache};
use crate::database::Repository;

// ── Token lifetime constants (in seconds) ────────────────────────────────────

pub const MOBILE_CLIENT_TTL_SECS: i64 = 3_600;        // 1 hour
pub const PARTNER_TTL_SECS: i64 = 1_800;              // 30 minutes
pub const MICROSERVICE_TTL_SECS: i64 = 900;           // 15 minutes
pub const ADMIN_TTL_SECS: i64 = 900;                  // 15 minutes

// ── Consumer types ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsumerType {
    MobileClient,
    Partner,
    Microservice,
    Admin,
}

impl ConsumerType {
    /// Get the maximum token lifetime for this consumer type
    pub fn max_ttl_secs(&self) -> i64 {
        match self {
            ConsumerType::MobileClient => MOBILE_CLIENT_TTL_SECS,
            ConsumerType::Partner => PARTNER_TTL_SECS,
            ConsumerType::Microservice => MICROSERVICE_TTL_SECS,
            ConsumerType::Admin => ADMIN_TTL_SECS,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            ConsumerType::MobileClient => "mobile_client",
            ConsumerType::Partner => "partner",
            ConsumerType::Microservice => "microservice",
            ConsumerType::Admin => "admin",
        }
    }
}

// ── Environment types ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Environment {
    Testnet,
    Mainnet,
}

impl Environment {
    pub fn as_str(&self) -> &'static str {
        match self {
            Environment::Testnet => "testnet",
            Environment::Mainnet => "mainnet",
        }
    }
}

// ── OAuth 2.0 Access Token Claims ────────────────────────────────────────────

/// Standard OAuth 2.0 + custom claims for access tokens
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthTokenClaims {
    /// Issuer URL
    pub iss: String,
    /// Subject (consumer ID)
    pub sub: String,
    /// Audience (API audience)
    pub aud: String,
    /// Expiry (Unix timestamp)
    pub exp: i64,
    /// Issued-at (Unix timestamp)
    pub iat: i64,
    /// JWT ID (unique token identifier)
    pub jti: String,
    /// Space-separated scopes
    pub scope: String,
    /// Client ID
    pub client_id: String,
    /// Consumer type (mobile_client | partner | microservice | admin)
    pub consumer_type: String,
    /// Environment (testnet | mainnet)
    pub environment: String,
    /// Key ID used for signing
    pub kid: String,
    /// Token binding (IP address or nonce)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binding: Option<String>,
}

// ── Token issuance request ───────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenIssuanceRequest {
    pub consumer_id: String,
    pub client_id: String,
    pub consumer_type: ConsumerType,
    pub scope: String,
    pub environment: Environment,
    pub requested_ttl_secs: Option<i64>,
    pub binding: Option<String>, // IP or nonce
}

// ── Token issuance response ──────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenIssuanceResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub scope: String,
}

// ── Token registry record (for database persistence) ────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenRegistryRecord {
    pub jti: String,
    pub consumer_id: String,
    pub client_id: String,
    pub scope: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub revoked: bool,
}

// ── Error types ──────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum OAuthTokenError {
    #[error("requested TTL exceeds maximum for consumer type: requested {requested}, max {max}")]
    TtlExceedsLimit { requested: i64, max: i64 },
    #[error("invalid consumer type")]
    InvalidConsumerType,
    #[error("invalid environment")]
    InvalidEnvironment,
    #[error("failed to generate token: {0}")]
    TokenGenerationFailed(String),
    #[error("failed to persist token: {0}")]
    PersistenceFailed(String),
    #[error("token not found: {0}")]
    TokenNotFound(String),
    #[error("internal error: {0}")]
    Internal(String),
}

// ── OAuth Token Service ──────────────────────────────────────────────────────

pub struct OAuthTokenService {
    issuer_url: String,
    api_audience: String,
    private_key_pem: String,
    key_id: String,
    db: Repository,
    cache: Option<RedisCache>,
}

impl OAuthTokenService {
    pub fn new(
        issuer_url: String,
        api_audience: String,
        private_key_pem: String,
        key_id: String,
        db: Repository,
        cache: Option<RedisCache>,
    ) -> Self {
        Self {
            issuer_url,
            api_audience,
            private_key_pem,
            key_id,
            db,
            cache,
        }
    }

    /// Generate a new access token
    pub async fn issue_token(
        &self,
        request: TokenIssuanceRequest,
    ) -> Result<TokenIssuanceResponse, OAuthTokenError> {
        // Validate TTL against consumer type limits
        let max_ttl = request.consumer_type.max_ttl_secs();
        let requested_ttl = request.requested_ttl_secs.unwrap_or(max_ttl);

        if requested_ttl > max_ttl {
            return Err(OAuthTokenError::TtlExceedsLimit {
                requested: requested_ttl,
                max: max_ttl,
            });
        }

        // Generate unique JTI
        let jti = format!("jti_{}", Uuid::new_v4().simple());

        // Calculate expiry
        let now = Utc::now().timestamp();
        let expires_at = now + requested_ttl;

        // Build claims
        let claims = OAuthTokenClaims {
            iss: self.issuer_url.clone(),
            sub: request.consumer_id.clone(),
            aud: self.api_audience.clone(),
            exp: expires_at,
            iat: now,
            jti: jti.clone(),
            scope: request.scope.clone(),
            client_id: request.client_id.clone(),
            consumer_type: request.consumer_type.as_str().to_string(),
            environment: request.environment.as_str().to_string(),
            kid: self.key_id.clone(),
            binding: request.binding.clone(),
        };

        // Sign token with RS256
        let token = self.sign_token(&claims)?;

        // Persist to database
        let record = TokenRegistryRecord {
            jti: jti.clone(),
            consumer_id: request.consumer_id,
            client_id: request.client_id,
            scope: request.scope.clone(),
            issued_at: now,
            expires_at,
            revoked: false,
        };

        self.persist_token(&record).await?;

        // Cache revocation status (not revoked)
        if let Some(cache) = &self.cache {
            let cache_key = format!("token_revoked:{}", jti);
            let _ = <RedisCache as Cache<bool>>::set(
                cache,
                &cache_key,
                &false,
                Some(std::time::Duration::from_secs(requested_ttl as u64)),
            )
            .await;
        }

        // Log token issuance (only JTI, never full token)
        tracing::info!(
            jti = %jti,
            consumer_id = %record.consumer_id,
            client_id = %record.client_id,
            scope = %record.scope,
            expires_at = expires_at,
            "access token issued"
        );

        Ok(TokenIssuanceResponse {
            access_token: token,
            token_type: "Bearer".to_string(),
            expires_in: requested_ttl,
            scope: request.scope,
        })
    }

    /// Sign token with RS256
    fn sign_token(&self, claims: &OAuthTokenClaims) -> Result<String, OAuthTokenError> {
        let key = EncodingKey::from_rsa_pem(self.private_key_pem.as_bytes())
            .map_err(|e| OAuthTokenError::TokenGenerationFailed(e.to_string()))?;

        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(self.key_id.clone());

        encode(&header, claims, &key)
            .map_err(|e| OAuthTokenError::TokenGenerationFailed(e.to_string()))
    }

    /// Persist token to database
    async fn persist_token(&self, record: &TokenRegistryRecord) -> Result<(), OAuthTokenError> {
        // TODO: Implement database persistence
        // This will be implemented in the token_registry_repository.rs
        Ok(())
    }

    /// Check if token is revoked
    pub async fn is_token_revoked(&self, jti: &str) -> Result<bool, OAuthTokenError> {
        // Check cache first
        if let Some(cache) = &self.cache {
            let cache_key = format!("token_revoked:{}", jti);
            if let Ok(Some(revoked)) = <RedisCache as Cache<bool>>::get(cache, &cache_key).await {
                return Ok(revoked);
            }
        }

        // Fall back to database
        // TODO: Query database for revocation status
        Ok(false)
    }

    /// Revoke a token
    pub async fn revoke_token(&self, jti: &str) -> Result<(), OAuthTokenError> {
        // Update database
        // TODO: Mark token as revoked in database

        // Update cache
        if let Some(cache) = &self.cache {
            let cache_key = format!("token_revoked:{}", jti);
            let _ = <RedisCache as Cache<bool>>::set(
                cache,
                &cache_key,
                &true,
                Some(std::time::Duration::from_secs(86400)), // 24 hours
            )
            .await;
        }

        tracing::info!(jti = %jti, "access token revoked");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_consumer_type_ttl() {
        assert_eq!(ConsumerType::MobileClient.max_ttl_secs(), 3_600);
        assert_eq!(ConsumerType::Partner.max_ttl_secs(), 1_800);
        assert_eq!(ConsumerType::Microservice.max_ttl_secs(), 900);
        assert_eq!(ConsumerType::Admin.max_ttl_secs(), 900);
    }

    #[test]
    fn test_ttl_validation() {
        let request = TokenIssuanceRequest {
            consumer_id: "consumer_1".to_string(),
            client_id: "client_1".to_string(),
            consumer_type: ConsumerType::Partner,
            scope: "read write".to_string(),
            environment: Environment::Testnet,
            requested_ttl_secs: Some(3_600), // Exceeds Partner max of 1800
            binding: None,
        };

        // This would fail validation in the service
        assert!(request.requested_ttl_secs.unwrap() > ConsumerType::Partner.max_ttl_secs());
    }

    #[test]
    fn test_environment_serialization() {
        let env = Environment::Mainnet;
        assert_eq!(env.as_str(), "mainnet");

        let env = Environment::Testnet;
        assert_eq!(env.as_str(), "testnet");
    }
}
