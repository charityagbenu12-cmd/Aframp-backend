//! Core types for service authentication

use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

// ── Error types ──────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum ServiceAuthError {
    #[error("service not registered: {0}")]
    ServiceNotRegistered(String),

    #[error("invalid service credentials")]
    InvalidCredentials,

    #[error("service token expired")]
    TokenExpired,

    #[error("service token refresh failed: {0}")]
    TokenRefreshFailed(String),

    #[error("service impersonation detected: claimed={claimed}, actual={actual}")]
    ServiceImpersonation { claimed: String, actual: String },

    #[error("service not authorized to call endpoint: service={service}, endpoint={endpoint}")]
    ServiceNotAuthorized { service: String, endpoint: String },

    #[error("certificate error: {0}")]
    CertificateError(String),

    #[error("certificate expired: service={service}, expired_at={expired_at}")]
    CertificateExpired { service: String, expired_at: String },

    #[error("database error: {0}")]
    DatabaseError(String),

    #[error("secrets manager error: {0}")]
    SecretsManagerError(String),

    #[error("internal error: {0}")]
    Internal(String),
}

pub type ServiceAuthResult<T> = Result<T, ServiceAuthError>;

// ── Service token claims ─────────────────────────────────────────────────────

/// JWT claims for service-to-service tokens
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceTokenClaims {
    /// Issuer
    pub iss: String,
    /// Subject (service name)
    pub sub: String,
    /// Audience
    pub aud: Vec<String>,
    /// Expiry (Unix timestamp)
    pub exp: i64,
    /// Issued at (Unix timestamp)
    pub iat: i64,
    /// JWT ID
    pub jti: String,
    /// Scopes (always includes "microservice:internal")
    pub scope: String,
    /// OAuth client ID
    pub client_id: String,
    /// Consumer type (always "service")
    pub consumer_type: String,
}

// ── Service identity ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceIdentityInfo {
    pub service_name: String,
    pub client_id: String,
    pub allowed_scopes: Vec<String>,
    pub allowed_targets: Vec<String>,
    pub status: ServiceStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ServiceStatus {
    Active,
    Suspended,
    Revoked,
}

impl fmt::Display for ServiceStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServiceStatus::Active => write!(f, "active"),
            ServiceStatus::Suspended => write!(f, "suspended"),
            ServiceStatus::Revoked => write!(f, "revoked"),
        }
    }
}

// ── Service call context ─────────────────────────────────────────────────────

/// Injected into request extensions after successful service authentication
#[derive(Debug, Clone)]
pub struct AuthenticatedService {
    pub service_name: String,
    pub client_id: String,
    pub scopes: Vec<String>,
    pub token_jti: String,
}

// ── Token refresh configuration ──────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct TokenRefreshConfig {
    /// Refresh when remaining lifetime falls below this fraction (0.0 - 1.0)
    pub refresh_threshold: f64,
    /// Maximum retry attempts on refresh failure
    pub max_retries: u32,
    /// Initial backoff duration in milliseconds
    pub initial_backoff_ms: u64,
    /// Maximum backoff duration in milliseconds
    pub max_backoff_ms: u64,
}

impl Default for TokenRefreshConfig {
    fn default() -> Self {
        Self {
            refresh_threshold: 0.2, // Refresh at 20% remaining lifetime
            max_retries: 3,
            initial_backoff_ms: 100,
            max_backoff_ms: 5000,
        }
    }
}

// ── Service authentication audit ─────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceAuthAudit {
    pub calling_service: String,
    pub target_endpoint: String,
    pub token_jti: Option<String>,
    pub auth_result: AuthResult,
    pub failure_reason: Option<String>,
    pub request_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthResult {
    Success,
    Unauthorized,
    Forbidden,
    ImpersonationAttempt,
}

impl fmt::Display for AuthResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthResult::Success => write!(f, "success"),
            AuthResult::Unauthorized => write!(f, "unauthorized"),
            AuthResult::Forbidden => write!(f, "forbidden"),
            AuthResult::ImpersonationAttempt => write!(f, "impersonation_attempt"),
        }
    }
}
