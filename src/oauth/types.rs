//! Core OAuth 2.0 domain types.

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};

// ── Grant types ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantType {
    AuthorizationCode,
    ClientCredentials,
    RefreshToken,
}

impl GrantType {
    pub fn as_str(&self) -> &'static str {
        match self {
            GrantType::AuthorizationCode => "authorization_code",
            GrantType::ClientCredentials => "client_credentials",
            GrantType::RefreshToken => "refresh_token",
        }
    }
}

impl std::fmt::Display for GrantType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for GrantType {
    type Err = OAuthError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "authorization_code" => Ok(GrantType::AuthorizationCode),
            "client_credentials" => Ok(GrantType::ClientCredentials),
            "refresh_token" => Ok(GrantType::RefreshToken),
            _ => Err(OAuthError::UnsupportedGrantType(s.to_string())),
        }
    }
}

// ── Client type ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ClientType {
    Public,
    Confidential,
}

impl std::fmt::Display for ClientType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientType::Public => write!(f, "public"),
            ClientType::Confidential => write!(f, "confidential"),
        }
    }
}

impl std::str::FromStr for ClientType {
    type Err = OAuthError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "public" => Ok(ClientType::Public),
            "confidential" => Ok(ClientType::Confidential),
            _ => Err(OAuthError::InvalidRequest(format!("unknown client_type: {}", s))),
        }
    }
}

// ── Client record ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthClient {
    pub id: Uuid,
    pub client_id: String,
    /// None for public clients
    pub client_secret_hash: Option<String>,
    pub client_name: String,
    pub client_type: ClientType,
    pub allowed_grant_types: Vec<String>,
    pub allowed_scopes: Vec<String>,
    pub redirect_uris: Vec<String>,
    pub status: String,
    pub created_by: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl OAuthClient {
    pub fn is_active(&self) -> bool {
        self.status == "active"
    }

    pub fn supports_grant(&self, grant: &GrantType) -> bool {
        self.allowed_grant_types.iter().any(|g| g == grant.as_str())
    }

    pub fn has_redirect_uri(&self, uri: &str) -> bool {
        self.redirect_uris.iter().any(|u| u == uri)
    }

    /// Validate that requested scopes are a subset of allowed scopes.
    pub fn validate_scopes(&self, requested: &[String]) -> Result<(), OAuthError> {
        for scope in requested {
            if !self.allowed_scopes.contains(scope) {
                return Err(OAuthError::InvalidScope(scope.clone()));
            }
        }
        Ok(())
    }
}

// ── Authorization code record ─────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationCode {
    pub id: Uuid,
    pub code: String,
    pub client_id: String,
    /// Wallet address of the authorizing user
    pub subject: String,
    pub scope: Vec<String>,
    pub redirect_uri: String,
    /// SHA-256 of the PKCE code_verifier (base64url-encoded)
    pub code_challenge: String,
    pub used: bool,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

impl AuthorizationCode {
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }
}

// ── Token response ────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: &'static str,
    pub expires_in: u64,
    pub scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
}

// ── OAuth error ───────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum OAuthError {
    #[error("invalid_request: {0}")]
    InvalidRequest(String),
    #[error("invalid_client")]
    InvalidClient,
    #[error("invalid_grant: {0}")]
    InvalidGrant(String),
    #[error("unauthorized_client")]
    UnauthorizedClient,
    #[error("unsupported_grant_type: {0}")]
    UnsupportedGrantType(String),
    #[error("invalid_scope: {0}")]
    InvalidScope(String),
    #[error("access_denied")]
    AccessDenied,
    #[error("server_error: {0}")]
    ServerError(String),
    #[error("temporarily_unavailable")]
    TemporarilyUnavailable,
}

impl OAuthError {
    /// RFC 6749 error code string
    pub fn error_code(&self) -> &'static str {
        match self {
            OAuthError::InvalidRequest(_) => "invalid_request",
            OAuthError::InvalidClient => "invalid_client",
            OAuthError::InvalidGrant(_) => "invalid_grant",
            OAuthError::UnauthorizedClient => "unauthorized_client",
            OAuthError::UnsupportedGrantType(_) => "unsupported_grant_type",
            OAuthError::InvalidScope(_) => "invalid_scope",
            OAuthError::AccessDenied => "access_denied",
            OAuthError::ServerError(_) => "server_error",
            OAuthError::TemporarilyUnavailable => "temporarily_unavailable",
        }
    }

    pub fn http_status(&self) -> u16 {
        match self {
            OAuthError::InvalidClient => 401,
            OAuthError::AccessDenied => 403,
            OAuthError::ServerError(_) | OAuthError::TemporarilyUnavailable => 500,
            _ => 400,
        }
    }
}

// ── Supported scopes ──────────────────────────────────────────────────────────

pub const SUPPORTED_SCOPES: &[&str] = &[
    "openid",
    "profile",
    "wallet:read",
    "wallet:write",
    "transactions:read",
    "transactions:write",
    "offramp",
    "onramp",
    "admin",
];

pub fn is_supported_scope(scope: &str) -> bool {
    SUPPORTED_SCOPES.contains(&scope)
}

pub fn parse_scope_string(scope_str: &str) -> Vec<String> {
    scope_str
        .split_whitespace()
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

pub fn scope_vec_to_string(scopes: &[String]) -> String {
    scopes.join(" ")
}
