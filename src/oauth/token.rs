//! RS256 JWT access token generation and validation for OAuth 2.0.

use chrono::Utc;
use jsonwebtoken::{decode, encode, Algorithm, Header, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::keys::RsaKeyPair;
use super::types::OAuthError;

pub const ACCESS_TOKEN_TTL_SECS: u64 = 3_600; // 1 hour

// ── Claims ────────────────────────────────────────────────────────────────────

/// Standard + platform-specific JWT claims for OAuth 2.0 access tokens.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthClaims {
    /// Issuer
    pub iss: String,
    /// Subject (wallet address or client_id for client_credentials)
    pub sub: String,
    /// Audience
    pub aud: Vec<String>,
    /// Expiry (Unix timestamp)
    pub exp: i64,
    /// Issued at (Unix timestamp)
    pub iat: i64,
    /// JWT ID — unique per token, used for revocation
    pub jti: String,
    /// Space-separated scopes
    pub scope: String,
    /// OAuth client ID
    pub client_id: String,
    /// "user" | "service" — distinguishes end-user vs machine tokens
    pub consumer_type: String,
}

// ── Generation ────────────────────────────────────────────────────────────────

pub struct TokenParams<'a> {
    pub issuer: &'a str,
    pub subject: &'a str,
    pub audience: Vec<String>,
    pub scope: &'a str,
    pub client_id: &'a str,
    pub consumer_type: &'a str,
    pub ttl_secs: u64,
}

/// Sign an RS256 access token.
pub fn generate_access_token(
    key_pair: &RsaKeyPair,
    params: TokenParams<'_>,
) -> Result<(String, OAuthClaims), OAuthError> {
    let now = Utc::now().timestamp();
    let jti = Uuid::new_v4().to_string();

    let claims = OAuthClaims {
        iss: params.issuer.to_string(),
        sub: params.subject.to_string(),
        aud: params.audience,
        exp: now + params.ttl_secs as i64,
        iat: now,
        jti,
        scope: params.scope.to_string(),
        client_id: params.client_id.to_string(),
        consumer_type: params.consumer_type.to_string(),
    };

    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(key_pair.kid.clone());

    let encoding_key = key_pair.encoding_key()?;
    let token = encode(&header, &claims, &encoding_key)
        .map_err(|e| OAuthError::ServerError(format!("JWT signing failed: {}", e)))?;

    Ok((token, claims))
}

/// Validate an RS256 access token and return its claims.
pub fn validate_access_token(
    token: &str,
    key_pair: &RsaKeyPair,
    expected_issuer: &str,
) -> Result<OAuthClaims, OAuthError> {
    let decoding_key = key_pair.decoding_key()?;

    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[expected_issuer]);
    // Audience validation is done by callers (resource servers may differ)
    validation.validate_aud = false;

    let data = decode::<OAuthClaims>(token, &decoding_key, &validation).map_err(|e| {
        use jsonwebtoken::errors::ErrorKind;
        match e.kind() {
            ErrorKind::ExpiredSignature => OAuthError::InvalidGrant("token expired".to_string()),
            _ => OAuthError::InvalidGrant(format!("invalid token: {}", e)),
        }
    })?;

    // Manual expiry check for typed error
    if data.claims.exp < Utc::now().timestamp() {
        return Err(OAuthError::InvalidGrant("token expired".to_string()));
    }

    Ok(data.claims)
}

// ── Introspection response ────────────────────────────────────────────────────

/// RFC 7662 token introspection response.
#[derive(Debug, Serialize)]
pub struct IntrospectionResponse {
    pub active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
}

impl IntrospectionResponse {
    pub fn inactive() -> Self {
        Self {
            active: false,
            scope: None,
            client_id: None,
            sub: None,
            exp: None,
            iat: None,
            jti: None,
            iss: None,
        }
    }

    pub fn from_claims(claims: OAuthClaims) -> Self {
        Self {
            active: true,
            scope: Some(claims.scope),
            client_id: Some(claims.client_id),
            sub: Some(claims.sub),
            exp: Some(claims.exp),
            iat: Some(claims.iat),
            jti: Some(claims.jti),
            iss: Some(claims.iss),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // We can't easily generate RSA keys in unit tests without the rsa crate's
    // key generation feature, so we test claim construction logic only.

    #[test]
    fn test_introspection_inactive() {
        let resp = IntrospectionResponse::inactive();
        assert!(!resp.active);
        assert!(resp.scope.is_none());
    }

    #[test]
    fn test_introspection_from_claims() {
        let claims = OAuthClaims {
            iss: "https://aframp.com".to_string(),
            sub: "GWALLET123".to_string(),
            aud: vec!["aframp-api".to_string()],
            exp: Utc::now().timestamp() + 3600,
            iat: Utc::now().timestamp(),
            jti: "jti-test".to_string(),
            scope: "wallet:read".to_string(),
            client_id: "client-abc".to_string(),
            consumer_type: "user".to_string(),
        };
        let resp = IntrospectionResponse::from_claims(claims);
        assert!(resp.active);
        assert_eq!(resp.scope.as_deref(), Some("wallet:read"));
        assert_eq!(resp.client_id.as_deref(), Some("client-abc"));
    }
}
