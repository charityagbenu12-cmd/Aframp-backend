//! OAuth 2.0 endpoint handlers.
//!
//! Endpoints:
//!   POST /oauth/token                        — token endpoint (auth code exchange + client credentials + refresh)
//!   GET  /oauth/authorize                    — authorization endpoint (PKCE flow)
//!   POST /oauth/token/introspect             — RFC 7662 token introspection
//!   POST /oauth/token/revoke                 — RFC 7009 token revocation
//!   GET  /oauth/.well-known/jwks.json        — JWKS public key set
//!   GET  /oauth/.well-known/openid-configuration — discovery document
//!   POST /api/admin/oauth/clients            — admin client registration
//!   POST /api/developer/oauth/clients        — self-service client registration

use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Redirect, Response},
    Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use uuid::Uuid;

use super::{
    client_store::{
        consume_auth_code, get_refresh_token, is_token_blacklisted, revoke_refresh_token,
        store_auth_code, store_refresh_token, blacklist_token, CreateClientInput,
        OAuthClientRepository, OAuthRefreshRecord, REFRESH_TOKEN_TTL_SECS,
    },
    keys::{JwkSet, RsaKeyPair},
    pkce::{compute_s256_challenge, validate_challenge_method, validate_code_verifier, verify_pkce_s256},
    token::{generate_access_token, validate_access_token, IntrospectionResponse, OAuthClaims, TokenParams, ACCESS_TOKEN_TTL_SECS},
    types::{
        parse_scope_string, scope_vec_to_string, AuthorizationCode, ClientType, GrantType,
        OAuthClient, OAuthError, TokenResponse, SUPPORTED_SCOPES,
    },
};
use crate::cache::RedisCache;
use crate::middleware::error::get_request_id_from_headers;

// ── Shared state ──────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct OAuthState {
    pub db_pool: sqlx::PgPool,
    pub redis_cache: RedisCache,
    pub key_pair: Arc<RsaKeyPair>,
    pub issuer: String,
    pub is_production: bool,
}

// ── Error helper ──────────────────────────────────────────────────────────────

fn oauth_error_response(err: OAuthError) -> Response {
    let status = StatusCode::from_u16(err.http_status()).unwrap_or(StatusCode::BAD_REQUEST);
    let body = serde_json::json!({
        "error": err.error_code(),
        "error_description": err.to_string(),
    });
    (status, Json(body)).into_response()
}

// ── Client registration ───────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct RegisterClientRequest {
    pub client_name: String,
    pub client_type: String,
    pub allowed_grant_types: Vec<String>,
    pub allowed_scopes: Vec<String>,
    pub redirect_uris: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct RegisterClientResponse {
    pub client_id: String,
    /// Only present at registration time for confidential clients
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    pub client_name: String,
    pub client_type: String,
    pub allowed_grant_types: Vec<String>,
    pub allowed_scopes: Vec<String>,
    pub redirect_uris: Vec<String>,
}

async fn register_client_inner(
    state: &OAuthState,
    req: RegisterClientRequest,
    created_by: Option<String>,
) -> Result<RegisterClientResponse, OAuthError> {
    // Parse and validate client type
    let client_type: ClientType = req.client_type.parse()?;

    // Validate grant types
    let mut grant_types = Vec::new();
    for g in &req.allowed_grant_types {
        let gt: GrantType = g.parse()?;
        grant_types.push(gt);
    }

    // Public clients cannot use client_credentials
    if client_type == ClientType::Public
        && grant_types.contains(&GrantType::ClientCredentials)
    {
        return Err(OAuthError::InvalidRequest(
            "public clients cannot use the client_credentials grant type".to_string(),
        ));
    }

    // Validate scopes
    for scope in &req.allowed_scopes {
        if !super::types::is_supported_scope(scope) {
            return Err(OAuthError::InvalidScope(scope.clone()));
        }
    }

    // Validate redirect URIs
    for uri in &req.redirect_uris {
        if state.is_production && uri.starts_with("http://") {
            return Err(OAuthError::InvalidRequest(format!(
                "redirect_uri '{}' must use HTTPS in production",
                uri
            )));
        }
    }

    // Authorization code flow requires at least one redirect URI
    if grant_types.contains(&GrantType::AuthorizationCode) && req.redirect_uris.is_empty() {
        return Err(OAuthError::InvalidRequest(
            "authorization_code grant requires at least one redirect_uri".to_string(),
        ));
    }

    // Generate client credentials
    let client_id = format!("client_{}", Uuid::new_v4().simple());
    let (raw_secret, secret_hash) = if client_type == ClientType::Confidential {
        let secret = generate_client_secret();
        let hash = hash_secret(&secret);
        (Some(secret), Some(hash))
    } else {
        (None, None)
    };

    let repo = OAuthClientRepository::new(state.db_pool.clone());
    repo.create(CreateClientInput {
        client_id: client_id.clone(),
        client_secret_hash: secret_hash,
        client_name: req.client_name.clone(),
        client_type: client_type.clone(),
        allowed_grant_types: req.allowed_grant_types.clone(),
        allowed_scopes: req.allowed_scopes.clone(),
        redirect_uris: req.redirect_uris.clone(),
        created_by,
    })
    .await?;

    Ok(RegisterClientResponse {
        client_id,
        client_secret: raw_secret,
        client_name: req.client_name,
        client_type: client_type.to_string(),
        allowed_grant_types: req.allowed_grant_types,
        allowed_scopes: req.allowed_scopes,
        redirect_uris: req.redirect_uris,
    })
}

/// POST /api/admin/oauth/clients
pub async fn admin_register_client(
    State(state): State<Arc<OAuthState>>,
    headers: HeaderMap,
    Json(req): Json<RegisterClientRequest>,
) -> Response {
    let created_by = get_request_id_from_headers(&headers)
        .map(|_| "admin".to_string());
    match register_client_inner(&state, req, created_by).await {
        Ok(resp) => (StatusCode::CREATED, Json(resp)).into_response(),
        Err(e) => oauth_error_response(e),
    }
}

/// POST /api/developer/oauth/clients
pub async fn developer_register_client(
    State(state): State<Arc<OAuthState>>,
    headers: HeaderMap,
    Json(req): Json<RegisterClientRequest>,
) -> Response {
    // In a real system, extract the authenticated developer's wallet from JWT extension.
    // Here we mark it as developer_portal.
    let created_by = Some("developer_portal".to_string());
    match register_client_inner(&state, req, created_by).await {
        Ok(resp) => (StatusCode::CREATED, Json(resp)).into_response(),
        Err(e) => oauth_error_response(e),
    }
}

// ── Authorization endpoint (GET /oauth/authorize) ─────────────────────────────

#[derive(Debug, Deserialize)]
pub struct AuthorizeQuery {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub code_challenge: String,
    pub code_challenge_method: String,
    /// Wallet address of the authenticated user (in production, extracted from session/JWT)
    pub subject: Option<String>,
    /// Consent decision: "approve" | "deny"
    pub consent: Option<String>,
}

/// GET /oauth/authorize
///
/// Phase 1: validate params and show consent screen (returns 200 with consent payload).
/// Phase 2: with consent=approve, issue authorization code and redirect.
pub async fn authorize(
    State(state): State<Arc<OAuthState>>,
    Query(params): Query<AuthorizeQuery>,
) -> Response {
    // Only "code" response_type is supported
    if params.response_type != "code" {
        return oauth_error_response(OAuthError::InvalidRequest(
            "only response_type=code is supported".to_string(),
        ));
    }

    // Validate PKCE method
    if let Err(e) = validate_challenge_method(&params.code_challenge_method) {
        return oauth_error_response(e);
    }

    // Validate code_challenge is present
    if params.code_challenge.trim().is_empty() {
        return oauth_error_response(OAuthError::InvalidRequest(
            "code_challenge is required".to_string(),
        ));
    }

    // Load and validate client
    let repo = OAuthClientRepository::new(state.db_pool.clone());
    let client = match repo.find_by_client_id(&params.client_id).await {
        Ok(Some(c)) => c,
        Ok(None) => return oauth_error_response(OAuthError::InvalidClient),
        Err(e) => return oauth_error_response(e),
    };

    if !client.is_active() {
        return oauth_error_response(OAuthError::UnauthorizedClient);
    }

    if !client.supports_grant(&GrantType::AuthorizationCode) {
        return oauth_error_response(OAuthError::UnauthorizedClient);
    }

    if !client.has_redirect_uri(&params.redirect_uri) {
        return oauth_error_response(OAuthError::InvalidRequest(
            "redirect_uri is not registered for this client".to_string(),
        ));
    }

    // Validate scopes
    let requested_scopes = parse_scope_string(params.scope.as_deref().unwrap_or("openid"));
    if let Err(e) = client.validate_scopes(&requested_scopes) {
        return oauth_error_response(e);
    }

    // Require authenticated subject
    let subject = match &params.subject {
        Some(s) if !s.is_empty() => s.clone(),
        _ => {
            return oauth_error_response(OAuthError::AccessDenied);
        }
    };

    // Handle consent decision
    match params.consent.as_deref() {
        Some("deny") => {
            let redirect = format!(
                "{}?error=access_denied&error_description=User+denied+access{}",
                params.redirect_uri,
                params
                    .state
                    .as_ref()
                    .map(|s| format!("&state={}", s))
                    .unwrap_or_default()
            );
            return Redirect::to(&redirect).into_response();
        }
        Some("approve") => {
            // Issue authorization code
            let code = generate_auth_code();
            let auth_code = AuthorizationCode {
                id: Uuid::new_v4(),
                code: code.clone(),
                client_id: params.client_id.clone(),
                subject,
                scope: requested_scopes,
                redirect_uri: params.redirect_uri.clone(),
                code_challenge: params.code_challenge.clone(),
                used: false,
                expires_at: Utc::now() + chrono::Duration::seconds(600),
                created_at: Utc::now(),
            };

            if let Err(e) = store_auth_code(&state.redis_cache, &auth_code).await {
                return oauth_error_response(e);
            }

            let redirect = format!(
                "{}?code={}{}",
                params.redirect_uri,
                code,
                params
                    .state
                    .as_ref()
                    .map(|s| format!("&state={}", s))
                    .unwrap_or_default()
            );
            return Redirect::to(&redirect).into_response();
        }
        _ => {
            // No consent decision yet — return consent screen data
            let consent_data = serde_json::json!({
                "client_name": client.client_name,
                "client_id": client.client_id,
                "requested_scopes": requested_scopes,
                "redirect_uri": params.redirect_uri,
                "state": params.state,
                "code_challenge": params.code_challenge,
                "code_challenge_method": params.code_challenge_method,
                "subject": subject,
                "action_url": "/oauth/authorize",
            });
            return (StatusCode::OK, Json(consent_data)).into_response();
        }
    }
}

// ── Token endpoint (POST /oauth/token) ───────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    pub grant_type: String,
    // Authorization Code fields
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub code_verifier: Option<String>,
    // Client Credentials / Auth Code identification
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    // Scope downscoping
    pub scope: Option<String>,
    // Refresh Token
    pub refresh_token: Option<String>,
}

/// POST /oauth/token
pub async fn token_endpoint(
    State(state): State<Arc<OAuthState>>,
    headers: HeaderMap,
    Json(req): Json<TokenRequest>,
) -> Response {
    let grant: GrantType = match req.grant_type.parse() {
        Ok(g) => g,
        Err(e) => return oauth_error_response(e),
    };

    match grant {
        GrantType::AuthorizationCode => {
            handle_authorization_code(&state, req, &headers).await
        }
        GrantType::ClientCredentials => {
            handle_client_credentials(&state, req, &headers).await
        }
        GrantType::RefreshToken => {
            handle_refresh_token(&state, req, &headers).await
        }
    }
}

// ── Authorization Code exchange ───────────────────────────────────────────────

async fn handle_authorization_code(
    state: &OAuthState,
    req: TokenRequest,
    _headers: &HeaderMap,
) -> Response {
    let code = match req.code.as_deref() {
        Some(c) if !c.is_empty() => c.to_string(),
        _ => return oauth_error_response(OAuthError::InvalidRequest("code is required".to_string())),
    };
    let redirect_uri = match req.redirect_uri.as_deref() {
        Some(u) if !u.is_empty() => u.to_string(),
        _ => return oauth_error_response(OAuthError::InvalidRequest("redirect_uri is required".to_string())),
    };
    let code_verifier = match req.code_verifier.as_deref() {
        Some(v) if !v.is_empty() => v.to_string(),
        _ => return oauth_error_response(OAuthError::InvalidRequest("code_verifier is required".to_string())),
    };
    let client_id = match req.client_id.as_deref() {
        Some(id) if !id.is_empty() => id.to_string(),
        _ => return oauth_error_response(OAuthError::InvalidClient),
    };

    // Validate code_verifier format
    if let Err(e) = validate_code_verifier(&code_verifier) {
        return oauth_error_response(e);
    }

    // Load client
    let repo = OAuthClientRepository::new(state.db_pool.clone());
    let client = match repo.find_by_client_id(&client_id).await {
        Ok(Some(c)) => c,
        Ok(None) => return oauth_error_response(OAuthError::InvalidClient),
        Err(e) => return oauth_error_response(e),
    };

    if !client.is_active() {
        return oauth_error_response(OAuthError::UnauthorizedClient);
    }

    // Verify client secret for confidential clients
    if client.client_type == ClientType::Confidential {
        let secret = match req.client_secret.as_deref() {
            Some(s) if !s.is_empty() => s,
            _ => return oauth_error_response(OAuthError::InvalidClient),
        };
        if !verify_client_secret(secret, client.client_secret_hash.as_deref()) {
            return oauth_error_response(OAuthError::InvalidClient);
        }
    }

    // Consume authorization code (single-use)
    let auth_code = match consume_auth_code(&state.redis_cache, &code).await {
        Ok(Some(ac)) => ac,
        Ok(None) => return oauth_error_response(OAuthError::InvalidGrant("authorization code is invalid or already used".to_string())),
        Err(e) => return oauth_error_response(e),
    };

    // Validate code hasn't expired
    if auth_code.is_expired() {
        return oauth_error_response(OAuthError::InvalidGrant("authorization code has expired".to_string()));
    }

    // Validate client_id matches
    if auth_code.client_id != client_id {
        return oauth_error_response(OAuthError::InvalidGrant("client_id mismatch".to_string()));
    }

    // Validate redirect_uri matches
    if auth_code.redirect_uri != redirect_uri {
        return oauth_error_response(OAuthError::InvalidGrant("redirect_uri mismatch".to_string()));
    }

    // Verify PKCE
    if let Err(e) = verify_pkce_s256(&code_verifier, &auth_code.code_challenge) {
        return oauth_error_response(e);
    }

    let scope_str = scope_vec_to_string(&auth_code.scope);

    // Issue access token
    let (access_token, claims) = match generate_access_token(
        &state.key_pair,
        TokenParams {
            issuer: &state.issuer,
            subject: &auth_code.subject,
            audience: vec!["aframp-api".to_string()],
            scope: &scope_str,
            client_id: &client_id,
            consumer_type: "user",
            ttl_secs: ACCESS_TOKEN_TTL_SECS,
        },
    ) {
        Ok(t) => t,
        Err(e) => return oauth_error_response(e),
    };

    // Issue refresh token
    let refresh_jti = Uuid::new_v4().to_string();
    let (refresh_token_str, _refresh_claims) = match generate_access_token(
        &state.key_pair,
        TokenParams {
            issuer: &state.issuer,
            subject: &auth_code.subject,
            audience: vec!["aframp-api".to_string()],
            scope: &scope_str,
            client_id: &client_id,
            consumer_type: "user",
            ttl_secs: REFRESH_TOKEN_TTL_SECS,
        },
    ) {
        Ok(t) => t,
        Err(e) => return oauth_error_response(e),
    };

    // Store refresh token in Redis
    let record = OAuthRefreshRecord {
        client_id: client_id.clone(),
        subject: auth_code.subject.clone(),
        scope: scope_str.clone(),
        issued_at: Utc::now().timestamp(),
    };
    if let Err(e) = store_refresh_token(&state.redis_cache, &refresh_jti, &record).await {
        return oauth_error_response(e);
    }

    Json(TokenResponse {
        access_token,
        token_type: "Bearer",
        expires_in: ACCESS_TOKEN_TTL_SECS,
        scope: scope_str,
        refresh_token: Some(refresh_token_str),
    })
    .into_response()
}

// ── Client Credentials flow ───────────────────────────────────────────────────

async fn handle_client_credentials(
    state: &OAuthState,
    req: TokenRequest,
    _headers: &HeaderMap,
) -> Response {
    let client_id = match req.client_id.as_deref() {
        Some(id) if !id.is_empty() => id.to_string(),
        _ => return oauth_error_response(OAuthError::InvalidClient),
    };
    let client_secret = match req.client_secret.as_deref() {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => return oauth_error_response(OAuthError::InvalidClient),
    };

    let repo = OAuthClientRepository::new(state.db_pool.clone());
    let client = match repo.find_by_client_id(&client_id).await {
        Ok(Some(c)) => c,
        Ok(None) => return oauth_error_response(OAuthError::InvalidClient),
        Err(e) => return oauth_error_response(e),
    };

    if !client.is_active() {
        return oauth_error_response(OAuthError::UnauthorizedClient);
    }

    if client.client_type != ClientType::Confidential {
        return oauth_error_response(OAuthError::UnauthorizedClient);
    }

    if !client.supports_grant(&GrantType::ClientCredentials) {
        return oauth_error_response(OAuthError::UnauthorizedClient);
    }

    if !verify_client_secret(&client_secret, client.client_secret_hash.as_deref()) {
        return oauth_error_response(OAuthError::InvalidClient);
    }

    // Scope downscoping: requested ⊆ allowed
    let granted_scopes = if let Some(scope_str) = &req.scope {
        let requested = parse_scope_string(scope_str);
        if let Err(e) = client.validate_scopes(&requested) {
            return oauth_error_response(e);
        }
        requested
    } else {
        client.allowed_scopes.clone()
    };

    let scope_str = scope_vec_to_string(&granted_scopes);

    let (access_token, _) = match generate_access_token(
        &state.key_pair,
        TokenParams {
            issuer: &state.issuer,
            subject: &client_id,
            audience: vec!["aframp-api".to_string()],
            scope: &scope_str,
            client_id: &client_id,
            consumer_type: "service",
            ttl_secs: ACCESS_TOKEN_TTL_SECS,
        },
    ) {
        Ok(t) => t,
        Err(e) => return oauth_error_response(e),
    };

    Json(TokenResponse {
        access_token,
        token_type: "Bearer",
        expires_in: ACCESS_TOKEN_TTL_SECS,
        scope: scope_str,
        refresh_token: None,
    })
    .into_response()
}

// ── Refresh Token flow ────────────────────────────────────────────────────────

async fn handle_refresh_token(
    state: &OAuthState,
    req: TokenRequest,
    _headers: &HeaderMap,
) -> Response {
    let refresh_token_str = match req.refresh_token.as_deref() {
        Some(t) if !t.is_empty() => t.to_string(),
        _ => return oauth_error_response(OAuthError::InvalidRequest("refresh_token is required".to_string())),
    };

    // Validate the refresh token JWT
    let claims = match validate_access_token(&refresh_token_str, &state.key_pair, &state.issuer) {
        Ok(c) => c,
        Err(e) => return oauth_error_response(e),
    };

    // Check not blacklisted
    match is_token_blacklisted(&state.redis_cache, &claims.jti).await {
        Ok(true) => return oauth_error_response(OAuthError::InvalidGrant("refresh token has been revoked".to_string())),
        Err(e) => return oauth_error_response(e),
        Ok(false) => {}
    }

    // Verify the refresh record still exists in Redis
    match get_refresh_token(&state.redis_cache, &claims.jti).await {
        Ok(None) => return oauth_error_response(OAuthError::InvalidGrant("refresh token not found or expired".to_string())),
        Err(e) => return oauth_error_response(e),
        Ok(Some(_)) => {}
    }

    // Revoke old refresh token (rotation)
    if let Err(e) = revoke_refresh_token(&state.redis_cache, &claims.jti).await {
        return oauth_error_response(e);
    }

    // Issue new access token
    let (new_access_token, _) = match generate_access_token(
        &state.key_pair,
        TokenParams {
            issuer: &state.issuer,
            subject: &claims.sub,
            audience: claims.aud.clone(),
            scope: &claims.scope,
            client_id: &claims.client_id,
            consumer_type: &claims.consumer_type,
            ttl_secs: ACCESS_TOKEN_TTL_SECS,
        },
    ) {
        Ok(t) => t,
        Err(e) => return oauth_error_response(e),
    };

    // Issue new refresh token
    let new_refresh_jti = Uuid::new_v4().to_string();
    let (new_refresh_token, _new_refresh_claims) = match generate_access_token(
        &state.key_pair,
        TokenParams {
            issuer: &state.issuer,
            subject: &claims.sub,
            audience: claims.aud.clone(),
            scope: &claims.scope,
            client_id: &claims.client_id,
            consumer_type: &claims.consumer_type,
            ttl_secs: REFRESH_TOKEN_TTL_SECS,
        },
    ) {
        Ok(t) => t,
        Err(e) => return oauth_error_response(e),
    };

    let record = OAuthRefreshRecord {
        client_id: claims.client_id.clone(),
        subject: claims.sub.clone(),
        scope: claims.scope.clone(),
        issued_at: Utc::now().timestamp(),
    };
    if let Err(e) = store_refresh_token(&state.redis_cache, &new_refresh_jti, &record).await {
        return oauth_error_response(e);
    }

    Json(TokenResponse {
        access_token: new_access_token,
        token_type: "Bearer",
        expires_in: ACCESS_TOKEN_TTL_SECS,
        scope: claims.scope,
        refresh_token: Some(new_refresh_token),
    })
    .into_response()
}

// ── Token introspection (POST /oauth/token/introspect) ────────────────────────

#[derive(Debug, Deserialize)]
pub struct IntrospectRequest {
    pub token: String,
}

pub async fn introspect_token(
    State(state): State<Arc<OAuthState>>,
    Json(req): Json<IntrospectRequest>,
) -> Response {
    if req.token.trim().is_empty() {
        return oauth_error_response(OAuthError::InvalidRequest("token is required".to_string()));
    }

    let claims = match validate_access_token(&req.token, &state.key_pair, &state.issuer) {
        Ok(c) => c,
        Err(_) => return Json(IntrospectionResponse::inactive()).into_response(),
    };

    // Check blacklist
    match is_token_blacklisted(&state.redis_cache, &claims.jti).await {
        Ok(true) => return Json(IntrospectionResponse::inactive()).into_response(),
        _ => {}
    }

    Json(IntrospectionResponse::from_claims(claims)).into_response()
}

// ── Token revocation (POST /oauth/token/revoke) ───────────────────────────────

#[derive(Debug, Deserialize)]
pub struct RevokeRequest {
    pub token: String,
    pub client_id: String,
    pub client_secret: Option<String>,
}

pub async fn revoke_token(
    State(state): State<Arc<OAuthState>>,
    Json(req): Json<RevokeRequest>,
) -> Response {
    // Authenticate the client
    let repo = OAuthClientRepository::new(state.db_pool.clone());
    let client = match repo.find_by_client_id(&req.client_id).await {
        Ok(Some(c)) => c,
        Ok(None) => return oauth_error_response(OAuthError::InvalidClient),
        Err(e) => return oauth_error_response(e),
    };

    if client.client_type == ClientType::Confidential {
        let secret = match req.client_secret.as_deref() {
            Some(s) => s,
            None => return oauth_error_response(OAuthError::InvalidClient),
        };
        if !verify_client_secret(secret, client.client_secret_hash.as_deref()) {
            return oauth_error_response(OAuthError::InvalidClient);
        }
    }

    // Per RFC 7009: invalid tokens return 200 (don't leak info)
    let claims = match validate_access_token(&req.token, &state.key_pair, &state.issuer) {
        Ok(c) => c,
        Err(_) => return (StatusCode::OK, Json(serde_json::json!({ "revoked": true }))).into_response(),
    };

    let remaining = (claims.exp - Utc::now().timestamp()).max(0) as u64;
    let _ = blacklist_token(&state.redis_cache, &claims.jti, remaining).await;
    // Also revoke as refresh token if it exists
    let _ = revoke_refresh_token(&state.redis_cache, &claims.jti).await;

    (StatusCode::OK, Json(serde_json::json!({ "revoked": true }))).into_response()
}

// ── JWKS endpoint (GET /oauth/.well-known/jwks.json) ─────────────────────────

pub async fn jwks(State(state): State<Arc<OAuthState>>) -> Response {
    let jwk_set = JwkSet {
        keys: vec![state.key_pair.to_jwk()],
    };
    Json(jwk_set).into_response()
}

// ── Discovery document (GET /oauth/.well-known/openid-configuration) ──────────

pub async fn discovery(State(state): State<Arc<OAuthState>>) -> Response {
    let doc = serde_json::json!({
        "issuer": state.issuer,
        "authorization_endpoint": format!("{}/oauth/authorize", state.issuer),
        "token_endpoint": format!("{}/oauth/token", state.issuer),
        "jwks_uri": format!("{}/oauth/.well-known/jwks.json", state.issuer),
        "introspection_endpoint": format!("{}/oauth/token/introspect", state.issuer),
        "revocation_endpoint": format!("{}/oauth/token/revoke", state.issuer),
        "registration_endpoint": format!("{}/api/developer/oauth/clients", state.issuer),
        "response_types_supported": ["code"],
        "grant_types_supported": [
            "authorization_code",
            "client_credentials",
            "refresh_token"
        ],
        "token_endpoint_auth_methods_supported": [
            "client_secret_post",
            "none"
        ],
        "scopes_supported": SUPPORTED_SCOPES,
        "id_token_signing_alg_values_supported": ["RS256"],
        "code_challenge_methods_supported": ["S256"],
        "subject_types_supported": ["public"],
    });
    Json(doc).into_response()
}

// ── Crypto helpers ────────────────────────────────────────────────────────────

/// Generate a cryptographically random client secret (32 bytes → 64 hex chars).
fn generate_client_secret() -> String {
    use std::collections::hash_map::DefaultHasher;
    // Use UUID v4 entropy (two UUIDs = 256 bits)
    format!(
        "{}{}",
        Uuid::new_v4().simple(),
        Uuid::new_v4().simple()
    )
}

/// Hash a client secret with SHA-256.
fn hash_secret(secret: &str) -> String {
    let hash = Sha256::digest(secret.as_bytes());
    hex::encode(hash)
}

/// Verify a client secret against its stored hash.
fn verify_client_secret(secret: &str, stored_hash: Option<&str>) -> bool {
    match stored_hash {
        Some(hash) => hash_secret(secret) == hash,
        None => false,
    }
}

/// Generate a cryptographically random authorization code.
fn generate_auth_code() -> String {
    format!("code_{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}

// Crypto helpers use hex from the existing dep
