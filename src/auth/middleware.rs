//! Axum middleware for JWT authentication and scope enforcement.
//!
//! Usage:
//!   - `require_auth`  – validates the Bearer token and injects `TokenClaims` into extensions
//!   - `require_admin` – same as above but also asserts `scope == "admin"`

use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use chrono::Utc;
use serde_json::json;

use super::jwt::{validate_token, JwtError, Scope, TokenClaims};
use crate::cache::{Cache, RedisCache};

// ── Shared auth state ─────────────────────────────────────────────────────────

/// Minimal state required by the auth middleware.
/// Embed this (or the fields) in your `AppState`.
#[derive(Clone)]
pub struct AuthState {
    pub jwt_secret: String,
    pub redis_cache: Option<RedisCache>,
}

// ── Error → Response mapping ──────────────────────────────────────────────────

fn jwt_error_response(err: JwtError) -> Response {
    let (status, code, message, extra) = match &err {
        JwtError::MissingToken => (
            StatusCode::UNAUTHORIZED,
            "MISSING_TOKEN",
            "Authentication token required",
            None,
        ),
        JwtError::InvalidToken => (
            StatusCode::UNAUTHORIZED,
            "INVALID_TOKEN",
            "Invalid authentication token",
            None,
        ),
        JwtError::TokenExpired => (
            StatusCode::UNAUTHORIZED,
            "TOKEN_EXPIRED",
            "Token has expired. Please refresh or re-authenticate.",
            Some(json!({ "expired_at": Utc::now().to_rfc3339() })),
        ),
        JwtError::TokenRevoked => (
            StatusCode::UNAUTHORIZED,
            "TOKEN_REVOKED",
            "Token has been revoked",
            None,
        ),
        JwtError::InsufficientPermissions { required, got } => (
            StatusCode::FORBIDDEN,
            "INSUFFICIENT_PERMISSIONS",
            "This operation requires elevated privileges",
            Some(json!({
                "required_scope": required,
                "your_scope": got,
            })),
        ),
        JwtError::Internal(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "An internal error occurred",
            None,
        ),
    };

    let mut body = json!({
        "error": {
            "code": code,
            "message": message,
        }
    });

    if let Some(details) = extra {
        body["error"]
            .as_object_mut()
            .unwrap()
            .extend(details.as_object().unwrap().clone());
    }

    (status, Json(body)).into_response()
}

// ── Token extraction ──────────────────────────────────────────────────────────

fn extract_bearer(req: &Request) -> Result<&str, JwtError> {
    req.headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or(JwtError::MissingToken)
}

// ── require_auth middleware ───────────────────────────────────────────────────

/// Validates the `Authorization: Bearer <token>` header.
/// On success, injects `TokenClaims` into request extensions.
pub async fn require_auth(
    State(auth): State<AuthState>,
    mut req: Request,
    next: Next,
) -> Response {
    let token = match extract_bearer(&req) {
        Ok(t) => t,
        Err(e) => return jwt_error_response(e),
    };

    let claims = match validate_token(token, &auth.jwt_secret) {
        Ok(c) => c,
        Err(e) => return jwt_error_response(e),
    };

    // For access tokens: optionally check blacklist
    if let (Some(cache), Some(jti)) = (&auth.redis_cache, &claims.jti) {
        match <RedisCache as Cache<String>>::exists(cache, &format!("blacklist:{}", jti)).await {
            Ok(true) => return jwt_error_response(JwtError::TokenRevoked),
            Ok(false) => {}
            Err(_) => {} // graceful degradation – don't block on cache failure
        }
    }

    req.extensions_mut().insert(claims);
    next.run(req).await
}

// ── require_admin middleware ──────────────────────────────────────────────────

/// Same as `require_auth` but additionally enforces `scope == admin`.
pub async fn require_admin(
    State(auth): State<AuthState>,
    mut req: Request,
    next: Next,
) -> Response {
    let token = match extract_bearer(&req) {
        Ok(t) => t,
        Err(e) => return jwt_error_response(e),
    };

    let claims = match validate_token(token, &auth.jwt_secret) {
        Ok(c) => c,
        Err(e) => return jwt_error_response(e),
    };

    if claims.scope != Scope::Admin {
        return jwt_error_response(JwtError::InsufficientPermissions {
            required: "admin".to_string(),
            got: claims.scope.to_string(),
        });
    }

    req.extensions_mut().insert(claims);
    next.run(req).await
}

// ── Helper extractor ──────────────────────────────────────────────────────────

/// Convenience function for handlers to pull the authenticated wallet address
/// from request extensions (set by `require_auth`).
pub fn wallet_from_extensions(req: &Request) -> Option<String> {
    req.extensions()
        .get::<TokenClaims>()
        .map(|c| c.sub.clone())
}
