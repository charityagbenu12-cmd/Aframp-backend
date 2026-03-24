//! API key authentication and scope enforcement middleware (Issue #132).
//!
//! Usage:
//!   Wrap routes that require a specific scope with `require_scope(pool, "scope:name")`.
//!   The middleware extracts the `Authorization: Bearer <key>` header, looks up the key,
//!   checks that the required scope is granted, and either proceeds or returns 403.
//!
//!   A missing or invalid key always returns 401.
//!   A valid key that lacks the required scope always returns 403 (never 401).

use axum::{
    body::Body,
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::sync::Arc;
use tracing::{debug, info, warn};
use uuid::Uuid;

// ─── Error Responses ─────────────────────────────────────────────────────────

#[derive(Serialize)]
struct AuthError {
    error: AuthErrorDetail,
}

#[derive(Serialize)]
struct AuthErrorDetail {
    code: String,
    message: String,
}

fn unauthorized(code: &str, message: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(AuthError {
            error: AuthErrorDetail {
                code: code.to_string(),
                message: message.to_string(),
            },
        }),
    )
        .into_response()
}

fn forbidden(scope: &str, endpoint: &str) -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(AuthError {
            error: AuthErrorDetail {
                code: "INSUFFICIENT_SCOPE".to_string(),
                message: format!(
                    "API key does not have the required scope '{}' for endpoint '{}'",
                    scope, endpoint
                ),
            },
        }),
    )
        .into_response()
}

// ─── Key Lookup ───────────────────────────────────────────────────────────────

/// Hashes a raw API key using SHA-256 — matches what is stored in api_keys.key_hash.
fn hash_key(raw_key: &str) -> String {
    let digest = Sha256::digest(raw_key.as_bytes());
    hex::encode(digest)
}

/// Resolved API key context — attached to request extensions after successful auth.
#[derive(Clone, Debug)]
pub struct AuthenticatedKey {
    pub key_id: Uuid,
    pub consumer_id: Uuid,
    pub consumer_type: String,
    pub scopes: Vec<String>,
}

/// Look up a raw API key in the database and return its granted scopes.
/// Returns `None` if the key does not exist or is inactive/expired.
pub async fn resolve_api_key(pool: &PgPool, raw_key: &str) -> Option<AuthenticatedKey> {
    let hash = hash_key(raw_key);

    let row = sqlx::query!(
        r#"
        SELECT
            ak.id          AS key_id,
            c.id           AS consumer_id,
            c.consumer_type,
            ARRAY_AGG(ks.scope_name ORDER BY ks.scope_name) FILTER (WHERE ks.scope_name IS NOT NULL)
                           AS scopes
        FROM api_keys ak
        JOIN consumers c ON c.id = ak.consumer_id
        LEFT JOIN key_scopes ks ON ks.api_key_id = ak.id
        WHERE ak.key_hash = $1
          AND ak.is_active = TRUE
          AND c.is_active  = TRUE
          AND (ak.expires_at IS NULL OR ak.expires_at > now())
        GROUP BY ak.id, c.id, c.consumer_type
        "#,
        hash
    )
    .fetch_optional(pool)
    .await
    .ok()??;

    // Update last_used_at asynchronously (best-effort, don't block auth)
    let pool_clone = pool.clone();
    let key_id = row.key_id;
    tokio::spawn(async move {
        let _ = sqlx::query!(
            "UPDATE api_keys SET last_used_at = now() WHERE id = $1",
            key_id
        )
        .execute(&pool_clone)
        .await;
    });

    Some(AuthenticatedKey {
        key_id: row.key_id,
        consumer_id: row.consumer_id,
        consumer_type: row.consumer_type,
        scopes: row.scopes.unwrap_or_default(),
    })
}

// ─── Middleware ───────────────────────────────────────────────────────────────

/// Extract the raw API key from the `Authorization: Bearer <key>` header.
fn extract_bearer(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get("authorization")?.to_str().ok()?;
    value.strip_prefix("Bearer ")
}

/// Axum middleware that:
/// 1. Extracts the bearer token from the request.
/// 2. Resolves it against the database.
/// 3. Checks that `required_scope` is in the granted scope list.
/// 4. Injects `AuthenticatedKey` into request extensions on success.
///
/// Returns 401 for missing/invalid keys, 403 for valid keys without the required scope.
pub async fn scope_guard(
    State((pool, required_scope)): State<(Arc<PgPool>, &'static str)>,
    mut req: Request<Body>,
    next: Next,
) -> Response {
    let endpoint = req.uri().path().to_string();

    let raw_key = match extract_bearer(req.headers()) {
        Some(k) => k.to_string(),
        None => {
            debug!("No bearer token on request to {}", endpoint);
            return unauthorized("MISSING_API_KEY", "Authorization header with Bearer token is required");
        }
    };

    let auth = match resolve_api_key(&pool, &raw_key).await {
        Some(a) => a,
        None => {
            warn!(endpoint = %endpoint, "Invalid or expired API key");
            return unauthorized("INVALID_API_KEY", "The provided API key is invalid or has expired");
        }
    };

    if !auth.scopes.contains(&required_scope.to_string()) {
        warn!(
            consumer_id = %auth.consumer_id,
            key_id = %auth.key_id,
            required_scope = %required_scope,
            endpoint = %endpoint,
            "Scope denied"
        );

        // Log denial in audit table (best-effort)
        let pool_clone = pool.clone();
        let key_id = auth.key_id;
        let consumer_id = auth.consumer_id;
        let scope = required_scope.to_string();
        let ep = endpoint.clone();
        tokio::spawn(async move {
            let _ = sqlx::query!(
                r#"
                INSERT INTO scope_audit_log (api_key_id, consumer_id, action, scope_name, endpoint)
                VALUES ($1, $2, 'denied', $3, $4)
                "#,
                key_id,
                consumer_id,
                scope,
                ep
            )
            .execute(&pool_clone)
            .await;
        });

        return forbidden(required_scope, &endpoint);
    }

    info!(
        consumer_id = %auth.consumer_id,
        key_id = %auth.key_id,
        scope = %required_scope,
        endpoint = %endpoint,
        "API key authorized"
    );

    req.extensions_mut().insert(auth);
    next.run(req).await
}

// ─── Helper: Require Multiple Scopes ─────────────────────────────────────────

/// Validate that an already-resolved `AuthenticatedKey` holds ALL of the given scopes.
/// Returns `Ok(())` on success or a 403 `Response` on the first missing scope.
pub fn require_all_scopes(
    auth: &AuthenticatedKey,
    scopes: &[&str],
    endpoint: &str,
) -> Result<(), Response> {
    for scope in scopes {
        if !auth.scopes.contains(&scope.to_string()) {
            return Err(forbidden(scope, endpoint));
        }
    }
    Ok(())
}
