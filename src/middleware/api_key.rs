//! API key authentication, scope enforcement, and expiry management (Issues #132, #137).
//!
//! Changes in Issue #137:
//!   - Expired keys return 401 with code `KEY_EXPIRED` (distinct from `INVALID_API_KEY`)
//!   - Keys within an active grace period pass with `X-Key-Deprecation-Warning` header
//!   - Every expired-key rejection is logged with consumer_id, key_id, expiry, and request time
//! API key authentication and scope enforcement middleware (Issue #131 / #132).
//!
//! Verification flow:
//!   1. Extract `Authorization: Bearer <key>` or `X-API-Key: <key>` header.
//!   2. Derive the 8-char prefix from the raw key for fast index lookup.
//!   3. Fetch all active keys sharing that prefix + environment from DB.
//!   4. Verify the raw key against each candidate's Argon2id hash.
//!   5. Reject keys scoped to the wrong environment.
//!   6. Check required scope is granted.
//!   7. Update last_used_at asynchronously (non-blocking).
//!   8. Inject `AuthenticatedKey` into request extensions.
//!
//! Security guarantees:
//!   - 401 is returned for any verification failure — never reveals whether
//!     the key ID exists.
//!   - Plaintext key is never logged at any level.
//!   - last_used_at update is fire-and-forget (does not block the request).

use axum::{
    body::Body,
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use chrono::Utc;
use serde::Serialize;
use sqlx::PgPool;
use std::sync::Arc;
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::api_keys::{generator::verify_api_key, repository::ApiKeyRepository};

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

fn hash_key(raw_key: &str) -> String {
    let digest = Sha256::digest(raw_key.as_bytes());
    hex::encode(digest)
}
// ─── Resolved Key Context ─────────────────────────────────────────────────────

/// Injected into request extensions after successful authentication.
#[derive(Clone, Debug)]
pub struct AuthenticatedKey {
    pub key_id: Uuid,
    pub consumer_id: Uuid,
    pub consumer_type: String,
    pub environment: String,
    pub scopes: Vec<String>,
    /// Set when the key is an old key within an active grace period.
    pub grace_period_warning: Option<String>,
}

/// Outcome of a key lookup — distinguishes expired from invalid.
enum LookupResult {
    Valid(AuthenticatedKey),
    /// Key exists but has passed its `expires_at` timestamp.
    Expired {
        key_id: Uuid,
        consumer_id: Uuid,
        expires_at: chrono::DateTime<Utc>,
    },
    /// Key is within an active grace period (old key after rotation).
    GracePeriod {
        auth: AuthenticatedKey,
        grace_end: chrono::DateTime<Utc>,
    },
    NotFound,
}

/// Full key resolution with expiry and grace period awareness.
async fn resolve_api_key_full(pool: &PgPool, raw_key: &str) -> LookupResult {
    let hash = hash_key(raw_key);

    // 1. Look up the key regardless of expiry so we can distinguish expired vs invalid.
    let row = sqlx::query!(
        r#"
        SELECT
            ak.id          AS key_id,
            ak.is_active,
            ak.expires_at,
            c.id           AS consumer_id,
            c.consumer_type,
            c.is_active    AS consumer_active,
            ARRAY_AGG(ks.scope_name ORDER BY ks.scope_name)
                FILTER (WHERE ks.scope_name IS NOT NULL) AS scopes
        FROM api_keys ak
        JOIN consumers c ON c.id = ak.consumer_id
        LEFT JOIN key_scopes ks ON ks.api_key_id = ak.id
        WHERE ak.key_hash = $1
          AND c.is_active = TRUE
        GROUP BY ak.id, ak.is_active, ak.expires_at, c.id, c.consumer_type, c.is_active
        "#,
        hash
    )
    .fetch_optional(pool)
    .await;

    match row {
        Err(_) => LookupResult::NotFound,
        Ok(None) => LookupResult::NotFound,
        Ok(Some(r)) => {
            let now = Utc::now();
            if !r.is_active {
                return LookupResult::NotFound;
            }
            if let Some(exp) = r.expires_at {
                if exp < now {
                    let grace_end = exp + chrono::Duration::hours(24);
                    return LookupResult::Expired {
                        auth: AuthenticatedKey {
                            key_id: r.key_id,
                            consumer_id: r.consumer_id,
                            consumer_type: r.consumer_type,
                            scopes: r.scopes.unwrap_or_default(),
                            environment: String::new(),
                        },
                        grace_end,
                    };
                }
            }
            LookupResult::Valid(AuthenticatedKey {
                key_id: r.key_id,
                consumer_id: r.consumer_id,
                consumer_type: r.consumer_type,
                scopes: r.scopes.unwrap_or_default(),
                environment: String::new(),
            })
        }
    }
}

// ─── Key Extraction ───────────────────────────────────────────────────────────

/// Extract the raw API key from `Authorization: Bearer <key>` or `X-API-Key: <key>`.
fn extract_raw_key(headers: &HeaderMap) -> Option<String> {
    // Prefer Authorization: Bearer
    if let Some(bearer) = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
    {
        return Some(bearer.to_string());
    }
    // Fall back to X-API-Key
    headers
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

// ─── Key Resolution ───────────────────────────────────────────────────────────

/// Resolve a raw API key against the database using Argon2id verification.
///
/// Returns `None` if the key is invalid, expired, revoked, or environment-mismatched.
/// Never reveals which specific check failed to the caller.
pub async fn resolve_api_key(
    pool: &PgPool,
    raw_key: &str,
    expected_environment: &str,
) -> Option<AuthenticatedKey> {
    if raw_key.len() < 8 {
        return None;
    }

    // Derive prefix for fast index lookup (first 8 chars of the full key)
    let key_prefix: String = raw_key.chars().take(8).collect();

    let repo = ApiKeyRepository::new(pool.clone());

    // Fetch candidates by prefix + environment (uses idx_api_keys_prefix_status)
    let candidates = repo
        .find_active_by_prefix(&key_prefix, expected_environment)
        .await
        .ok()?;

    // Argon2id verify against each candidate (usually just one)
    let matched = candidates
        .into_iter()
        .find(|k| verify_api_key(raw_key, &k.key_hash))?;

    // Environment double-check (belt-and-suspenders — already filtered in query)
    if matched.environment != expected_environment {
        warn!(
            key_id = %matched.id,
            key_env = %matched.environment,
            expected_env = %expected_environment,
            "Environment mismatch on API key"
        );
        return None;
    }

    // Fetch granted scopes
    let scopes: Vec<String> = sqlx::query_scalar!(
        "SELECT scope_name FROM key_scopes WHERE api_key_id = $1 ORDER BY scope_name",
        matched.id
    )
    .fetch_all(pool)
    .await
    .ok()
    .unwrap_or_default();

    // Fetch consumer type
    let consumer_type: String = sqlx::query_scalar!(
        "SELECT consumer_type FROM consumers WHERE id = $1",
        matched.consumer_id
    )
    .fetch_optional(pool)
    .await
    .ok()
    .flatten();

    let row = match row {
        Some(r) => r,
        None => return LookupResult::NotFound,
    };

    let now = Utc::now();

    // 2. Check expiry.
    if let Some(expires_at) = row.expires_at {
        if expires_at <= now {
            // Key is expired — check if it's within a grace period.
            let grace_end = crate::services::key_rotation::check_grace_period(pool, row.key_id).await;
            if let Some(grace_end) = grace_end {
                // Still valid under grace period.
                let auth = AuthenticatedKey {
                    key_id: row.key_id,
                    consumer_id: row.consumer_id,
                    consumer_type: row.consumer_type,
                    scopes: row.scopes.unwrap_or_default(),
                    grace_period_warning: Some(format!(
                        "This API key has been rotated. Please migrate to the new key before {}",
                        grace_end.format("%Y-%m-%dT%H:%M:%SZ")
                    )),
                };
                return LookupResult::GracePeriod { auth, grace_end };
            }
            return LookupResult::Expired {
                key_id: row.key_id,
                consumer_id: row.consumer_id,
                expires_at,
            };
        }
    }

    // 3. Check is_active (deactivated by rotation completion or admin).
    if !row.is_active {
        // Could be an old key that was explicitly completed — treat as expired.
        return LookupResult::Expired {
            key_id: row.key_id,
            consumer_id: row.consumer_id,
            expires_at: row.expires_at.unwrap_or(now),
        };
    }

    // 4. Valid key — update last_used_at asynchronously.
    .flatten()
    .unwrap_or_default();

    // Update last_used_at asynchronously — does not block the request
    let pool_clone = pool.clone();
    let key_id = matched.id;
    tokio::spawn(async move {
        let _ = sqlx::query!(
            "UPDATE api_keys SET last_used_at = now() WHERE id = $1",
            key_id
        )
        .execute(&pool_clone)
        .await;
    });

    LookupResult::Valid(AuthenticatedKey {
        key_id: row.key_id,
        consumer_id: row.consumer_id,
        consumer_type: row.consumer_type,
        scopes: row.scopes.unwrap_or_default(),
        grace_period_warning: None,
    Some(AuthenticatedKey {
        key_id: matched.id,
        consumer_id: matched.consumer_id,
        consumer_type,
        environment: matched.environment,
        scopes,
    })
}

/// Simplified lookup used by existing code paths (returns None for expired/invalid).
pub async fn resolve_api_key(pool: &PgPool, raw_key: &str) -> Option<AuthenticatedKey> {
    match resolve_api_key_full(pool, raw_key).await {
        LookupResult::Valid(auth) | LookupResult::GracePeriod { auth, .. } => Some(auth),
        _ => None,
    }
}

// ─── Middleware ───────────────────────────────────────────────────────────────

fn extract_bearer(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get("authorization")?.to_str().ok()?;
    value.strip_prefix("Bearer ")
}

/// Axum middleware with full expiry and grace period enforcement (Issue #137).
/// Axum middleware that enforces API key authentication and a required scope.
///
/// State: `(Arc<PgPool>, &'static str /* required_scope */, &'static str /* environment */)`
pub async fn scope_guard(
    State((pool, required_scope, environment)): State<(Arc<PgPool>, &'static str, &'static str)>,
    mut req: Request<Body>,
    next: Next,
) -> Response {
    let endpoint = req.uri().path().to_string();

    let raw_key = match extract_raw_key(req.headers()) {
        Some(k) => k,
        None => {
            debug!("No bearer token on request to {}", endpoint);
            return unauthorized(
                "MISSING_API_KEY",
                "Authorization header with Bearer token is required",
            );
        }
    };

    let lookup = resolve_api_key_full(&pool, &raw_key).await;

    let auth = match lookup {
        LookupResult::Valid(auth) => auth,

        LookupResult::GracePeriod { auth, grace_end } => {
            warn!(
                consumer_id = %auth.consumer_id,
                key_id = %auth.key_id,
                grace_period_end = %grace_end,
                endpoint = %endpoint,
                "Request using deprecated key within grace period"
            );
            auth
        }

        LookupResult::Expired { key_id, consumer_id, expires_at } => {
            warn!(
                consumer_id = %consumer_id,
                key_id = %key_id,
                expires_at = %expires_at,
                request_time = %Utc::now(),
                endpoint = %endpoint,
                "Rejected expired API key"
            );
            // Log to scope_audit_log for observability.
            let pool_clone = pool.clone();
            let ep = endpoint.clone();
            tokio::spawn(async move {
                let _ = sqlx::query!(
                    r#"
                    INSERT INTO scope_audit_log
                        (api_key_id, consumer_id, action, scope_name, endpoint)
                    VALUES ($1, $2, 'denied', 'expired_key', $3)
                    "#,
                    key_id,
                    consumer_id,
                    ep,
                )
                .execute(&pool_clone)
                .await;
            });
            return unauthorized(
                "KEY_EXPIRED",
                &format!(
                    "API key expired at {}. Please rotate your key.",
                    expires_at.format("%Y-%m-%dT%H:%M:%SZ")
                ),
            );
        }

        LookupResult::NotFound => {
            warn!(endpoint = %endpoint, "Invalid API key");
            return unauthorized(
                "INVALID_API_KEY",
                "The provided API key is invalid",
            );
            debug!(endpoint = %endpoint, "No API key on request");
            return unauthorized(
                "MISSING_API_KEY",
                "Authorization header with Bearer token or X-API-Key header is required",
            );
        }
    };

    let auth = match resolve_api_key(&pool, &raw_key, environment).await {
        Some(a) => a,
        None => {
            // Generic 401 — never reveal whether the key exists
            warn!(endpoint = %endpoint, "Invalid, expired, or wrong-environment API key");
            return unauthorized("INVALID_API_KEY", "Invalid or expired API key");
        }
    };

    // Scope check.
    if !auth.scopes.contains(&required_scope.to_string()) {
        warn!(
            consumer_id = %auth.consumer_id,
            key_id = %auth.key_id,
            required_scope = %required_scope,
            endpoint = %endpoint,
            "Scope denied"
        );

        // Audit denial asynchronously
        let pool_clone = pool.clone();
        let key_id = auth.key_id;
        let consumer_id = auth.consumer_id;
        let scope = required_scope.to_string();
        let ep = endpoint.clone();
        let env = environment.to_string();
        tokio::spawn(async move {
            let _ = sqlx::query!(
                r#"
                INSERT INTO api_key_audit_log
                    (event_type, api_key_id, consumer_id, environment, endpoint, rejection_reason)
                VALUES ('rejected', $1, $2, $3, $4, $5)
                "#,
                key_id,
                consumer_id,
                env,
                ep,
                format!("missing scope: {}", scope),
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
        environment = %environment,
        endpoint = %endpoint,
        "API key authorized"
    );

    // Attach deprecation warning header for grace-period keys.
    let grace_warning = auth.grace_period_warning.clone();
    req.extensions_mut().insert(auth);
    let mut response = next.run(req).await;

    if let Some(warning) = grace_warning {
        if let Ok(val) = HeaderValue::from_str(&warning) {
            response.headers_mut().insert("X-Key-Deprecation-Warning", val);
        }
    }

    response
}

// ─── Helper ───────────────────────────────────────────────────────────────────

/// Validate that an already-resolved `AuthenticatedKey` holds ALL of the given scopes.
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
