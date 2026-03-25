//! Developer self-service API key issuance (Issue #131).
//!
//! POST /api/developer/keys  — authenticated developer issues their own key
//! GET  /api/developer/keys  — list own keys
//! DELETE /api/developer/keys/:key_id — revoke own key

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Extension, Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::sync::Arc;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::api_keys::{
    generator::{generate_api_key, KeyEnvironment},
    repository::ApiKeyRepository,
};
use crate::auth::jwt::TokenClaims;

// ─── Config ───────────────────────────────────────────────────────────────────

fn max_keys_per_consumer() -> i64 {
    std::env::var("API_KEY_MAX_PER_CONSUMER")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10)
}

// ─── State ────────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct DeveloperKeysState {
    pub db: Arc<PgPool>,
}

// ─── Request / Response ───────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct SelfServiceIssueRequest {
    /// Consumer ID the developer is issuing a key for (must be their own).
    pub consumer_id: String,
    /// "testnet" | "mainnet"
    pub environment: String,
    pub description: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
pub struct IssueKeyResponse {
    pub key_id: String,
    pub consumer_id: String,
    /// Plaintext key — shown exactly once.
    pub plaintext_key: String,
    pub key_prefix: String,
    pub key_id_prefix: String,
    pub environment: String,
    pub status: String,
    pub description: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub security_notice: String,
}

#[derive(Debug, Serialize)]
pub struct KeySummary {
    pub key_id: String,
    pub consumer_id: String,
    pub key_prefix: String,
    pub key_id_prefix: String,
    pub environment: String,
    pub status: String,
    pub description: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    code: String,
    message: String,
}

fn err(status: StatusCode, code: &str, msg: impl Into<String>) -> Response {
    (
        status,
        Json(ErrorBody {
            code: code.to_string(),
            message: msg.into(),
        }),
    )
        .into_response()
}

// ─── Handlers ─────────────────────────────────────────────────────────────────

/// POST /api/developer/keys
///
/// Authenticated developer issues a key for their own consumer record.
/// The JWT `sub` (wallet address) is used as the issuing identity.
pub async fn issue_key(
    State(state): State<DeveloperKeysState>,
    Extension(claims): Extension<TokenClaims>,
    Json(req): Json<SelfServiceIssueRequest>,
) -> Response {
    let consumer_id = match Uuid::parse_str(&req.consumer_id) {
        Ok(id) => id,
        Err(_) => return err(StatusCode::BAD_REQUEST, "INVALID_CONSUMER_ID", "consumer_id must be a valid UUID"),
    };

    let env = match KeyEnvironment::from_str(&req.environment) {
        Ok(e) => e,
        Err(e) => return err(StatusCode::BAD_REQUEST, "INVALID_ENVIRONMENT", e),
    };

    let repo = ApiKeyRepository::new((*state.db).clone());

    // Verify the consumer belongs to the authenticated wallet
    let consumer = sqlx::query!(
        r#"SELECT id, created_by FROM consumers WHERE id = $1 AND is_active = TRUE"#,
        consumer_id
    )
    .fetch_optional(state.db.as_ref())
    .await;

    match consumer {
        Ok(Some(row)) => {
            // Ownership check: created_by must match the authenticated wallet
            if row.created_by.as_deref() != Some(&claims.sub) {
                warn!(
                    wallet = %claims.sub,
                    consumer_id = %consumer_id,
                    "Developer attempted to issue key for another consumer"
                );
                return err(StatusCode::FORBIDDEN, "FORBIDDEN", "You can only issue keys for your own consumer records");
            }
        }
        Ok(None) => return err(StatusCode::NOT_FOUND, "CONSUMER_NOT_FOUND", "Consumer not found"),
        Err(e) => {
            error!(error = %e, "DB error checking consumer ownership");
            return err(StatusCode::INTERNAL_SERVER_ERROR, "DB_ERROR", "Database error");
        }
    }

    // Enforce max active keys
    match repo.count_active_for_consumer(consumer_id).await {
        Ok(count) if count >= max_keys_per_consumer() => {
            return err(
                StatusCode::UNPROCESSABLE_ENTITY,
                "MAX_KEYS_REACHED",
                format!("Maximum of {} active keys reached", max_keys_per_consumer()),
            );
        }
        Err(e) => {
            error!(error = %e, "Failed to count active keys");
            return err(StatusCode::INTERNAL_SERVER_ERROR, "DB_ERROR", "Database error");
        }
        Ok(_) => {}
    }

    // Generate key
    let generated = match generate_api_key(env) {
        Ok(k) => k,
        Err(e) => {
            error!(error = %e, "Key generation failed");
            return err(StatusCode::INTERNAL_SERVER_ERROR, "KEY_GEN_ERROR", "Failed to generate key");
        }
    };

    // Persist — hash only
    let key = match repo
        .create(
            consumer_id,
            &generated.key_hash,
            &generated.key_prefix,
            &generated.key_id_prefix,
            generated.environment.as_str(),
            req.description.as_deref(),
            Some(&claims.sub),
            req.expires_at,
        )
        .await
    {
        Ok(k) => k,
        Err(e) => {
            error!(error = %e, "Failed to persist API key");
            return err(StatusCode::INTERNAL_SERVER_ERROR, "DB_ERROR", "Failed to store key");
        }
    };

    // Audit log
    let _ = repo
        .log_audit_event(
            "issued",
            Some(key.id),
            Some(consumer_id),
            Some(&claims.sub),
            Some(generated.environment.as_str()),
            None,
            None,
            None,
        )
        .await;

    info!(
        key_id = %key.id,
        consumer_id = %consumer_id,
        wallet = %claims.sub,
        environment = %key.environment,
        "Developer self-service API key issued"
    );

    (
        StatusCode::CREATED,
        Json(IssueKeyResponse {
            key_id: key.id.to_string(),
            consumer_id: consumer_id.to_string(),
            plaintext_key: generated.plaintext_key,
            key_prefix: key.key_prefix,
            key_id_prefix: key.key_id_prefix,
            environment: key.environment,
            status: key.status,
            description: key.description,
            expires_at: key.expires_at,
            created_at: key.created_at,
            security_notice: "Store this key securely. It will not be shown again.".to_string(),
        }),
    )
        .into_response()
}

/// GET /api/developer/keys?consumer_id=<uuid>
pub async fn list_keys(
    State(state): State<DeveloperKeysState>,
    Extension(claims): Extension<TokenClaims>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Response {
    let consumer_id = match params.get("consumer_id").and_then(|s| Uuid::parse_str(s).ok()) {
        Some(id) => id,
        None => return err(StatusCode::BAD_REQUEST, "MISSING_CONSUMER_ID", "consumer_id query param required"),
    };

    // Ownership check
    let owned = sqlx::query_scalar!(
        "SELECT EXISTS(SELECT 1 FROM consumers WHERE id = $1 AND created_by = $2 AND is_active = TRUE)",
        consumer_id,
        claims.sub
    )
    .fetch_one(state.db.as_ref())
    .await;

    match owned {
        Ok(Some(true)) => {}
        Ok(_) => return err(StatusCode::FORBIDDEN, "FORBIDDEN", "Consumer not found or not owned by you"),
        Err(e) => {
            error!(error = %e, "DB error on ownership check");
            return err(StatusCode::INTERNAL_SERVER_ERROR, "DB_ERROR", "Database error");
        }
    }

    let repo = ApiKeyRepository::new((*state.db).clone());
    match repo.list_for_consumer(consumer_id).await {
        Ok(keys) => {
            let summaries: Vec<KeySummary> = keys
                .into_iter()
                .map(|k| KeySummary {
                    key_id: k.id.to_string(),
                    consumer_id: k.consumer_id.to_string(),
                    key_prefix: k.key_prefix,
                    key_id_prefix: k.key_id_prefix,
                    environment: k.environment,
                    status: k.status,
                    description: k.description,
                    expires_at: k.expires_at,
                    last_used_at: k.last_used_at,
                    created_at: k.created_at,
                })
                .collect();
            Json(summaries).into_response()
        }
        Err(e) => {
            error!(error = %e, "Failed to list keys");
            err(StatusCode::INTERNAL_SERVER_ERROR, "DB_ERROR", "Failed to list keys")
        }
    }
}

/// DELETE /api/developer/keys/:key_id?consumer_id=<uuid>
pub async fn revoke_key(
    State(state): State<DeveloperKeysState>,
    Extension(claims): Extension<TokenClaims>,
    Path(key_id): Path<Uuid>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Response {
    let consumer_id = match params.get("consumer_id").and_then(|s| Uuid::parse_str(s).ok()) {
        Some(id) => id,
        None => return err(StatusCode::BAD_REQUEST, "MISSING_CONSUMER_ID", "consumer_id query param required"),
    };

    // Ownership check
    let owned = sqlx::query_scalar!(
        "SELECT EXISTS(SELECT 1 FROM consumers WHERE id = $1 AND created_by = $2 AND is_active = TRUE)",
        consumer_id,
        claims.sub
    )
    .fetch_one(state.db.as_ref())
    .await;

    match owned {
        Ok(Some(true)) => {}
        Ok(_) => return err(StatusCode::FORBIDDEN, "FORBIDDEN", "Consumer not found or not owned by you"),
        Err(e) => {
            error!(error = %e, "DB error on ownership check");
            return err(StatusCode::INTERNAL_SERVER_ERROR, "DB_ERROR", "Database error");
        }
    }

    let repo = ApiKeyRepository::new((*state.db).clone());
    match repo.revoke(key_id, consumer_id).await {
        Ok(key) => {
            let _ = repo
                .log_audit_event(
                    "revoked",
                    Some(key_id),
                    Some(consumer_id),
                    Some(&claims.sub),
                    Some(&key.environment),
                    None,
                    None,
                    None,
                )
                .await;

            info!(key_id = %key_id, wallet = %claims.sub, "Developer revoked API key");

            Json(KeySummary {
                key_id: key.id.to_string(),
                consumer_id: key.consumer_id.to_string(),
                key_prefix: key.key_prefix,
                key_id_prefix: key.key_id_prefix,
                environment: key.environment,
                status: key.status,
                description: key.description,
                expires_at: key.expires_at,
                last_used_at: key.last_used_at,
                created_at: key.created_at,
            })
            .into_response()
        }
        Err(e) if e.is_not_found() => err(StatusCode::NOT_FOUND, "KEY_NOT_FOUND", "Key not found"),
        Err(e) => {
            error!(error = %e, "Failed to revoke key");
            err(StatusCode::INTERNAL_SERVER_ERROR, "DB_ERROR", "Failed to revoke key")
        }
    }
}
