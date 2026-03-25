//! Admin API key issuance endpoints (Issue #131).
//!
//! POST /api/admin/consumers/:consumer_id/keys  — issue a key for a consumer
//! GET  /api/admin/consumers/:consumer_id/keys  — list keys for a consumer
//! DELETE /api/admin/consumers/:consumer_id/keys/:key_id — revoke a key

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
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

// ─── Config ───────────────────────────────────────────────────────────────────

/// Maximum active keys allowed per consumer (configurable via env).
fn max_keys_per_consumer() -> i64 {
    std::env::var("API_KEY_MAX_PER_CONSUMER")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10)
}

// ─── State ────────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct AdminKeysState {
    pub db: Arc<PgPool>,
}

// ─── Request / Response ───────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct IssueKeyRequest {
    /// "testnet" | "mainnet"
    pub environment: String,
    pub description: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    /// Identity of the admin issuing the key (wallet address or admin ID).
    pub issued_by: String,
}

/// Response returned exactly once at issuance.
/// The `plaintext_key` is never retrievable again after this response.
#[derive(Debug, Serialize)]
pub struct IssueKeyResponse {
    pub key_id: String,
    pub consumer_id: String,
    /// Full plaintext key — shown exactly once. Store it securely.
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
    pub issued_by: Option<String>,
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

/// POST /api/admin/consumers/:consumer_id/keys
pub async fn issue_key(
    State(state): State<AdminKeysState>,
    Path(consumer_id): Path<Uuid>,
    Json(req): Json<IssueKeyRequest>,
) -> Response {
    // Validate environment
    let env = match KeyEnvironment::from_str(&req.environment) {
        Ok(e) => e,
        Err(e) => return err(StatusCode::BAD_REQUEST, "INVALID_ENVIRONMENT", e),
    };

    if req.issued_by.trim().is_empty() {
        return err(StatusCode::BAD_REQUEST, "MISSING_ISSUED_BY", "issued_by is required");
    }

    let repo = ApiKeyRepository::new((*state.db).clone());

    // Verify consumer exists
    let consumer_exists = sqlx::query_scalar!(
        "SELECT EXISTS(SELECT 1 FROM consumers WHERE id = $1 AND is_active = TRUE)",
        consumer_id
    )
    .fetch_one(state.db.as_ref())
    .await;

    match consumer_exists {
        Ok(Some(true)) => {}
        Ok(_) => return err(StatusCode::NOT_FOUND, "CONSUMER_NOT_FOUND", "Consumer not found"),
        Err(e) => {
            error!(error = %e, "DB error checking consumer");
            return err(StatusCode::INTERNAL_SERVER_ERROR, "DB_ERROR", "Database error");
        }
    }

    // Enforce max active keys per consumer
    match repo.count_active_for_consumer(consumer_id).await {
        Ok(count) if count >= max_keys_per_consumer() => {
            warn!(
                consumer_id = %consumer_id,
                count = count,
                max = max_keys_per_consumer(),
                "Max active keys reached for consumer"
            );
            return err(
                StatusCode::UNPROCESSABLE_ENTITY,
                "MAX_KEYS_REACHED",
                format!("Consumer already has {} active keys (maximum {})", count, max_keys_per_consumer()),
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

    // Persist — only the hash, never the plaintext
    let key = match repo
        .create(
            consumer_id,
            &generated.key_hash,
            &generated.key_prefix,
            &generated.key_id_prefix,
            generated.environment.as_str(),
            req.description.as_deref(),
            Some(req.issued_by.as_str()),
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

    // Audit log — issuance event (no plaintext key)
    let _ = repo
        .log_audit_event(
            "issued",
            Some(key.id),
            Some(consumer_id),
            Some(&req.issued_by),
            Some(generated.environment.as_str()),
            None,
            None,
            None,
        )
        .await;

    info!(
        key_id = %key.id,
        consumer_id = %consumer_id,
        environment = %key.environment,
        issued_by = %req.issued_by,
        "API key issued"
    );

    // Return plaintext key exactly once
    (
        StatusCode::CREATED,
        Json(IssueKeyResponse {
            key_id: key.id.to_string(),
            consumer_id: consumer_id.to_string(),
            plaintext_key: generated.plaintext_key, // shown once, never stored
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

/// GET /api/admin/consumers/:consumer_id/keys
pub async fn list_keys(
    State(state): State<AdminKeysState>,
    Path(consumer_id): Path<Uuid>,
) -> Response {
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
                    issued_by: k.issued_by,
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

/// DELETE /api/admin/consumers/:consumer_id/keys/:key_id
pub async fn revoke_key(
    State(state): State<AdminKeysState>,
    Path((consumer_id, key_id)): Path<(Uuid, Uuid)>,
) -> Response {
    let repo = ApiKeyRepository::new((*state.db).clone());

    match repo.revoke(key_id, consumer_id).await {
        Ok(key) => {
            // Audit log
            let _ = repo
                .log_audit_event(
                    "revoked",
                    Some(key_id),
                    Some(consumer_id),
                    None,
                    Some(&key.environment),
                    None,
                    None,
                    None,
                )
                .await;

            info!(key_id = %key_id, consumer_id = %consumer_id, "API key revoked");

            Json(KeySummary {
                key_id: key.id.to_string(),
                consumer_id: key.consumer_id.to_string(),
                key_prefix: key.key_prefix,
                key_id_prefix: key.key_id_prefix,
                environment: key.environment,
                status: key.status,
                description: key.description,
                issued_by: key.issued_by,
                expires_at: key.expires_at,
                last_used_at: key.last_used_at,
                created_at: key.created_at,
            })
            .into_response()
        }
        Err(e) if e.is_not_found() => {
            err(StatusCode::NOT_FOUND, "KEY_NOT_FOUND", "API key not found")
        }
        Err(e) => {
            error!(error = %e, "Failed to revoke key");
            err(StatusCode::INTERNAL_SERVER_ERROR, "DB_ERROR", "Failed to revoke key")
        }
    }
}
