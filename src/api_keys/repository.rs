//! Database repository for API key lifecycle management.

use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

use crate::database::error::{DatabaseError, DatabaseErrorKind};

// ---------------------------------------------------------------------------
// Entities
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, FromRow)]
pub struct ApiKey {
    pub id: Uuid,
    pub consumer_id: Uuid,
    pub key_hash: String,
    pub key_prefix: String,
    pub key_id_prefix: String,
    pub description: Option<String>,
    pub environment: String,
    pub status: String,
    pub issued_by: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow)]
pub struct ApiKeyAuditEvent {
    pub id: Uuid,
    pub event_type: String,
    pub api_key_id: Option<Uuid>,
    pub consumer_id: Option<Uuid>,
    pub issuing_identity: Option<String>,
    pub environment: Option<String>,
    pub endpoint: Option<String>,
    pub ip_address: Option<String>,
    pub rejection_reason: Option<String>,
    pub created_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Repository
// ---------------------------------------------------------------------------

pub struct ApiKeyRepository {
    pool: PgPool,
}

impl ApiKeyRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    // ── Key CRUD ─────────────────────────────────────────────────────────────

    /// Insert a new API key record. The plaintext key must NOT be passed here.
    pub async fn create(
        &self,
        consumer_id: Uuid,
        key_hash: &str,
        key_prefix: &str,
        key_id_prefix: &str,
        environment: &str,
        description: Option<&str>,
        issued_by: Option<&str>,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<ApiKey, DatabaseError> {
        sqlx::query_as::<_, ApiKey>(
            r#"
            INSERT INTO api_keys
                (consumer_id, key_hash, key_prefix, key_id_prefix,
                 environment, status, description, issued_by, expires_at)
            VALUES ($1, $2, $3, $4, $5, 'active', $6, $7, $8)
            RETURNING
                id, consumer_id, key_hash, key_prefix, key_id_prefix,
                description, environment, status, issued_by,
                expires_at, last_used_at, created_at, updated_at
            "#,
        )
        .bind(consumer_id)
        .bind(key_hash)
        .bind(key_prefix)
        .bind(key_id_prefix)
        .bind(environment)
        .bind(description)
        .bind(issued_by)
        .bind(expires_at)
        .fetch_one(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)
    }

    /// Count active keys for a consumer (used to enforce per-consumer limit).
    pub async fn count_active_for_consumer(
        &self,
        consumer_id: Uuid,
    ) -> Result<i64, DatabaseError> {
        sqlx::query_scalar!(
            "SELECT COUNT(*) FROM api_keys WHERE consumer_id = $1 AND status = 'active'",
            consumer_id
        )
        .fetch_one(&self.pool)
        .await
        .map(|c| c.unwrap_or(0))
        .map_err(DatabaseError::from_sqlx)
    }

    /// Look up an active key by its prefix for fast narrowing, then return
    /// the hash for Argon2id verification by the caller.
    /// Returns all active keys sharing the prefix (usually just one).
    pub async fn find_active_by_prefix(
        &self,
        key_prefix: &str,
        environment: &str,
    ) -> Result<Vec<ApiKey>, DatabaseError> {
        sqlx::query_as::<_, ApiKey>(
            r#"
            SELECT
                id, consumer_id, key_hash, key_prefix, key_id_prefix,
                description, environment, status, issued_by,
                expires_at, last_used_at, created_at, updated_at
            FROM api_keys
            WHERE key_prefix = $1
              AND environment = $2
              AND status = 'active'
              AND (expires_at IS NULL OR expires_at > now())
            "#,
        )
        .bind(key_prefix)
        .bind(environment)
        .fetch_all(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)
    }

    /// Update last_used_at — called asynchronously after successful verification.
    pub async fn touch_last_used(&self, key_id: Uuid) -> Result<(), DatabaseError> {
        sqlx::query!(
            "UPDATE api_keys SET last_used_at = now() WHERE id = $1",
            key_id
        )
        .execute(&self.pool)
        .await
        .map(|_| ())
        .map_err(DatabaseError::from_sqlx)
    }

    /// Revoke a key (soft delete — sets status = 'revoked').
    pub async fn revoke(&self, key_id: Uuid, consumer_id: Uuid) -> Result<ApiKey, DatabaseError> {
        sqlx::query_as::<_, ApiKey>(
            r#"
            UPDATE api_keys
            SET status = 'revoked', is_active = FALSE
            WHERE id = $1 AND consumer_id = $2
            RETURNING
                id, consumer_id, key_hash, key_prefix, key_id_prefix,
                description, environment, status, issued_by,
                expires_at, last_used_at, created_at, updated_at
            "#,
        )
        .bind(key_id)
        .bind(consumer_id)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            if matches!(e, sqlx::Error::RowNotFound) {
                DatabaseError::new(DatabaseErrorKind::NotFound {
                    entity: "ApiKey".to_string(),
                    id: key_id.to_string(),
                })
            } else {
                DatabaseError::from_sqlx(e)
            }
        })
    }

    /// List all keys for a consumer (for admin/developer portal views).
    pub async fn list_for_consumer(
        &self,
        consumer_id: Uuid,
    ) -> Result<Vec<ApiKey>, DatabaseError> {
        sqlx::query_as::<_, ApiKey>(
            r#"
            SELECT
                id, consumer_id, key_hash, key_prefix, key_id_prefix,
                description, environment, status, issued_by,
                expires_at, last_used_at, created_at, updated_at
            FROM api_keys
            WHERE consumer_id = $1
            ORDER BY created_at DESC
            "#,
        )
        .bind(consumer_id)
        .fetch_all(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)
    }

    // ── Audit log ─────────────────────────────────────────────────────────────

    /// Append an audit event. Never pass the plaintext key to this function.
    pub async fn log_audit_event(
        &self,
        event_type: &str,
        api_key_id: Option<Uuid>,
        consumer_id: Option<Uuid>,
        issuing_identity: Option<&str>,
        environment: Option<&str>,
        endpoint: Option<&str>,
        ip_address: Option<&str>,
        rejection_reason: Option<&str>,
    ) -> Result<(), DatabaseError> {
        sqlx::query!(
            r#"
            INSERT INTO api_key_audit_log
                (event_type, api_key_id, consumer_id, issuing_identity,
                 environment, endpoint, ip_address, rejection_reason)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            "#,
            event_type,
            api_key_id,
            consumer_id,
            issuing_identity,
            environment,
            endpoint,
            ip_address,
            rejection_reason,
        )
        .execute(&self.pool)
        .await
        .map(|_| ())
        .map_err(DatabaseError::from_sqlx)
    }
}
