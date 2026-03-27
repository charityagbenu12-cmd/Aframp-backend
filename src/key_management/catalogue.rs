//! Key catalogue — metadata inventory for all platform cryptographic keys.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "text")]
#[serde(rename_all = "snake_case")]
pub enum KeyType {
    JwtSigning,
    PayloadEncryption,
    DbFieldEncryption,
    HmacDerivation,
    BackupEncryption,
    Tls,
}

impl KeyType {
    /// Scheduled rotation interval in days.
    pub fn rotation_days(&self) -> i64 {
        match self {
            KeyType::JwtSigning => 90,
            KeyType::PayloadEncryption => 180,
            KeyType::DbFieldEncryption => 365,
            KeyType::HmacDerivation => 90,
            KeyType::BackupEncryption => 365,
            KeyType::Tls => 365,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            KeyType::JwtSigning => "jwt_signing",
            KeyType::PayloadEncryption => "payload_encryption",
            KeyType::DbFieldEncryption => "db_field_encryption",
            KeyType::HmacDerivation => "hmac_derivation",
            KeyType::BackupEncryption => "backup_encryption",
            KeyType::Tls => "tls",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "text")]
#[serde(rename_all = "snake_case")]
pub enum KeyStatus {
    Pending,
    Active,
    Transitional,
    Retired,
    Destroyed,
}

impl KeyStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            KeyStatus::Pending => "pending",
            KeyStatus::Active => "active",
            KeyStatus::Transitional => "transitional",
            KeyStatus::Retired => "retired",
            KeyStatus::Destroyed => "destroyed",
        }
    }
}

/// Key metadata record — no key material ever stored here.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformKey {
    pub id: Uuid,
    pub key_id: String,
    pub key_type: String,
    pub algorithm: String,
    pub key_length_bits: Option<i32>,
    pub status: String,
    pub storage_location: String,
    pub rotation_days: i32,
    pub created_at: DateTime<Utc>,
    pub activated_at: Option<DateTime<Utc>>,
    pub last_rotated_at: Option<DateTime<Utc>>,
    pub next_rotation_at: Option<DateTime<Utc>>,
    pub grace_period_end: Option<DateTime<Utc>>,
    pub retired_at: Option<DateTime<Utc>>,
    pub destroyed_at: Option<DateTime<Utc>>,
    pub jwt_kid: Option<String>,
    pub enc_version: Option<String>,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformKeyEvent {
    pub id: Uuid,
    pub platform_key_id: Uuid,
    pub event_type: String,
    pub initiated_by: String,
    pub reason: Option<String>,
    pub metadata: serde_json::Value,
    pub created_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum CatalogueError {
    #[error("Key not found: {0}")]
    NotFound(String),
    #[error("Key already exists: {0}")]
    AlreadyExists(String),
    #[error("Invalid status transition from {from} to {to}")]
    InvalidTransition { from: String, to: String },
    #[error(transparent)]
    Database(#[from] sqlx::Error),
}

// ---------------------------------------------------------------------------
// Repository
// ---------------------------------------------------------------------------

pub struct KeyCatalogueRepository {
    pool: PgPool,
}

impl KeyCatalogueRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn insert(&self, key: &NewPlatformKey) -> Result<PlatformKey, CatalogueError> {
        let rotation_days = key.key_type.rotation_days() as i32;
        let next_rotation = Utc::now() + Duration::days(key.key_type.rotation_days());

        let row = sqlx::query_as!(
            PlatformKey,
            r#"INSERT INTO platform_keys
               (key_id, key_type, algorithm, key_length_bits, status, storage_location,
                rotation_days, activated_at, next_rotation_at, jwt_kid, enc_version, notes)
               VALUES ($1,$2,$3,$4,'active',$5,$6,now(),$7,$8,$9,$10)
               RETURNING *"#,
            key.key_id,
            key.key_type.as_str(),
            key.algorithm,
            key.key_length_bits,
            key.storage_location,
            rotation_days,
            next_rotation,
            key.jwt_kid,
            key.enc_version,
            key.notes,
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(row)
    }

    pub async fn get_by_key_id(&self, key_id: &str) -> Result<PlatformKey, CatalogueError> {
        sqlx::query_as!(PlatformKey, "SELECT * FROM platform_keys WHERE key_id = $1", key_id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or_else(|| CatalogueError::NotFound(key_id.to_string()))
    }

    pub async fn get_by_uuid(&self, id: Uuid) -> Result<PlatformKey, CatalogueError> {
        sqlx::query_as!(PlatformKey, "SELECT * FROM platform_keys WHERE id = $1", id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or_else(|| CatalogueError::NotFound(id.to_string()))
    }

    pub async fn list(
        &self,
        page: i64,
        per_page: i64,
    ) -> Result<(Vec<PlatformKey>, i64), CatalogueError> {
        let offset = (page - 1) * per_page;
        let rows = sqlx::query_as!(
            PlatformKey,
            "SELECT * FROM platform_keys ORDER BY created_at DESC LIMIT $1 OFFSET $2",
            per_page,
            offset,
        )
        .fetch_all(&self.pool)
        .await?;

        let total: i64 =
            sqlx::query_scalar!("SELECT COUNT(*) FROM platform_keys")
                .fetch_one(&self.pool)
                .await?
                .unwrap_or(0);

        Ok((rows, total))
    }

    pub async fn keys_due_for_rotation(&self) -> Result<Vec<PlatformKey>, CatalogueError> {
        let rows = sqlx::query_as!(
            PlatformKey,
            r#"SELECT * FROM platform_keys
               WHERE status IN ('active','transitional')
               AND next_rotation_at <= now()"#,
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    pub async fn update_status(
        &self,
        id: Uuid,
        status: KeyStatus,
        grace_period_end: Option<DateTime<Utc>>,
    ) -> Result<(), CatalogueError> {
        sqlx::query!(
            r#"UPDATE platform_keys
               SET status = $1, grace_period_end = $2,
                   retired_at = CASE WHEN $1 = 'retired' THEN now() ELSE retired_at END,
                   destroyed_at = CASE WHEN $1 = 'destroyed' THEN now() ELSE destroyed_at END
               WHERE id = $3"#,
            status.as_str(),
            grace_period_end,
            id,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn mark_rotated(
        &self,
        id: Uuid,
        rotation_days: i64,
    ) -> Result<(), CatalogueError> {
        let next = Utc::now() + Duration::days(rotation_days);
        sqlx::query!(
            "UPDATE platform_keys SET last_rotated_at = now(), next_rotation_at = $1 WHERE id = $2",
            next,
            id,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn append_event(
        &self,
        platform_key_id: Uuid,
        event_type: &str,
        initiated_by: &str,
        reason: Option<&str>,
        metadata: serde_json::Value,
    ) -> Result<(), CatalogueError> {
        sqlx::query!(
            r#"INSERT INTO platform_key_events
               (platform_key_id, event_type, initiated_by, reason, metadata)
               VALUES ($1,$2,$3,$4,$5)"#,
            platform_key_id,
            event_type,
            initiated_by,
            reason,
            metadata,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn events_for_key(
        &self,
        platform_key_id: Uuid,
    ) -> Result<Vec<PlatformKeyEvent>, CatalogueError> {
        let rows = sqlx::query_as!(
            PlatformKeyEvent,
            r#"SELECT id, platform_key_id, event_type, initiated_by, reason,
                      metadata as "metadata: serde_json::Value", created_at
               FROM platform_key_events
               WHERE platform_key_id = $1
               ORDER BY created_at DESC"#,
            platform_key_id,
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }
}

// ---------------------------------------------------------------------------
// DTO for inserting a new key
// ---------------------------------------------------------------------------

pub struct NewPlatformKey {
    pub key_id: String,
    pub key_type: KeyType,
    pub algorithm: String,
    pub key_length_bits: Option<i32>,
    pub storage_location: String,
    pub jwt_kid: Option<String>,
    pub enc_version: Option<String>,
    pub notes: Option<String>,
}
