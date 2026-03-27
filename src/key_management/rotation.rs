//! Automated key rotation scheduler.
//!
//! Runs daily, identifies keys due for rotation, and initiates the
//! appropriate rotation procedure per key type with zero-downtime grace periods.

use chrono::{Duration, Utc};
use sqlx::PgPool;
use tracing::{error, info, warn};
use uuid::Uuid;

use super::catalogue::{CatalogueError, KeyCatalogueRepository, KeyStatus, NewPlatformKey, KeyType};
use super::metrics;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Grace period during which both old and new keys are simultaneously valid.
pub const DEFAULT_GRACE_PERIOD_DAYS: i64 = 7;

/// Grace period for JWT signing keys (tokens expire within 1h, so shorter is fine).
pub const JWT_GRACE_PERIOD_DAYS: i64 = 1;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum RotationSchedulerError {
    #[error("Catalogue error: {0}")]
    Catalogue(#[from] CatalogueError),
    #[error("Key generation failed: {0}")]
    KeyGeneration(String),
    #[error("Secrets manager error: {0}")]
    SecretsManager(String),
}

// ---------------------------------------------------------------------------
// Rotation outcome
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct RotationOutcome {
    pub old_key_id: String,
    pub new_key_id: String,
    pub grace_period_end: chrono::DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Scheduler
// ---------------------------------------------------------------------------

pub struct KeyRotationScheduler {
    repo: KeyCatalogueRepository,
    pool: PgPool,
}

impl KeyRotationScheduler {
    pub fn new(pool: PgPool) -> Self {
        Self {
            repo: KeyCatalogueRepository::new(pool.clone()),
            pool,
        }
    }

    /// Run one rotation sweep — called daily by the background worker.
    pub async fn run_sweep(&self) -> Result<Vec<RotationOutcome>, RotationSchedulerError> {
        let due = self.repo.keys_due_for_rotation().await?;
        let mut outcomes = Vec::new();

        for key in due {
            let key_type = parse_key_type(&key.key_type);
            info!(key_id = %key.key_id, key_type = %key.key_type, "Initiating scheduled rotation");

            match self.rotate_key(&key.id, &key.key_id, &key_type).await {
                Ok(outcome) => {
                    metrics::inc_rotation_initiated(&key.key_type);
                    outcomes.push(outcome);
                }
                Err(e) => {
                    error!(key_id = %key.key_id, error = %e, "Rotation failed");
                    metrics::inc_rotation_failed(&key.key_type);
                }
            }
        }

        Ok(outcomes)
    }

    /// Expire grace periods — retire old keys whose grace window has closed.
    pub async fn expire_grace_periods(&self) -> Result<u64, RotationSchedulerError> {
        let expired = sqlx::query!(
            r#"UPDATE platform_keys
               SET status = 'retired', retired_at = now()
               WHERE status = 'transitional'
               AND grace_period_end <= now()
               RETURNING id, key_id, key_type"#,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(CatalogueError::Database)?;

        for row in &expired {
            info!(key_id = %row.key_id, "Grace period expired — key retired");
            self.repo
                .append_event(
                    row.id,
                    "grace_period_expired",
                    "scheduler",
                    None,
                    serde_json::json!({}),
                )
                .await?;
            metrics::inc_grace_period_expired(&row.key_type);
        }

        Ok(expired.len() as u64)
    }

    // -----------------------------------------------------------------------
    // Per-key-type rotation
    // -----------------------------------------------------------------------

    async fn rotate_key(
        &self,
        old_id: &Uuid,
        old_key_id: &str,
        key_type: &KeyType,
    ) -> Result<RotationOutcome, RotationSchedulerError> {
        let grace_days = match key_type {
            KeyType::JwtSigning => JWT_GRACE_PERIOD_DAYS,
            _ => DEFAULT_GRACE_PERIOD_DAYS,
        };
        let grace_end = Utc::now() + Duration::days(grace_days);

        // 1. Generate new key metadata (material generated in secrets manager)
        let new_key_id = format!("{}-v{}", key_type.as_str(), Utc::now().timestamp());
        let new_key = NewPlatformKey {
            key_id: new_key_id.clone(),
            key_type: key_type.clone(),
            algorithm: default_algorithm(key_type),
            key_length_bits: default_key_length(key_type),
            storage_location: "secrets_manager".to_string(),
            jwt_kid: if matches!(key_type, KeyType::JwtSigning) {
                Some(format!("kid-{}", Uuid::new_v4()))
            } else {
                None
            },
            enc_version: if matches!(key_type, KeyType::PayloadEncryption) {
                Some(format!("v{}", Utc::now().timestamp()))
            } else {
                None
            },
            notes: Some(format!("Rotated from {old_key_id}")),
        };

        let inserted = self.repo.insert(&new_key).await?;

        // 2. Mark old key as transitional with grace period
        self.repo
            .update_status(*old_id, KeyStatus::Transitional, Some(grace_end))
            .await?;

        // 3. Record rotation events
        self.repo
            .append_event(
                *old_id,
                "rotation_initiated",
                "scheduler",
                None,
                serde_json::json!({ "new_key_id": new_key_id, "grace_period_end": grace_end }),
            )
            .await?;
        self.repo
            .append_event(
                inserted.id,
                "generated",
                "scheduler",
                None,
                serde_json::json!({ "replaced": old_key_id }),
            )
            .await?;

        // 4. Update rotation timestamp on old key
        self.repo
            .mark_rotated(*old_id, key_type.rotation_days())
            .await?;

        info!(
            old_key = %old_key_id,
            new_key = %new_key_id,
            grace_period_end = %grace_end,
            "Key rotation initiated"
        );

        Ok(RotationOutcome {
            old_key_id: old_key_id.to_string(),
            new_key_id,
            grace_period_end: grace_end,
        })
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn parse_key_type(s: &str) -> KeyType {
    match s {
        "jwt_signing" => KeyType::JwtSigning,
        "payload_encryption" => KeyType::PayloadEncryption,
        "db_field_encryption" => KeyType::DbFieldEncryption,
        "hmac_derivation" => KeyType::HmacDerivation,
        "backup_encryption" => KeyType::BackupEncryption,
        _ => KeyType::Tls,
    }
}

fn default_algorithm(key_type: &KeyType) -> String {
    match key_type {
        KeyType::JwtSigning => "RS256".to_string(),
        KeyType::PayloadEncryption => "ECDH-ES+A256KW".to_string(),
        KeyType::DbFieldEncryption => "AES-256-GCM".to_string(),
        KeyType::HmacDerivation => "HMAC-SHA256".to_string(),
        KeyType::BackupEncryption => "AES-256-GCM".to_string(),
        KeyType::Tls => "RSA-2048".to_string(),
    }
}

fn default_key_length(key_type: &KeyType) -> Option<i32> {
    match key_type {
        KeyType::JwtSigning => Some(4096),
        KeyType::PayloadEncryption => Some(384), // P-384
        KeyType::DbFieldEncryption => Some(256),
        KeyType::HmacDerivation => Some(256),
        KeyType::BackupEncryption => Some(256),
        KeyType::Tls => Some(2048),
    }
}

// ---------------------------------------------------------------------------
// Background worker
// ---------------------------------------------------------------------------

pub struct KeyRotationWorker {
    scheduler: KeyRotationScheduler,
}

impl KeyRotationWorker {
    pub fn new(pool: PgPool) -> Self {
        Self { scheduler: KeyRotationScheduler::new(pool) }
    }

    pub async fn run(self, mut shutdown: tokio::sync::watch::Receiver<bool>) {
        // Daily sweep at startup then every 24h
        let mut sweep_ticker =
            tokio::time::interval(std::time::Duration::from_secs(86_400));
        // Grace period expiry check every hour
        let mut grace_ticker =
            tokio::time::interval(std::time::Duration::from_secs(3_600));

        info!("Platform key rotation worker started");

        loop {
            tokio::select! {
                _ = sweep_ticker.tick() => {
                    match self.scheduler.run_sweep().await {
                        Ok(outcomes) if !outcomes.is_empty() =>
                            info!(count = outcomes.len(), "Key rotation sweep completed"),
                        Ok(_) => {}
                        Err(e) => error!(error = %e, "Key rotation sweep failed"),
                    }
                }
                _ = grace_ticker.tick() => {
                    match self.scheduler.expire_grace_periods().await {
                        Ok(n) if n > 0 => info!(count = n, "Grace periods expired"),
                        Ok(_) => {}
                        Err(e) => error!(error = %e, "Grace period expiry check failed"),
                    }
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        info!("Platform key rotation worker shutting down");
                        break;
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Rotation schedule helpers (used in tests and admin UI)
// ---------------------------------------------------------------------------

/// Returns days until next scheduled rotation. Negative = overdue.
pub fn days_until_rotation(next_rotation_at: Option<chrono::DateTime<Utc>>) -> Option<i64> {
    next_rotation_at.map(|t| (t - Utc::now()).num_days())
}

/// Returns true if the key is within its grace period (both old and new valid).
pub fn is_in_grace_period(
    status: &str,
    grace_period_end: Option<chrono::DateTime<Utc>>,
) -> bool {
    status == "transitional"
        && grace_period_end.map(|t| t > Utc::now()).unwrap_or(false)
}
