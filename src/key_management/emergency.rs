//! Emergency key revocation.
//!
//! Immediately generates a replacement key, activates it, and retires the
//! compromised key with no grace period. For JWT signing keys, all tokens
//! signed with the compromised key are immediately invalidated via the
//! token registry.

use sqlx::PgPool;
use tracing::{error, info, warn};
use uuid::Uuid;

use super::catalogue::{CatalogueError, KeyCatalogueRepository, KeyStatus, NewPlatformKey};
use super::rotation::{default_algorithm, default_key_length, parse_key_type};
use super::metrics;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum RevocationError {
    #[error("Key not found: {0}")]
    NotFound(String),
    #[error("Key already destroyed")]
    AlreadyDestroyed,
    #[error("Catalogue error: {0}")]
    Catalogue(#[from] CatalogueError),
    #[error(transparent)]
    Database(#[from] sqlx::Error),
}

// ---------------------------------------------------------------------------
// Result
// ---------------------------------------------------------------------------

#[derive(Debug, serde::Serialize)]
pub struct RevocationResult {
    pub revoked_key_id: String,
    pub replacement_key_id: String,
    pub tokens_invalidated: Option<u64>,
    pub revoked_at: chrono::DateTime<chrono::Utc>,
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

pub struct EmergencyRevocationService {
    repo: KeyCatalogueRepository,
    pool: PgPool,
}

impl EmergencyRevocationService {
    pub fn new(pool: PgPool) -> Self {
        Self {
            repo: KeyCatalogueRepository::new(pool.clone()),
            pool,
        }
    }

    /// Immediately revoke a key — no grace period.
    ///
    /// `admin_id` — the admin initiating the revocation.
    /// `reason`   — mandatory reason for audit trail.
    pub async fn revoke(
        &self,
        key_id: &str,
        admin_id: &str,
        reason: &str,
    ) -> Result<RevocationResult, RevocationError> {
        let key = self.repo.get_by_key_id(key_id).await?;

        if key.status == "destroyed" {
            return Err(RevocationError::AlreadyDestroyed);
        }

        let key_type = parse_key_type(&key.key_type);

        // 1. Immediately retire the compromised key (no grace period)
        self.repo
            .update_status(key.id, KeyStatus::Retired, None)
            .await?;

        self.repo
            .append_event(
                key.id,
                "emergency_revoked",
                &format!("admin:{admin_id}"),
                Some(reason),
                serde_json::json!({ "reason": reason }),
            )
            .await?;

        warn!(
            key_id = %key_id,
            admin_id = %admin_id,
            reason = %reason,
            "EMERGENCY KEY REVOCATION"
        );

        // 2. Generate replacement key immediately
        let replacement_id = format!("{}-emergency-{}", key.key_type, chrono::Utc::now().timestamp());
        let replacement = NewPlatformKey {
            key_id: replacement_id.clone(),
            key_type: key_type.clone(),
            algorithm: default_algorithm(&key_type),
            key_length_bits: default_key_length(&key_type),
            storage_location: "secrets_manager".to_string(),
            jwt_kid: if key.jwt_kid.is_some() {
                Some(format!("kid-emergency-{}", Uuid::new_v4()))
            } else {
                None
            },
            enc_version: key.enc_version.as_ref().map(|_| {
                format!("v-emergency-{}", chrono::Utc::now().timestamp())
            }),
            notes: Some(format!("Emergency replacement for revoked key {key_id}")),
        };

        let inserted = self.repo.insert(&replacement).await?;
        self.repo
            .append_event(
                inserted.id,
                "generated",
                &format!("admin:{admin_id}"),
                Some("Emergency replacement"),
                serde_json::json!({ "replaced": key_id, "reason": reason }),
            )
            .await?;

        // 3. For JWT signing keys: invalidate all tokens signed with the old kid
        let tokens_invalidated = if key.key_type == "jwt_signing" {
            if let Some(kid) = &key.jwt_kid {
                match self.invalidate_jwt_tokens_by_kid(kid).await {
                    Ok(n) => {
                        info!(kid = %kid, count = n, "JWT tokens invalidated after emergency revocation");
                        Some(n)
                    }
                    Err(e) => {
                        error!(kid = %kid, error = %e, "Failed to invalidate JWT tokens");
                        None
                    }
                }
            } else {
                None
            }
        } else {
            None
        };

        metrics::inc_emergency_revocation(&key.key_type);

        info!(
            revoked = %key_id,
            replacement = %replacement_id,
            tokens_invalidated = ?tokens_invalidated,
            "Emergency revocation complete"
        );

        Ok(RevocationResult {
            revoked_key_id: key_id.to_string(),
            replacement_key_id: replacement_id,
            tokens_invalidated,
            revoked_at: chrono::Utc::now(),
        })
    }

    /// Invalidate all active JWT tokens signed with the given kid via the token registry.
    async fn invalidate_jwt_tokens_by_kid(&self, kid: &str) -> Result<u64, sqlx::Error> {
        // The token_registry table stores the kid in the metadata or we match by
        // the signing key version. We revoke all non-revoked tokens for this kid.
        let result = sqlx::query!(
            r#"UPDATE token_registry
               SET revoked = true, revoked_at = now()
               WHERE revoked = false
               AND metadata->>'kid' = $1"#,
            kid,
        )
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected())
    }
}
