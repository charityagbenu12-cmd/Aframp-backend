//! API Key Rotation & Expiry Management (Issue #137).
//!
//! Covers:
//!   - Key lifetime policy enforcement per consumer type
//!   - Consumer-initiated and admin-initiated rotation with grace period
//!   - Forced rotation (no grace period, immediate invalidation)
//!   - Grace period enforcement and early completion
//!   - Expiry notification deduplication
//!   - Background job helpers (grace period expiry, expiry notifications)

use chrono::{DateTime, Duration, Utc};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tracing::info;
use uuid::Uuid;

// ─── Constants ────────────────────────────────────────────────────────────────

/// Warning thresholds in days before expiry at which notifications are sent.
pub const EXPIRY_WARNING_DAYS: &[i32] = &[30, 14, 7, 1];

/// Default grace period for standard rotation (24 hours).
pub const DEFAULT_GRACE_PERIOD_HOURS: i64 = 24;

// ─── Errors ───────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum RotationError {
    #[error("Key not found")]
    KeyNotFound,
    #[error("Key is already inactive")]
    KeyInactive,
    #[error("Requested lifetime of {requested} days exceeds the maximum of {max} days for consumer type '{consumer_type}'")]
    LifetimeExceedsMax {
        requested: i64,
        max: i64,
        consumer_type: String,
    },
    #[error("No expiry specified — every key must have an explicit expiry")]
    MissingExpiry,
    #[error("Active rotation already exists for this key")]
    RotationAlreadyActive,
    #[error("No active rotation found for this key")]
    NoActiveRotation,
    #[error(transparent)]
    Database(#[from] sqlx::Error),
}

// ─── DTOs ─────────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct RotationResult {
    pub rotation_id: Uuid,
    pub new_key_id: Uuid,
    /// Plaintext key — returned exactly once, never stored.
    pub new_key_plaintext: String,
    pub grace_period_end: DateTime<Utc>,
}

#[derive(Debug)]
pub struct KeyLifetimePolicy {
    pub max_lifetime_days: i64,
    pub default_lifetime_days: i64,
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn hash_key(raw: &str) -> String {
    hex::encode(Sha256::digest(raw.as_bytes()))
}

fn generate_api_key() -> String {
    use std::fmt::Write;
    let bytes: [u8; 32] = rand_bytes();
    let mut s = String::with_capacity(64);
    for b in &bytes {
        write!(s, "{:02x}", b).unwrap();
    }
    s
}

/// Minimal CSPRNG using OS entropy via `uuid` crate internals.
fn rand_bytes() -> [u8; 32] {
    let a = Uuid::new_v4();
    let b = Uuid::new_v4();
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(a.as_bytes());
    out[16..].copy_from_slice(b.as_bytes());
    out
}

// ─── Service ──────────────────────────────────────────────────────────────────

pub struct KeyRotationService {
    pool: PgPool,
    grace_period_hours: i64,
}

impl KeyRotationService {
    pub fn new(pool: PgPool) -> Self {
        let grace_period_hours = std::env::var("KEY_ROTATION_GRACE_PERIOD_HOURS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_GRACE_PERIOD_HOURS);
        Self { pool, grace_period_hours }
    }

    // ── Lifetime policy ───────────────────────────────────────────────────────

    /// Returns the lifetime policy for a consumer type.
    pub async fn get_lifetime_policy(
        &self,
        consumer_type: &str,
    ) -> Result<KeyLifetimePolicy, RotationError> {
        let row = sqlx::query!(
            "SELECT max_lifetime_days FROM consumer_types WHERE name = $1",
            consumer_type
        )
        .fetch_optional(&self.pool)
        .await?
        .ok_or(RotationError::KeyNotFound)?;

        let max = row.max_lifetime_days as i64;
        Ok(KeyLifetimePolicy {
            max_lifetime_days: max,
            default_lifetime_days: max,
        })
    }

    /// Validates that `requested_days` does not exceed the maximum for the
    /// consumer type. Returns the resolved expiry timestamp.
    pub async fn resolve_expiry(
        &self,
        consumer_type: &str,
        requested_days: Option<i64>,
    ) -> Result<DateTime<Utc>, RotationError> {
        let policy = self.get_lifetime_policy(consumer_type).await?;
        let days = requested_days.unwrap_or(policy.default_lifetime_days);
        if days > policy.max_lifetime_days {
            return Err(RotationError::LifetimeExceedsMax {
                requested: days,
                max: policy.max_lifetime_days,
                consumer_type: consumer_type.to_string(),
            });
        }
        Ok(Utc::now() + Duration::days(days))
    }

    // ── Standard rotation ─────────────────────────────────────────────────────

    /// Rotate a key: generate a new key with the same scopes, activate a grace
    /// period, and record the rotation in the audit log.
    ///
    /// Returns the new plaintext key exactly once.
    pub async fn rotate_key(
        &self,
        key_id: Uuid,
        initiated_by: &str,
        forced: bool,
    ) -> Result<RotationResult, RotationError> {
        // 1. Load the key being rotated.
        let old_key = sqlx::query!(
            r#"
            SELECT ak.id, ak.consumer_id, ak.is_active, ak.expires_at,
                   c.consumer_type
            FROM api_keys ak
            JOIN consumers c ON c.id = ak.consumer_id
            WHERE ak.id = $1
            "#,
            key_id
        )
        .fetch_optional(&self.pool)
        .await?
        .ok_or(RotationError::KeyNotFound)?;

        if !old_key.is_active {
            return Err(RotationError::KeyInactive);
        }

        // 2. Ensure no active rotation already exists (unless forced).
        if !forced {
            let existing = sqlx::query_scalar!(
                "SELECT id FROM key_rotations WHERE old_key_id = $1 AND status = 'active'",
                key_id
            )
            .fetch_optional(&self.pool)
            .await?;
            if existing.is_some() {
                return Err(RotationError::RotationAlreadyActive);
            }
        }

        // 3. Determine new key expiry (same lifetime as old key from now).
        let old_expires = old_key.expires_at.ok_or(RotationError::MissingExpiry)?;
        let remaining = old_expires - Utc::now();
        let new_expires = if remaining > Duration::zero() {
            // Carry forward the same remaining lifetime.
            Utc::now() + remaining
        } else {
            // Old key already expired — use the default for the consumer type.
            let policy = self.get_lifetime_policy(&old_key.consumer_type).await?;
            Utc::now() + Duration::days(policy.default_lifetime_days)
        };

        // 4. Generate new key material.
        let raw_key = generate_api_key();
        let key_hash = hash_key(&raw_key);
        let key_prefix = &raw_key[..8];

        // 5. Fetch scopes of the old key.
        let scopes: Vec<String> = sqlx::query_scalar!(
            "SELECT scope_name FROM key_scopes WHERE api_key_id = $1",
            key_id
        )
        .fetch_all(&self.pool)
        .await?;

        // 6. Persist everything in a transaction.
        let grace_period_end = if forced {
            Utc::now() // immediate — grace period is zero
        } else {
            Utc::now() + Duration::hours(self.grace_period_hours)
        };

        let rotation_status = if forced { "forced" } else { "active" };

        let mut tx = self.pool.begin().await?;

        // Insert new key.
        let new_key_id = sqlx::query_scalar!(
            r#"
            INSERT INTO api_keys
                (consumer_id, key_hash, key_prefix, description, is_active, expires_at, issued_by)
            VALUES ($1, $2, $3, 'Rotation replacement', TRUE, $4, $5)
            RETURNING id
            "#,
            old_key.consumer_id,
            key_hash,
            key_prefix,
            new_expires,
            initiated_by,
        )
        .fetch_one(&mut *tx)
        .await?;

        // Copy scopes to new key.
        for scope in &scopes {
            sqlx::query!(
                "INSERT INTO key_scopes (api_key_id, scope_name, granted_by) VALUES ($1, $2, $3)",
                new_key_id,
                scope,
                initiated_by,
            )
            .execute(&mut *tx)
            .await?;
        }

        // If forced, immediately deactivate old key.
        if forced {
            sqlx::query!(
                "UPDATE api_keys SET is_active = FALSE WHERE id = $1",
                key_id
            )
            .execute(&mut *tx)
            .await?;
        }

        // Insert rotation record.
        let rotation_id = sqlx::query_scalar!(
            r#"
            INSERT INTO key_rotations
                (old_key_id, new_key_id, grace_period_start, grace_period_end, status, initiated_by, forced)
            VALUES ($1, $2, now(), $3, $4, $5, $6)
            RETURNING id
            "#,
            key_id,
            new_key_id,
            grace_period_end,
            rotation_status,
            initiated_by,
            forced,
        )
        .fetch_one(&mut *tx)
        .await?;

        // Audit log entry.
        let action = if forced { "forced_rotation" } else { "rotated" };
        sqlx::query!(
            r#"
            INSERT INTO key_audit_log (api_key_id, consumer_id, action, initiated_by, metadata)
            VALUES ($1, $2, $3, $4, $5)
            "#,
            key_id,
            old_key.consumer_id,
            action,
            initiated_by,
            serde_json::json!({
                "new_key_id": new_key_id,
                "rotation_id": rotation_id,
                "grace_period_end": grace_period_end,
                "forced": forced,
            }),
        )
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        info!(
            old_key_id = %key_id,
            new_key_id = %new_key_id,
            rotation_id = %rotation_id,
            forced = forced,
            initiated_by = %initiated_by,
            "Key rotation completed"
        );

        Ok(RotationResult {
            rotation_id,
            new_key_id,
            new_key_plaintext: raw_key,
            grace_period_end,
        })
    }

    // ── Early grace period completion ─────────────────────────────────────────

    /// Consumer explicitly completes rotation before grace period expires,
    /// immediately invalidating the old key.
    pub async fn complete_rotation(
        &self,
        old_key_id: Uuid,
        initiated_by: &str,
    ) -> Result<(), RotationError> {
        let rotation = sqlx::query!(
            r#"
            SELECT id, new_key_id, old_key_id,
                   (SELECT consumer_id FROM api_keys WHERE id = old_key_id) AS consumer_id
            FROM key_rotations
            WHERE old_key_id = $1 AND status = 'active'
            "#,
            old_key_id
        )
        .fetch_optional(&self.pool)
        .await?
        .ok_or(RotationError::NoActiveRotation)?;

        let mut tx = self.pool.begin().await?;

        sqlx::query!(
            "UPDATE api_keys SET is_active = FALSE WHERE id = $1",
            old_key_id
        )
        .execute(&mut *tx)
        .await?;

        sqlx::query!(
            "UPDATE key_rotations SET status = 'completed', updated_at = now() WHERE id = $1",
            rotation.id
        )
        .execute(&mut *tx)
        .await?;

        sqlx::query!(
            r#"
            INSERT INTO key_audit_log (api_key_id, consumer_id, action, initiated_by, metadata)
            VALUES ($1, $2, 'grace_completed', $3, $4)
            "#,
            old_key_id,
            rotation.consumer_id,
            initiated_by,
            serde_json::json!({ "rotation_id": rotation.id, "new_key_id": rotation.new_key_id }),
        )
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        info!(
            old_key_id = %old_key_id,
            rotation_id = %rotation.id,
            "Rotation completed early by consumer"
        );
        Ok(())
    }

    // ── Background: expire grace periods ─────────────────────────────────────

    /// Called by the background worker. Invalidates old keys whose grace period
    /// has elapsed and marks the rotation as 'expired'.
    pub async fn expire_grace_periods(&self) -> Result<u64, RotationError> {
        let rows = sqlx::query!(
            r#"
            SELECT kr.id AS rotation_id, kr.old_key_id,
                   ak.consumer_id
            FROM key_rotations kr
            JOIN api_keys ak ON ak.id = kr.old_key_id
            WHERE kr.status = 'active'
              AND kr.grace_period_end <= now()
            "#
        )
        .fetch_all(&self.pool)
        .await?;

        let count = rows.len() as u64;
        for row in rows {
            let mut tx = self.pool.begin().await?;

            sqlx::query!(
                "UPDATE api_keys SET is_active = FALSE WHERE id = $1",
                row.old_key_id
            )
            .execute(&mut *tx)
            .await?;

            sqlx::query!(
                "UPDATE key_rotations SET status = 'expired', updated_at = now() WHERE id = $1",
                row.rotation_id
            )
            .execute(&mut *tx)
            .await?;

            sqlx::query!(
                r#"
                INSERT INTO key_audit_log (api_key_id, consumer_id, action, initiated_by, metadata)
                VALUES ($1, $2, 'expired', 'system', $3)
                "#,
                row.old_key_id,
                row.consumer_id,
                serde_json::json!({ "rotation_id": row.rotation_id }),
            )
            .execute(&mut *tx)
            .await?;

            tx.commit().await?;

            info!(
                old_key_id = %row.old_key_id,
                rotation_id = %row.rotation_id,
                "Grace period expired — old key invalidated"
            );
        }
        Ok(count)
    }

    // ── Background: expiry notifications ─────────────────────────────────────

    /// Queries for keys expiring within each warning window and records
    /// notifications. Returns the list of (consumer_id, key_id, warning_days)
    /// tuples that should be notified (deduplication already applied).
    pub async fn collect_expiry_notifications(
        &self,
    ) -> Result<Vec<(Uuid, Uuid, i32)>, RotationError> {
        let mut to_notify: Vec<(Uuid, Uuid, i32)> = Vec::new();

        for &days in EXPIRY_WARNING_DAYS {
            let window_start = Utc::now() + Duration::days(days as i64 - 1);
            let window_end = Utc::now() + Duration::days(days as i64);

            let rows = sqlx::query!(
                r#"
                SELECT ak.id AS key_id, ak.consumer_id
                FROM api_keys ak
                WHERE ak.is_active = TRUE
                  AND ak.expires_at > $1
                  AND ak.expires_at <= $2
                  AND NOT EXISTS (
                      SELECT 1 FROM key_expiry_notifications ken
                      WHERE ken.api_key_id = ak.id
                        AND ken.warning_days = $3
                  )
                "#,
                window_start,
                window_end,
                days,
            )
            .fetch_all(&self.pool)
            .await?;

            for row in rows {
                // Record notification to prevent duplicates.
                let inserted = sqlx::query!(
                    r#"
                    INSERT INTO key_expiry_notifications (api_key_id, consumer_id, warning_days)
                    VALUES ($1, $2, $3)
                    ON CONFLICT (api_key_id, warning_days) DO NOTHING
                    "#,
                    row.key_id,
                    row.consumer_id,
                    days,
                )
                .execute(&self.pool)
                .await?;

                if inserted.rows_affected() > 0 {
                    to_notify.push((row.consumer_id, row.key_id, days));
                }
            }
        }

        // Final expiry notification (warning_days = 0) for keys that just expired.
        let just_expired = sqlx::query!(
            r#"
            SELECT ak.id AS key_id, ak.consumer_id
            FROM api_keys ak
            WHERE ak.is_active = FALSE
              AND ak.expires_at >= now() - INTERVAL '1 day'
              AND ak.expires_at < now()
              AND NOT EXISTS (
                  SELECT 1 FROM key_expiry_notifications ken
                  WHERE ken.api_key_id = ak.id AND ken.warning_days = 0
              )
            "#
        )
        .fetch_all(&self.pool)
        .await?;

        for row in just_expired {
            let inserted = sqlx::query!(
                r#"
                INSERT INTO key_expiry_notifications (api_key_id, consumer_id, warning_days)
                VALUES ($1, $2, 0)
                ON CONFLICT (api_key_id, warning_days) DO NOTHING
                "#,
                row.key_id,
                row.consumer_id,
            )
            .execute(&self.pool)
            .await?;

            if inserted.rows_affected() > 0 {
                to_notify.push((row.consumer_id, row.key_id, 0));
            }
        }

        Ok(to_notify)
    }
}

// ─── Expiry check helper (used by middleware) ─────────────────────────────────

/// Checks whether a key is within an active grace period.
/// Returns `Some(grace_period_end)` if the old key is still valid under grace.
pub async fn check_grace_period(
    pool: &PgPool,
    key_id: Uuid,
) -> Option<DateTime<Utc>> {
    sqlx::query_scalar!(
        r#"
        SELECT grace_period_end
        FROM key_rotations
        WHERE old_key_id = $1
          AND status = 'active'
          AND grace_period_end > now()
        "#,
        key_id
    )
    .fetch_optional(pool)
    .await
    .ok()
    .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    // ── Unit tests (no DB required) ───────────────────────────────────────────

    #[test]
    fn test_hash_key_is_deterministic() {
        let raw = "test_api_key_abc123";
        assert_eq!(hash_key(raw), hash_key(raw));
    }

    #[test]
    fn test_hash_key_different_inputs_differ() {
        assert_ne!(hash_key("key_a"), hash_key("key_b"));
    }

    #[test]
    fn test_generate_api_key_length() {
        let key = generate_api_key();
        assert_eq!(key.len(), 64, "Generated key should be 64 hex chars");
    }

    #[test]
    fn test_generate_api_key_uniqueness() {
        let k1 = generate_api_key();
        let k2 = generate_api_key();
        assert_ne!(k1, k2, "Two generated keys must differ");
    }

    #[test]
    fn test_expiry_warning_days_contains_all_thresholds() {
        assert!(EXPIRY_WARNING_DAYS.contains(&30));
        assert!(EXPIRY_WARNING_DAYS.contains(&14));
        assert!(EXPIRY_WARNING_DAYS.contains(&7));
        assert!(EXPIRY_WARNING_DAYS.contains(&1));
    }

    #[test]
    fn test_grace_period_end_is_in_future() {
        let grace_end = Utc::now() + Duration::hours(DEFAULT_GRACE_PERIOD_HOURS);
        assert!(grace_end > Utc::now());
    }

    #[test]
    fn test_lifetime_exceeds_max_error_message() {
        let err = RotationError::LifetimeExceedsMax {
            requested: 100,
            max: 90,
            consumer_type: "third_party_partner".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("100"));
        assert!(msg.contains("90"));
        assert!(msg.contains("third_party_partner"));
    }

    #[test]
    fn test_missing_expiry_error() {
        let err = RotationError::MissingExpiry;
        assert!(err.to_string().contains("expiry"));
    }

    #[test]
    fn test_key_prefix_is_first_8_chars() {
        let raw = generate_api_key();
        let prefix = &raw[..8];
        assert_eq!(prefix.len(), 8);
    }
}
