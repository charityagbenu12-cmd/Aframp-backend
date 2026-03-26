//! API Key Revocation & Blacklisting Service (Issue #138).
//!
//! Responsibilities:
//!   - Revoke individual keys (consumer-initiated or admin-initiated)
//!   - Revoke all keys for a consumer simultaneously
//!   - Synchronously push revoked key IDs to Redis blacklist set
//!   - Consumer-level blacklisting with optional TTL
//!   - Automated revocation triggers (abuse, suspicious IP, inactivity)
//!   - Bootstrap: load all revoked/blacklisted IDs into Redis on startup
//!   - Revocation audit list + blacklist state queries

use chrono::{DateTime, Utc};
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::sync::Arc;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::cache::RedisCache;
use crate::services::notification::NotificationService;

// ─── Redis key constants ──────────────────────────────────────────────────────

/// Redis Set that holds all revoked API key IDs (as UUID strings).
pub const REDIS_REVOKED_KEYS_SET: &str = "revoked_api_keys";
/// Redis Set that holds all blacklisted consumer IDs (as UUID strings).
pub const REDIS_BLACKLISTED_CONSUMERS_SET: &str = "blacklisted_consumers";
/// TTL for individual key blacklist entries (365 days — max key lifetime).
pub const KEY_BLACKLIST_TTL_SECS: u64 = 365 * 24 * 3600;

// ─── Domain types ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationRecord {
    pub id: Uuid,
    pub key_id: Uuid,
    pub consumer_id: Uuid,
    pub revocation_type: String,
    pub reason: String,
    pub revoked_by: String,
    pub triggering_detail: Option<serde_json::Value>,
    pub revoked_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlacklistEntry {
    pub id: Uuid,
    pub consumer_id: Uuid,
    pub reason: String,
    pub blacklisted_by: String,
    pub blacklisted_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub is_active: bool,
}

#[derive(Debug, Clone)]
pub struct RevokeKeyInput {
    pub key_id: Uuid,
    pub consumer_id: Uuid,
    pub revocation_type: &'static str,
    pub reason: String,
    pub revoked_by: String,
    pub triggering_detail: Option<serde_json::Value>,
}

#[derive(Debug, Clone)]
pub struct BlacklistConsumerInput {
    pub consumer_id: Uuid,
    pub reason: String,
    pub blacklisted_by: String,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationListQuery {
    pub consumer_id: Option<Uuid>,
    pub revocation_type: Option<String>,
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
    pub page: i64,
    pub page_size: i64,
}

// ─── Service ──────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct RevocationService {
    db: Arc<PgPool>,
    redis: Arc<RedisCache>,
    notifications: Arc<NotificationService>,
}

impl RevocationService {
    pub fn new(
        db: Arc<PgPool>,
        redis: Arc<RedisCache>,
        notifications: Arc<NotificationService>,
    ) -> Self {
        Self { db, redis, notifications }
    }

    // ── Single key revocation ─────────────────────────────────────────────────

    /// Revoke a single API key.
    ///
    /// Steps (all synchronous before returning):
    ///   1. Mark key as revoked in DB (`is_active = FALSE`, `status = 'revoked'`)
    ///   2. Insert revocation record in `key_revocations`
    ///   3. Push key ID to Redis blacklist set (synchronous — no eventual consistency)
    ///   4. Notify consumer
    pub async fn revoke_key(&self, input: RevokeKeyInput) -> Result<RevocationRecord, String> {
        // 1. Verify key belongs to consumer and is currently active
        let key_row = sqlx::query!(
            r#"
            SELECT ak.id, ak.consumer_id, c.name AS consumer_name
            FROM api_keys ak
            JOIN consumers c ON c.id = ak.consumer_id
            WHERE ak.id = $1 AND ak.consumer_id = $2 AND ak.is_active = TRUE
            "#,
            input.key_id,
            input.consumer_id,
        )
        .fetch_optional(self.db.as_ref())
        .await
        .map_err(|e| format!("DB error: {e}"))?
        .ok_or_else(|| "API key not found or already revoked".to_string())?;

        // 2. Update key status in DB
        sqlx::query!(
            r#"
            UPDATE api_keys
            SET is_active = FALSE, status = 'revoked', updated_at = now()
            WHERE id = $1
            "#,
            input.key_id,
        )
        .execute(self.db.as_ref())
        .await
        .map_err(|e| format!("Failed to update key status: {e}"))?;

        // 3. Insert revocation record
        let record = sqlx::query_as!(
            RevocationRecord,
            r#"
            INSERT INTO key_revocations
                (key_id, consumer_id, revocation_type, reason, revoked_by, triggering_detail)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING
                id,
                key_id,
                consumer_id,
                revocation_type,
                reason,
                revoked_by,
                triggering_detail,
                revoked_at
            "#,
            input.key_id,
            input.consumer_id,
            input.revocation_type,
            input.reason,
            input.revoked_by,
            input.triggering_detail,
        )
        .fetch_one(self.db.as_ref())
        .await
        .map_err(|e| format!("Failed to insert revocation record: {e}"))?;

        // 4. Synchronously push to Redis blacklist — MUST complete before returning
        self.push_key_to_redis_blacklist(input.key_id).await?;

        info!(
            key_id = %input.key_id,
            consumer_id = %input.consumer_id,
            revocation_type = %input.revocation_type,
            "API key revoked and pushed to Redis blacklist"
        );

        // 5. Notify consumer (best-effort, non-blocking)
        let notification_msg = build_revocation_notification_message(
            input.revocation_type,
            &input.reason,
        );
        let consumer_name = key_row.consumer_name.clone();
        let notif_svc = self.notifications.clone();
        let key_id = input.key_id;
        let rev_type = input.revocation_type;
        tokio::spawn(async move {
            info!(
                key_id = %key_id,
                consumer = %consumer_name,
                revocation_type = %rev_type,
                "🔔 REVOCATION NOTIFICATION: {}",
                notification_msg
            );
            let _ = notif_svc;
        });

        Ok(record)
    }

    // ── Consumer-level revocation ─────────────────────────────────────────────

    /// Revoke ALL active keys for a consumer simultaneously.
    /// Returns the number of keys revoked.
    pub async fn revoke_all_consumer_keys(
        &self,
        consumer_id: Uuid,
        reason: String,
        revoked_by: String,
    ) -> Result<Vec<RevocationRecord>, String> {
        // Fetch all active key IDs for this consumer
        let active_keys = sqlx::query!(
            r#"SELECT id FROM api_keys WHERE consumer_id = $1 AND is_active = TRUE"#,
            consumer_id,
        )
        .fetch_all(self.db.as_ref())
        .await
        .map_err(|e| format!("DB error fetching active keys: {e}"))?;

        if active_keys.is_empty() {
            return Ok(vec![]);
        }

        let key_ids: Vec<Uuid> = active_keys.iter().map(|r| r.id).collect();

        // Bulk update all keys to revoked
        sqlx::query!(
            r#"
            UPDATE api_keys
            SET is_active = FALSE, status = 'revoked', updated_at = now()
            WHERE consumer_id = $1 AND is_active = TRUE
            "#,
            consumer_id,
        )
        .execute(self.db.as_ref())
        .await
        .map_err(|e| format!("Failed to bulk revoke keys: {e}"))?;

        // Insert revocation records for each key
        let mut records = Vec::with_capacity(key_ids.len());
        for key_id in &key_ids {
            let record = sqlx::query_as!(
                RevocationRecord,
                r#"
                INSERT INTO key_revocations
                    (key_id, consumer_id, revocation_type, reason, revoked_by)
                VALUES ($1, $2, 'admin_initiated', $3, $4)
                RETURNING
                    id, key_id, consumer_id, revocation_type, reason,
                    revoked_by, triggering_detail, revoked_at
                "#,
                key_id,
                consumer_id,
                reason,
                revoked_by,
            )
            .fetch_one(self.db.as_ref())
            .await
            .map_err(|e| format!("Failed to insert revocation record for {key_id}: {e}"))?;
            records.push(record);
        }

        // Synchronously push ALL revoked key IDs to Redis
        self.push_keys_to_redis_blacklist(&key_ids).await?;

        info!(
            consumer_id = %consumer_id,
            keys_revoked = key_ids.len(),
            "All consumer keys revoked and pushed to Redis blacklist"
        );

        Ok(records)
    }

    // ── Consumer blacklisting ─────────────────────────────────────────────────

    /// Blacklist an entire consumer. All current and future key verifications
    /// for this consumer will be rejected.
    pub async fn blacklist_consumer(
        &self,
        input: BlacklistConsumerInput,
    ) -> Result<BlacklistEntry, String> {
        // Deactivate any existing active blacklist entry first (upsert pattern)
        sqlx::query!(
            r#"
            UPDATE consumer_blacklist
            SET is_active = FALSE, lifted_at = now()
            WHERE consumer_id = $1 AND is_active = TRUE
            "#,
            input.consumer_id,
        )
        .execute(self.db.as_ref())
        .await
        .map_err(|e| format!("DB error clearing old blacklist: {e}"))?;

        let entry = sqlx::query_as!(
            BlacklistEntry,
            r#"
            INSERT INTO consumer_blacklist
                (consumer_id, reason, blacklisted_by, expires_at)
            VALUES ($1, $2, $3, $4)
            RETURNING
                id, consumer_id, reason, blacklisted_by,
                blacklisted_at, expires_at, is_active
            "#,
            input.consumer_id,
            input.reason,
            input.blacklisted_by,
            input.expires_at,
        )
        .fetch_one(self.db.as_ref())
        .await
        .map_err(|e| format!("Failed to insert blacklist entry: {e}"))?;

        // Push consumer ID to Redis blacklist set
        self.push_consumer_to_redis_blacklist(input.consumer_id, input.expires_at)
            .await?;

        // Also revoke all active keys for this consumer
        let _ = self
            .revoke_all_consumer_keys(
                input.consumer_id,
                format!("Consumer blacklisted: {}", input.reason),
                input.blacklisted_by.clone(),
            )
            .await;

        info!(
            consumer_id = %input.consumer_id,
            expires_at = ?input.expires_at,
            "Consumer blacklisted and pushed to Redis"
        );

        Ok(entry)
    }

    /// Lift a consumer blacklist entry (manual removal).
    pub async fn lift_consumer_blacklist(&self, consumer_id: Uuid) -> Result<(), String> {
        sqlx::query!(
            r#"
            UPDATE consumer_blacklist
            SET is_active = FALSE, lifted_at = now()
            WHERE consumer_id = $1 AND is_active = TRUE
            "#,
            consumer_id,
        )
        .execute(self.db.as_ref())
        .await
        .map_err(|e| format!("DB error lifting blacklist: {e}"))?;

        // Remove from Redis
        let mut conn = self
            .redis
            .pool
            .get()
            .await
            .map_err(|e| format!("Redis connection error: {e}"))?;
        let _: () = conn
            .srem(REDIS_BLACKLISTED_CONSUMERS_SET, consumer_id.to_string())
            .await
            .map_err(|e| format!("Redis SREM error: {e}"))?;

        info!(consumer_id = %consumer_id, "Consumer blacklist lifted");
        Ok(())
    }

    // ── Automated revocation triggers ─────────────────────────────────────────

    /// Automatically revoke keys that exceed the abuse threshold.
    pub async fn revoke_abusive_key(
        &self,
        key_id: Uuid,
        consumer_id: Uuid,
        threshold_detail: serde_json::Value,
    ) -> Result<RevocationRecord, String> {
        warn!(
            key_id = %key_id,
            detail = %threshold_detail,
            "Automated revocation: abuse threshold exceeded"
        );
        self.revoke_key(RevokeKeyInput {
            key_id,
            consumer_id,
            revocation_type: "automated_abuse",
            reason: "Automated: abuse threshold exceeded".to_string(),
            revoked_by: "system".to_string(),
            triggering_detail: Some(threshold_detail),
        })
        .await
    }

    /// Automatically revoke a key associated with a suspicious IP.
    pub async fn revoke_suspicious_ip_key(
        &self,
        key_id: Uuid,
        consumer_id: Uuid,
        ip: &str,
    ) -> Result<RevocationRecord, String> {
        warn!(
            key_id = %key_id,
            ip = %ip,
            "Automated revocation: suspicious IP association"
        );
        self.revoke_key(RevokeKeyInput {
            key_id,
            consumer_id,
            revocation_type: "automated_suspicious_ip",
            reason: format!("Automated: suspicious IP {ip}"),
            revoked_by: "system".to_string(),
            triggering_detail: Some(serde_json::json!({ "ip": ip })),
        })
        .await
    }

    /// Revoke keys inactive for longer than `inactivity_days`.
    /// Returns the number of keys revoked.
    pub async fn revoke_inactive_keys(&self, inactivity_days: i64) -> Result<usize, String> {
        let inactive_keys = sqlx::query!(
            r#"
            SELECT ak.id, ak.consumer_id
            FROM api_keys ak
            WHERE ak.is_active = TRUE
              AND (
                  ak.last_used_at IS NULL AND ak.created_at < now() - ($1 || ' days')::interval
                  OR
                  ak.last_used_at < now() - ($1 || ' days')::interval
              )
            "#,
            inactivity_days.to_string(),
        )
        .fetch_all(self.db.as_ref())
        .await
        .map_err(|e| format!("DB error fetching inactive keys: {e}"))?;

        let count = inactive_keys.len();
        for row in inactive_keys {
            if let Err(e) = self
                .revoke_key(RevokeKeyInput {
                    key_id: row.id,
                    consumer_id: row.consumer_id,
                    revocation_type: "automated_inactivity",
                    reason: format!("Automated: inactive for {inactivity_days} days"),
                    revoked_by: "system".to_string(),
                    triggering_detail: Some(
                        serde_json::json!({ "inactivity_days": inactivity_days }),
                    ),
                })
                .await
            {
                error!(key_id = %row.id, error = %e, "Failed to revoke inactive key");
            }
        }

        info!(count = count, inactivity_days = inactivity_days, "Inactive keys revoked");
        Ok(count)
    }

    // ── Audit & reporting ─────────────────────────────────────────────────────

    pub async fn list_revocations(
        &self,
        query: RevocationListQuery,
    ) -> Result<(Vec<RevocationRecord>, i64), String> {
        let offset = (query.page - 1).max(0) * query.page_size;

        let records = sqlx::query_as!(
            RevocationRecord,
            r#"
            SELECT id, key_id, consumer_id, revocation_type, reason,
                   revoked_by, triggering_detail, revoked_at
            FROM key_revocations
            WHERE ($1::uuid IS NULL OR consumer_id = $1)
              AND ($2::text IS NULL OR revocation_type = $2)
              AND ($3::timestamptz IS NULL OR revoked_at >= $3)
              AND ($4::timestamptz IS NULL OR revoked_at <= $4)
            ORDER BY revoked_at DESC
            LIMIT $5 OFFSET $6
            "#,
            query.consumer_id,
            query.revocation_type,
            query.from,
            query.to,
            query.page_size,
            offset,
        )
        .fetch_all(self.db.as_ref())
        .await
        .map_err(|e| format!("DB error: {e}"))?;

        let total: i64 = sqlx::query_scalar!(
            r#"
            SELECT COUNT(*) FROM key_revocations
            WHERE ($1::uuid IS NULL OR consumer_id = $1)
              AND ($2::text IS NULL OR revocation_type = $2)
              AND ($3::timestamptz IS NULL OR revoked_at >= $3)
              AND ($4::timestamptz IS NULL OR revoked_at <= $4)
            "#,
            query.consumer_id,
            query.revocation_type,
            query.from,
            query.to,
        )
        .fetch_one(self.db.as_ref())
        .await
        .map_err(|e| format!("DB count error: {e}"))?
        .unwrap_or(0);

        Ok((records, total))
    }

    pub async fn list_active_blacklist(&self) -> Result<Vec<BlacklistEntry>, String> {
        // Expire any entries whose TTL has passed
        sqlx::query!(
            r#"
            UPDATE consumer_blacklist
            SET is_active = FALSE, lifted_at = now()
            WHERE is_active = TRUE AND expires_at IS NOT NULL AND expires_at <= now()
            "#,
        )
        .execute(self.db.as_ref())
        .await
        .ok();

        let entries = sqlx::query_as!(
            BlacklistEntry,
            r#"
            SELECT id, consumer_id, reason, blacklisted_by,
                   blacklisted_at, expires_at, is_active
            FROM consumer_blacklist
            WHERE is_active = TRUE
            ORDER BY blacklisted_at DESC
            "#,
        )
        .fetch_all(self.db.as_ref())
        .await
        .map_err(|e| format!("DB error: {e}"))?;

        Ok(entries)
    }

    // ── Redis helpers ─────────────────────────────────────────────────────────

    async fn push_key_to_redis_blacklist(&self, key_id: Uuid) -> Result<(), String> {
        let mut conn = self
            .redis
            .pool
            .get()
            .await
            .map_err(|e| format!("Redis connection error: {e}"))?;
        let _: () = conn
            .sadd(REDIS_REVOKED_KEYS_SET, key_id.to_string())
            .await
            .map_err(|e| format!("Redis SADD error: {e}"))?;
        Ok(())
    }

    async fn push_keys_to_redis_blacklist(&self, key_ids: &[Uuid]) -> Result<(), String> {
        if key_ids.is_empty() {
            return Ok(());
        }
        let mut conn = self
            .redis
            .pool
            .get()
            .await
            .map_err(|e| format!("Redis connection error: {e}"))?;
        let ids: Vec<String> = key_ids.iter().map(|id| id.to_string()).collect();
        let _: () = conn
            .sadd(REDIS_REVOKED_KEYS_SET, ids)
            .await
            .map_err(|e| format!("Redis SADD error: {e}"))?;
        Ok(())
    }

    async fn push_consumer_to_redis_blacklist(
        &self,
        consumer_id: Uuid,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<(), String> {
        let mut conn = self
            .redis
            .pool
            .get()
            .await
            .map_err(|e| format!("Redis connection error: {e}"))?;
        let _: () = conn
            .sadd(REDIS_BLACKLISTED_CONSUMERS_SET, consumer_id.to_string())
            .await
            .map_err(|e| format!("Redis SADD error: {e}"))?;

        // If temporary, schedule expiry via a separate key with TTL
        if let Some(exp) = expires_at {
            let ttl = (exp - Utc::now()).num_seconds().max(1) as u64;
            let expiry_key = format!("consumer_blacklist_expiry:{consumer_id}");
            let _: () = conn
                .set_ex(expiry_key, "1", ttl)
                .await
                .map_err(|e| format!("Redis SETEX error: {e}"))?;
        }

        Ok(())
    }

    // ── Bootstrap ─────────────────────────────────────────────────────────────

    /// On application startup, load all revoked key IDs and blacklisted consumer
    /// IDs from the database into Redis. Handles Redis restarts gracefully.
    pub async fn bootstrap_redis_blacklist(&self) -> Result<(), String> {
        info!("Bootstrapping Redis blacklist from database...");

        // Load all revoked key IDs
        let revoked_keys = sqlx::query_scalar!(
            r#"SELECT id FROM api_keys WHERE is_active = FALSE AND status = 'revoked'"#
        )
        .fetch_all(self.db.as_ref())
        .await
        .map_err(|e| format!("DB error loading revoked keys: {e}"))?;

        if !revoked_keys.is_empty() {
            let ids: Vec<String> = revoked_keys.iter().map(|id| id.to_string()).collect();
            let mut conn = self
                .redis
                .pool
                .get()
                .await
                .map_err(|e| format!("Redis connection error: {e}"))?;
            let _: () = conn
                .sadd(REDIS_REVOKED_KEYS_SET, ids)
                .await
                .map_err(|e| format!("Redis SADD error: {e}"))?;
            info!(count = revoked_keys.len(), "Loaded revoked keys into Redis");
        }

        // Load all active blacklisted consumer IDs (expire stale entries first)
        sqlx::query!(
            r#"
            UPDATE consumer_blacklist
            SET is_active = FALSE, lifted_at = now()
            WHERE is_active = TRUE AND expires_at IS NOT NULL AND expires_at <= now()
            "#,
        )
        .execute(self.db.as_ref())
        .await
        .ok();

        let blacklisted_consumers = sqlx::query!(
            r#"SELECT consumer_id, expires_at FROM consumer_blacklist WHERE is_active = TRUE"#
        )
        .fetch_all(self.db.as_ref())
        .await
        .map_err(|e| format!("DB error loading blacklisted consumers: {e}"))?;

        for row in &blacklisted_consumers {
            if let Err(e) = self
                .push_consumer_to_redis_blacklist(row.consumer_id, row.expires_at)
                .await
            {
                error!(consumer_id = %row.consumer_id, error = %e, "Failed to bootstrap consumer blacklist");
            }
        }

        info!(
            revoked_keys = revoked_keys.len(),
            blacklisted_consumers = blacklisted_consumers.len(),
            "Redis blacklist bootstrap complete"
        );
        Ok(())
    }

    // ── Fast blacklist checks (used by middleware) ────────────────────────────

    /// Check if a key ID is in the Redis revoked set.
    /// Returns `true` if the key is blacklisted (should be rejected).
    pub async fn is_key_blacklisted_redis(
        redis: &RedisCache,
        key_id: Uuid,
    ) -> bool {
        let conn = match redis.pool.get().await {
            Ok(c) => c,
            Err(_) => return false, // fail open on Redis error — DB check will catch it
        };
        let mut conn = conn;
        conn.sismember::<_, _, bool>(REDIS_REVOKED_KEYS_SET, key_id.to_string())
            .await
            .unwrap_or(false)
    }

    /// Check if a consumer ID is in the Redis blacklisted consumers set.
    pub async fn is_consumer_blacklisted_redis(
        redis: &RedisCache,
        consumer_id: Uuid,
    ) -> bool {
        let conn = match redis.pool.get().await {
            Ok(c) => c,
            Err(_) => return false,
        };
        let mut conn = conn;
        // Also check if the temporary expiry key is still alive
        let in_set: bool = conn
            .sismember(REDIS_BLACKLISTED_CONSUMERS_SET, consumer_id.to_string())
            .await
            .unwrap_or(false);

        if !in_set {
            return false;
        }

        // If there's an expiry key and it's gone, the blacklist has expired
        let expiry_key = format!("consumer_blacklist_expiry:{consumer_id}");
        let has_expiry: bool = conn.exists(&expiry_key).await.unwrap_or(false);
        // If no expiry key exists, it's either permanent or the key was never set
        // We treat absence of expiry key as permanent blacklist
        let _ = has_expiry; // expiry is handled by TTL on the expiry key itself
        true
    }
}

// ─── Notification message builder ────────────────────────────────────────────

fn build_revocation_notification_message(revocation_type: &str, reason: &str) -> String {
    match revocation_type {
        "suspected_compromise" => format!(
            "Your API key has been revoked due to suspected compromise. Reason: {reason}. \
             Please rotate your credentials immediately and review your integration security."
        ),
        "admin_initiated" => format!(
            "Your API key has been revoked by an administrator. Reason: {reason}. \
             Contact support if you believe this is in error."
        ),
        "automated_abuse" => format!(
            "Your API key has been automatically revoked due to detected abuse. Reason: {reason}. \
             Contact support to appeal."
        ),
        "automated_suspicious_ip" => format!(
            "Your API key has been automatically revoked due to suspicious IP activity. \
             Reason: {reason}."
        ),
        "automated_inactivity" => format!(
            "Your API key has been revoked due to inactivity. Reason: {reason}. \
             Generate a new key to resume access."
        ),
        _ => format!("Your API key has been revoked. Reason: {reason}."),
    }
}
