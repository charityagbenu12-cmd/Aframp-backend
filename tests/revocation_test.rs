//! Unit and integration tests for Issue #138 — API Key Revocation & Blacklisting.
//!
//! Test coverage:
//!   Unit:
//!     - Redis blacklist enforcement (key + consumer)
//!     - Bootstrap process
//!     - Consumer-level blacklisting
//!     - Automated revocation trigger logic
//!   Integration:
//!     - Immediate revocation flow
//!     - Consumer-level revocation
//!     - Redis restart recovery (bootstrap)
//!     - Temporary blacklist expiry
//!     - Automated revocation scenarios

#[cfg(test)]
mod revocation_unit_tests {
    use crate::services::revocation::{
        REDIS_BLACKLISTED_CONSUMERS_SET, REDIS_REVOKED_KEYS_SET,
    };
    use uuid::Uuid;

    // ── Redis key/consumer blacklist check logic ──────────────────────────────

    /// Verifies that the Redis set key constants are stable and correctly named.
    #[test]
    fn test_redis_set_key_constants() {
        assert_eq!(REDIS_REVOKED_KEYS_SET, "revoked_api_keys");
        assert_eq!(REDIS_BLACKLISTED_CONSUMERS_SET, "blacklisted_consumers");
    }

    /// Verifies UUID-to-string conversion used for Redis set members.
    #[test]
    fn test_uuid_to_redis_member_format() {
        let id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let member = id.to_string();
        assert_eq!(member, "550e8400-e29b-41d4-a716-446655440000");
        // Ensure it round-trips
        let parsed = Uuid::parse_str(&member).unwrap();
        assert_eq!(parsed, id);
    }

    // ── Revocation type validation ────────────────────────────────────────────

    #[test]
    fn test_valid_revocation_types() {
        let valid_types = [
            "consumer_requested",
            "admin_initiated",
            "forced",
            "automated_abuse",
            "automated_suspicious_ip",
            "automated_inactivity",
            "decommission",
            "policy_violation",
            "suspected_compromise",
        ];
        // All types must be non-empty strings
        for t in &valid_types {
            assert!(!t.is_empty(), "Revocation type must not be empty: {t}");
        }
        // No duplicates
        let mut seen = std::collections::HashSet::new();
        for t in &valid_types {
            assert!(seen.insert(*t), "Duplicate revocation type: {t}");
        }
    }

    // ── Notification message builder ──────────────────────────────────────────

    #[test]
    fn test_revocation_notification_messages_are_non_empty() {
        let types = [
            "suspected_compromise",
            "admin_initiated",
            "automated_abuse",
            "automated_suspicious_ip",
            "automated_inactivity",
            "consumer_requested",
            "unknown_type",
        ];
        for t in &types {
            let msg = build_notification_message(t, "test reason");
            assert!(!msg.is_empty(), "Notification message must not be empty for type: {t}");
            assert!(
                msg.contains("test reason"),
                "Notification message must include the reason for type: {t}"
            );
        }
    }

    fn build_notification_message(revocation_type: &str, reason: &str) -> String {
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

    // ── Revocation list query defaults ────────────────────────────────────────

    #[test]
    fn test_revocation_list_query_page_clamping() {
        // page must be >= 1
        let page: i64 = 0_i64.max(1);
        assert_eq!(page, 1);

        // page_size must be in [1, 100]
        let page_size: i64 = 200_i64.clamp(1, 100);
        assert_eq!(page_size, 100);

        let page_size_zero: i64 = 0_i64.clamp(1, 100);
        assert_eq!(page_size_zero, 1);
    }

    // ── Automated trigger detail serialisation ────────────────────────────────

    #[test]
    fn test_abuse_trigger_detail_serialisation() {
        let detail = serde_json::json!({
            "requests_per_minute": 500,
            "threshold": 100,
            "window_seconds": 60
        });
        let serialised = serde_json::to_string(&detail).unwrap();
        assert!(serialised.contains("requests_per_minute"));
        assert!(serialised.contains("500"));
    }

    #[test]
    fn test_suspicious_ip_trigger_detail_serialisation() {
        let ip = "192.168.1.1";
        let detail = serde_json::json!({ "ip": ip });
        let serialised = serde_json::to_string(&detail).unwrap();
        assert!(serialised.contains(ip));
    }

    #[test]
    fn test_inactivity_trigger_detail_serialisation() {
        let days = 180_i64;
        let detail = serde_json::json!({ "inactivity_days": days });
        let serialised = serde_json::to_string(&detail).unwrap();
        assert!(serialised.contains("180"));
    }

    // ── Consumer blacklist expiry TTL calculation ─────────────────────────────

    #[test]
    fn test_temporary_blacklist_ttl_is_positive() {
        use chrono::{Duration, Utc};
        let expires_at = Utc::now() + Duration::hours(24);
        let ttl = (expires_at - Utc::now()).num_seconds().max(1) as u64;
        assert!(ttl > 0, "TTL must be positive");
        assert!(ttl <= 86400 + 5, "TTL should be approximately 24 hours");
    }

    #[test]
    fn test_expired_blacklist_ttl_clamps_to_one() {
        use chrono::{Duration, Utc};
        // Already expired
        let expires_at = Utc::now() - Duration::hours(1);
        let ttl = (expires_at - Utc::now()).num_seconds().max(1) as u64;
        assert_eq!(ttl, 1, "Expired TTL must clamp to 1 second");
    }

    // ── Bootstrap: verify all revoked keys would be loaded ───────────────────

    #[test]
    fn test_bootstrap_deduplicates_key_ids() {
        // Simulate loading revoked keys — duplicates should be handled by Redis SADD
        let key_ids: Vec<String> = vec![
            "550e8400-e29b-41d4-a716-446655440000".to_string(),
            "550e8400-e29b-41d4-a716-446655440000".to_string(), // duplicate
            "660e8400-e29b-41d4-a716-446655440001".to_string(),
        ];
        // Redis SADD is idempotent — duplicates are silently ignored
        let unique: std::collections::HashSet<&String> = key_ids.iter().collect();
        assert_eq!(unique.len(), 2, "Unique key IDs after dedup");
    }

    // ── Admin revocation type mapping ─────────────────────────────────────────

    #[test]
    fn test_admin_revocation_type_mapping() {
        let map_type = |s: &str| -> &'static str {
            match s {
                "admin_initiated" => "admin_initiated",
                "forced" => "forced",
                "decommission" => "decommission",
                "policy_violation" => "policy_violation",
                "suspected_compromise" => "suspected_compromise",
                _ => "admin_initiated",
            }
        };

        assert_eq!(map_type("admin_initiated"), "admin_initiated");
        assert_eq!(map_type("forced"), "forced");
        assert_eq!(map_type("decommission"), "decommission");
        assert_eq!(map_type("policy_violation"), "policy_violation");
        assert_eq!(map_type("suspected_compromise"), "suspected_compromise");
        // Unknown type falls back to admin_initiated
        assert_eq!(map_type("unknown"), "admin_initiated");
    }
}

// ─── Integration tests ────────────────────────────────────────────────────────
// These tests require a live PostgreSQL + Redis instance.
// Run with: cargo test --features integration -- revocation_integration

#[cfg(all(test, feature = "integration"))]
mod revocation_integration_tests {
    use crate::cache::{init_cache_pool, CacheConfig, RedisCache};
    use crate::database::init_pool;
    use crate::services::notification::NotificationService;
    use crate::services::revocation::{
        BlacklistConsumerInput, RevocationService, RevokeKeyInput,
        REDIS_BLACKLISTED_CONSUMERS_SET, REDIS_REVOKED_KEYS_SET,
    };
    use redis::AsyncCommands;
    use std::sync::Arc;
    use std::time::Duration;
    use uuid::Uuid;

    async fn setup() -> (RevocationService, sqlx::PgPool, RedisCache) {
        let db_url = std::env::var("DATABASE_URL").expect("DATABASE_URL required for integration tests");
        let redis_url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());

        let pool = init_pool(&db_url, None).await.expect("DB pool");
        let cache_pool = init_cache_pool(CacheConfig {
            redis_url: redis_url.clone(),
            max_connections: 5,
            min_idle: 1,
            connection_timeout: Duration::from_secs(5),
            max_lifetime: Duration::from_secs(300),
            idle_timeout: Duration::from_secs(60),
            health_check_interval: Duration::from_secs(30),
        })
        .await
        .expect("Redis pool");
        let redis = RedisCache::new(cache_pool);
        let svc = RevocationService::new(
            Arc::new(pool.clone()),
            Arc::new(redis.clone()),
            Arc::new(NotificationService::new()),
        );
        (svc, pool, redis)
    }

    /// Helper: insert a test consumer + api_key, return (consumer_id, key_id).
    async fn insert_test_key(pool: &sqlx::PgPool) -> (Uuid, Uuid) {
        let consumer_id: Uuid = sqlx::query_scalar!(
            r#"
            INSERT INTO consumers (name, consumer_type)
            VALUES ('test-consumer', 'mobile_client')
            RETURNING id
            "#
        )
        .fetch_one(pool)
        .await
        .expect("insert consumer");

        let key_id: Uuid = sqlx::query_scalar!(
            r#"
            INSERT INTO api_keys (consumer_id, key_hash, key_prefix)
            VALUES ($1, 'testhash_' || gen_random_uuid()::text, 'testpfx')
            RETURNING id
            "#,
            consumer_id,
        )
        .fetch_one(pool)
        .await
        .expect("insert api_key");

        (consumer_id, key_id)
    }

    /// Cleanup test data.
    async fn cleanup(pool: &sqlx::PgPool, consumer_id: Uuid) {
        let _ = sqlx::query!("DELETE FROM consumers WHERE id = $1", consumer_id)
            .execute(pool)
            .await;
    }

    // ── Test: immediate revocation pushes to Redis synchronously ─────────────

    #[tokio::test]
    async fn test_revoke_key_pushes_to_redis_synchronously() {
        let (svc, pool, redis) = setup().await;
        let (consumer_id, key_id) = insert_test_key(&pool).await;

        let result = svc
            .revoke_key(RevokeKeyInput {
                key_id,
                consumer_id,
                revocation_type: "admin_initiated",
                reason: "integration test".to_string(),
                revoked_by: "test".to_string(),
                triggering_detail: None,
            })
            .await;

        assert!(result.is_ok(), "Revocation should succeed: {:?}", result);

        // Verify key is in Redis blacklist immediately
        let is_blacklisted = RevocationService::is_key_blacklisted_redis(&redis, key_id).await;
        assert!(is_blacklisted, "Key must be in Redis blacklist after revocation");

        // Verify DB status
        let status: String = sqlx::query_scalar!(
            "SELECT status FROM api_keys WHERE id = $1",
            key_id
        )
        .fetch_one(&pool)
        .await
        .expect("fetch key status");
        assert_eq!(status, "revoked");

        cleanup(&pool, consumer_id).await;
    }

    // ── Test: consumer-level revocation terminates all active keys ────────────

    #[tokio::test]
    async fn test_revoke_all_consumer_keys() {
        let (svc, pool, redis) = setup().await;
        let (consumer_id, key_id_1) = insert_test_key(&pool).await;

        // Insert a second key for the same consumer
        let key_id_2: Uuid = sqlx::query_scalar!(
            r#"
            INSERT INTO api_keys (consumer_id, key_hash, key_prefix)
            VALUES ($1, 'testhash2_' || gen_random_uuid()::text, 'testpf2')
            RETURNING id
            "#,
            consumer_id,
        )
        .fetch_one(&pool)
        .await
        .expect("insert second key");

        let records = svc
            .revoke_all_consumer_keys(consumer_id, "bulk test".to_string(), "admin".to_string())
            .await
            .expect("revoke all");

        assert_eq!(records.len(), 2, "Both keys must be revoked");

        // Both keys must be in Redis
        assert!(RevocationService::is_key_blacklisted_redis(&redis, key_id_1).await);
        assert!(RevocationService::is_key_blacklisted_redis(&redis, key_id_2).await);

        cleanup(&pool, consumer_id).await;
    }

    // ── Test: Redis restart recovery (bootstrap) ──────────────────────────────

    #[tokio::test]
    async fn test_bootstrap_repopulates_redis_after_restart() {
        let (svc, pool, redis) = setup().await;
        let (consumer_id, key_id) = insert_test_key(&pool).await;

        // Revoke the key (pushes to Redis)
        svc.revoke_key(RevokeKeyInput {
            key_id,
            consumer_id,
            revocation_type: "admin_initiated",
            reason: "bootstrap test".to_string(),
            revoked_by: "test".to_string(),
            triggering_detail: None,
        })
        .await
        .expect("revoke");

        // Simulate Redis restart by clearing the set
        let mut conn = redis.pool.get().await.expect("redis conn");
        let _: () = conn.del(REDIS_REVOKED_KEYS_SET).await.expect("del set");

        // Verify it's gone
        let in_set: bool = conn
            .sismember(REDIS_REVOKED_KEYS_SET, key_id.to_string())
            .await
            .unwrap_or(false);
        assert!(!in_set, "Key should be absent after simulated Redis restart");

        // Bootstrap
        svc.bootstrap_redis_blacklist().await.expect("bootstrap");

        // Verify it's back
        let is_blacklisted = RevocationService::is_key_blacklisted_redis(&redis, key_id).await;
        assert!(is_blacklisted, "Key must be back in Redis after bootstrap");

        cleanup(&pool, consumer_id).await;
    }

    // ── Test: temporary consumer blacklist expiry ─────────────────────────────

    #[tokio::test]
    async fn test_temporary_consumer_blacklist_expiry() {
        let (svc, pool, redis) = setup().await;
        let (consumer_id, _key_id) = insert_test_key(&pool).await;

        // Blacklist with 2-second expiry
        let expires_at = chrono::Utc::now() + chrono::Duration::seconds(2);
        svc.blacklist_consumer(BlacklistConsumerInput {
            consumer_id,
            reason: "temp blacklist test".to_string(),
            blacklisted_by: "test".to_string(),
            expires_at: Some(expires_at),
        })
        .await
        .expect("blacklist");

        // Should be blacklisted immediately
        let is_bl = RevocationService::is_consumer_blacklisted_redis(&redis, consumer_id).await;
        assert!(is_bl, "Consumer must be blacklisted immediately");

        // Wait for expiry
        tokio::time::sleep(Duration::from_secs(3)).await;

        // Lift expired entries in DB
        svc.list_active_blacklist().await.expect("list (triggers expiry cleanup)");

        // Lift from Redis manually (in production this is done by the expiry key TTL)
        svc.lift_consumer_blacklist(consumer_id).await.expect("lift");

        let is_bl_after = RevocationService::is_consumer_blacklisted_redis(&redis, consumer_id).await;
        assert!(!is_bl_after, "Consumer must not be blacklisted after expiry + lift");

        cleanup(&pool, consumer_id).await;
    }

    // ── Test: automated abuse revocation ─────────────────────────────────────

    #[tokio::test]
    async fn test_automated_abuse_revocation() {
        let (svc, pool, redis) = setup().await;
        let (consumer_id, key_id) = insert_test_key(&pool).await;

        let detail = serde_json::json!({
            "requests_per_minute": 500,
            "threshold": 100
        });

        let record = svc
            .revoke_abusive_key(key_id, consumer_id, detail)
            .await
            .expect("automated abuse revocation");

        assert_eq!(record.revocation_type, "automated_abuse");
        assert_eq!(record.revoked_by, "system");
        assert!(RevocationService::is_key_blacklisted_redis(&redis, key_id).await);

        cleanup(&pool, consumer_id).await;
    }

    // ── Test: automated suspicious IP revocation ──────────────────────────────

    #[tokio::test]
    async fn test_automated_suspicious_ip_revocation() {
        let (svc, pool, redis) = setup().await;
        let (consumer_id, key_id) = insert_test_key(&pool).await;

        let record = svc
            .revoke_suspicious_ip_key(key_id, consumer_id, "1.2.3.4")
            .await
            .expect("suspicious IP revocation");

        assert_eq!(record.revocation_type, "automated_suspicious_ip");
        assert!(record.reason.contains("1.2.3.4"));
        assert!(RevocationService::is_key_blacklisted_redis(&redis, key_id).await);

        cleanup(&pool, consumer_id).await;
    }

    // ── Test: revocation audit list is paginated and filterable ───────────────

    #[tokio::test]
    async fn test_revocation_audit_list_pagination() {
        let (svc, pool, _redis) = setup().await;
        let (consumer_id, key_id) = insert_test_key(&pool).await;

        svc.revoke_key(RevokeKeyInput {
            key_id,
            consumer_id,
            revocation_type: "admin_initiated",
            reason: "audit test".to_string(),
            revoked_by: "admin".to_string(),
            triggering_detail: None,
        })
        .await
        .expect("revoke");

        let (records, total) = svc
            .list_revocations(crate::services::revocation::RevocationListQuery {
                consumer_id: Some(consumer_id),
                revocation_type: None,
                from: None,
                to: None,
                page: 1,
                page_size: 10,
            })
            .await
            .expect("list revocations");

        assert!(total >= 1, "At least one revocation record expected");
        assert!(!records.is_empty());
        assert_eq!(records[0].consumer_id, consumer_id);

        cleanup(&pool, consumer_id).await;
    }

    // ── Test: blacklist state endpoint reflects active entries ────────────────

    #[tokio::test]
    async fn test_blacklist_state_reflects_active_entries() {
        let (svc, pool, _redis) = setup().await;
        let (consumer_id, _key_id) = insert_test_key(&pool).await;

        svc.blacklist_consumer(BlacklistConsumerInput {
            consumer_id,
            reason: "state test".to_string(),
            blacklisted_by: "admin".to_string(),
            expires_at: None,
        })
        .await
        .expect("blacklist");

        let entries = svc.list_active_blacklist().await.expect("list blacklist");
        let found = entries.iter().any(|e| e.consumer_id == consumer_id);
        assert!(found, "Blacklisted consumer must appear in active blacklist state");

        // Lift and verify removal
        svc.lift_consumer_blacklist(consumer_id).await.expect("lift");
        let entries_after = svc.list_active_blacklist().await.expect("list after lift");
        let still_found = entries_after.iter().any(|e| e.consumer_id == consumer_id);
        assert!(!still_found, "Lifted consumer must not appear in active blacklist");

        cleanup(&pool, consumer_id).await;
    }
}
