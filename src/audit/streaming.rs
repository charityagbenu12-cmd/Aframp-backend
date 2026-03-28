/// Redis pub/sub streaming for real-time audit event delivery.
///
/// Every persisted audit entry is published to `audit:events` immediately after
/// DB write. Consumers can subscribe to specific categories via
/// `audit:events:<category>` channels.
use crate::audit::models::AuditLogEntry;
use crate::cache::RedisPool;
use redis::AsyncCommands;
use tracing::{error, warn};

const AUDIT_CHANNEL_ALL: &str = "audit:events";
const DEAD_LETTER_KEY: &str = "audit:dead_letter";
/// How long (seconds) undelivered events are retained in the dead-letter list.
const DEAD_LETTER_TTL_SECS: usize = 86_400; // 24 hours

pub struct AuditStreamer {
    pool: RedisPool,
}

impl AuditStreamer {
    pub fn new(pool: RedisPool) -> Self {
        Self { pool }
    }

    /// Publish an audit entry to Redis pub/sub.
    /// On failure, the entry is pushed to the dead-letter list for retry.
    pub async fn publish(&self, entry: &AuditLogEntry) {
        let payload = match serde_json::to_string(entry) {
            Ok(p) => p,
            Err(e) => {
                error!(entry_id = %entry.id, error = %e, "Failed to serialise audit entry for pub/sub");
                return;
            }
        };

        let category_channel = format!("audit:events:{}", entry.event_category.as_str());

        match self.pool.get().await {
            Ok(mut conn) => {
                let r1: redis::RedisResult<i64> =
                    conn.publish(AUDIT_CHANNEL_ALL, &payload).await;
                let r2: redis::RedisResult<i64> =
                    conn.publish(&category_channel, &payload).await;

                if r1.is_err() || r2.is_err() {
                    warn!(entry_id = %entry.id, "Pub/sub delivery failed; pushing to dead-letter");
                    self.push_dead_letter(&payload).await;
                }
            }
            Err(e) => {
                warn!(entry_id = %entry.id, error = %e, "Redis unavailable; pushing audit entry to dead-letter");
                self.push_dead_letter(&payload).await;
            }
        }
    }

    async fn push_dead_letter(&self, payload: &str) {
        if let Ok(mut conn) = self.pool.get().await {
            let _: redis::RedisResult<()> = conn.lpush(DEAD_LETTER_KEY, payload).await;
            // Trim to prevent unbounded growth (keep last 10k)
            let _: redis::RedisResult<()> = conn.ltrim(DEAD_LETTER_KEY, 0, 9_999).await;
        }
    }
}
