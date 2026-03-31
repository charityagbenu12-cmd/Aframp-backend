//! Mint Request Expiry Worker
//!
//! Periodically scans for mint requests that have passed their `expires_at`
//! deadline while still in an active state (`pending_approval` or
//! `partially_approved`) and transitions them to `expired`.
//!
//! This is a safety net — the service layer also checks expiry inline on every
//! approve/reject call, but this worker ensures requests are expired even when
//! no one interacts with them.

use serde_json::json;
use sqlx::PgPool;
use std::time::Duration;
use tokio::sync::watch;
use tracing::{error, info, warn};

/// Configuration for the expiry worker.
#[derive(Debug, Clone)]
pub struct MintExpiryWorkerConfig {
    /// How often the worker wakes up to scan for expired requests.
    pub poll_interval: Duration,
    /// Maximum number of requests to expire per cycle (prevents long DB locks).
    pub batch_size: i64,
}

impl Default for MintExpiryWorkerConfig {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_secs(60), // run every minute
            batch_size: 100,
        }
    }
}

impl MintExpiryWorkerConfig {
    /// Load config from environment variables with sensible defaults.
    pub fn from_env() -> Self {
        Self {
            poll_interval: Duration::from_secs(
                std::env::var("MINT_EXPIRY_POLL_INTERVAL_SECS")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(60),
            ),
            batch_size: std::env::var("MINT_EXPIRY_BATCH_SIZE")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(100),
        }
    }
}

/// The expiry worker.
pub struct MintExpiryWorker {
    pool: PgPool,
    config: MintExpiryWorkerConfig,
}

impl MintExpiryWorker {
    pub fn new(pool: PgPool, config: MintExpiryWorkerConfig) -> Self {
        Self { pool, config }
    }

    /// Run the worker loop until a shutdown signal is received.
    pub async fn run(self, mut shutdown_rx: watch::Receiver<bool>) {
        info!(
            poll_interval_secs = self.config.poll_interval.as_secs(),
            batch_size = self.config.batch_size,
            "Mint expiry worker started"
        );

        loop {
            tokio::select! {
                _ = tokio::time::sleep(self.config.poll_interval) => {
                    if let Err(e) = self.expire_stale_requests().await {
                        error!(error = %e, "Mint expiry worker cycle failed");
                    }
                }
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        info!("Mint expiry worker shutting down");
                        break;
                    }
                }
            }
        }
    }

    /// Find all active requests past their expiry deadline and mark them expired.
    async fn expire_stale_requests(&self) -> Result<(), sqlx::Error> {
        // Fetch IDs + current status of requests that have expired but are still active
        let rows: Vec<(uuid::Uuid, String)> = sqlx::query_as(
            r#"
            SELECT id, status
              FROM mint_requests
             WHERE expires_at < NOW()
               AND status IN ('pending_approval', 'partially_approved')
             LIMIT $1
            "#,
        )
        .bind(self.config.batch_size)
        .fetch_all(&self.pool)
        .await?;

        if rows.is_empty() {
            return Ok(());
        }

        info!(count = rows.len(), "Expiring stale mint requests");

        for (id, from_status) in rows {
            // Update status to expired
            let result = sqlx::query(
                r#"
                UPDATE mint_requests
                   SET status = 'expired', updated_at = NOW()
                 WHERE id = $1
                   AND status IN ('pending_approval', 'partially_approved')
                "#,
            )
            .bind(id)
            .execute(&self.pool)
            .await;

            match result {
                Ok(r) if r.rows_affected() == 1 => {
                    // Write immutable audit entry
                    let audit_result = sqlx::query(
                        r#"
                        INSERT INTO mint_audit_log
                            (mint_request_id, actor_id, actor_role, event_type,
                             from_status, to_status, payload)
                        VALUES ($1, 'system', NULL, 'mint_request_expired', $2, 'expired', $3)
                        "#,
                    )
                    .bind(id)
                    .bind(&from_status)
                    .bind(json!({ "reason": "Request exceeded 24-hour approval window" }))
                    .execute(&self.pool)
                    .await;

                    if let Err(e) = audit_result {
                        // Non-fatal: log but don't fail the whole cycle
                        warn!(
                            mint_request_id = %id,
                            error = %e,
                            "Failed to write expiry audit log entry"
                        );
                    } else {
                        info!(mint_request_id = %id, "Mint request expired by worker");
                    }
                }
                Ok(_) => {
                    // Another process already handled it — skip silently
                }
                Err(e) => {
                    error!(mint_request_id = %id, error = %e, "Failed to expire mint request");
                }
            }
        }

        Ok(())
    }
}
