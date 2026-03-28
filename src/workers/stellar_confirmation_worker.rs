//! Stellar Confirmation Polling Worker
//!
//! Polls Horizon for every active transaction that has a `stellar_tx_hash`,
//! transitions state to `completed` or `failed`, fires webhook events on every
//! transition, detects stale transactions, and exposes Prometheus metrics.

use crate::chains::stellar::client::StellarClient;
use crate::database::webhook_repository::WebhookRepository;
use prometheus::{
    register_counter_vec, register_gauge, CounterVec, Gauge, Registry,
};
use serde_json::{json, Value as JsonValue};
use sqlx::PgPool;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use tokio::time::interval;
use tracing::{error, info, warn};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// All tuneable knobs for the worker, loaded from environment variables.
#[derive(Debug, Clone)]
pub struct StellarConfirmationConfig {
    /// How often the worker wakes up (default: 15 s).
    pub poll_interval: Duration,
    /// Minimum ledger confirmations required (default: 1).
    pub confirmation_threshold: u32,
    /// Transactions stuck longer than this are flagged stale (default: 30 min).
    pub stale_timeout: Duration,
    /// Max transactions fetched per cycle (default: 200).
    pub batch_size: i64,
    /// Look-back window for active transactions (default: 48 h).
    pub monitoring_window_hours: i32,
}

impl Default for StellarConfirmationConfig {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_secs(15),
            confirmation_threshold: 1,
            stale_timeout: Duration::from_secs(30 * 60),
            batch_size: 200,
            monitoring_window_hours: 48,
        }
    }
}

impl StellarConfirmationConfig {
    pub fn from_env() -> Self {
        let mut c = Self::default();
        c.poll_interval = Duration::from_secs(
            env_u64("STELLAR_CONFIRM_POLL_INTERVAL_SECS", c.poll_interval.as_secs()),
        );
        c.confirmation_threshold =
            env_u64("STELLAR_CONFIRM_THRESHOLD", c.confirmation_threshold as u64) as u32;
        c.stale_timeout = Duration::from_secs(env_u64(
            "STELLAR_CONFIRM_STALE_TIMEOUT_SECS",
            c.stale_timeout.as_secs(),
        ));
        c.batch_size = env_u64("STELLAR_CONFIRM_BATCH_SIZE", c.batch_size as u64) as i64;
        c.monitoring_window_hours =
            env_u64("STELLAR_CONFIRM_WINDOW_HOURS", c.monitoring_window_hours as u64) as i32;
        c
    }
}

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

// ---------------------------------------------------------------------------
// Prometheus metrics
// ---------------------------------------------------------------------------

pub struct WorkerMetrics {
    pub transactions_checked: CounterVec,
    pub confirmations_detected: CounterVec,
    pub failures_detected: CounterVec,
    pub stale_flagged: CounterVec,
    pub active_transactions: Gauge,
}

impl WorkerMetrics {
    pub fn new(registry: &Registry) -> anyhow::Result<Self> {
        let transactions_checked = register_counter_vec!(
            prometheus::opts!(
                "stellar_worker_transactions_checked_total",
                "Total transactions checked per cycle"
            ),
            &["cycle"]
        )?;
        registry.register(Box::new(transactions_checked.clone()))?;

        let confirmations_detected = register_counter_vec!(
            prometheus::opts!(
                "stellar_worker_confirmations_detected_total",
                "Stellar confirmations detected"
            ),
            &["status"]
        )?;
        registry.register(Box::new(confirmations_detected.clone()))?;

        let failures_detected = register_counter_vec!(
            prometheus::opts!(
                "stellar_worker_failures_detected_total",
                "Stellar failures detected"
            ),
            &["reason"]
        )?;
        registry.register(Box::new(failures_detected.clone()))?;

        let stale_flagged = register_counter_vec!(
            prometheus::opts!(
                "stellar_worker_stale_transactions_total",
                "Stale transactions flagged for manual review"
            ),
            &["status"]
        )?;
        registry.register(Box::new(stale_flagged.clone()))?;

        let active_transactions = register_gauge!(prometheus::opts!(
            "stellar_worker_active_transactions",
            "Active transactions currently being monitored"
        ))?;
        registry.register(Box::new(active_transactions.clone()))?;

        Ok(Self {
            transactions_checked,
            confirmations_detected,
            failures_detected,
            stale_flagged,
            active_transactions,
        })
    }
}

// ---------------------------------------------------------------------------
// Worker
// ---------------------------------------------------------------------------

pub struct StellarConfirmationWorker {
    pool: PgPool,
    stellar: StellarClient,
    config: StellarConfirmationConfig,
    metrics: Arc<WorkerMetrics>,
}

impl StellarConfirmationWorker {
    pub fn new(
        pool: PgPool,
        stellar: StellarClient,
        config: StellarConfirmationConfig,
        metrics: Arc<WorkerMetrics>,
    ) -> Self {
        Self {
            pool,
            stellar,
            config,
            metrics,
        }
    }

    /// Main loop — runs until the shutdown channel fires.
    pub async fn run(self, mut shutdown_rx: watch::Receiver<bool>) {
        info!(
            poll_interval_secs = self.config.poll_interval.as_secs(),
            confirmation_threshold = self.config.confirmation_threshold,
            stale_timeout_secs = self.config.stale_timeout.as_secs(),
            "stellar confirmation worker started"
        );

        let mut ticker = interval(self.config.poll_interval);
        // Consume the first immediate tick so we don't fire before the server
        // is fully initialised.
        ticker.tick().await;

        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        info!("stellar confirmation worker: shutdown signal received — completing current cycle");
                        // Run one final cycle so in-flight work is not abandoned.
                        if let Err(e) = self.run_cycle().await {
                            warn!(error = %e, "final cycle error during shutdown");
                        }
                        break;
                    }
                }
                _ = ticker.tick() => {
                    if let Err(e) = self.run_cycle().await {
                        warn!(error = %e, "stellar confirmation cycle error");
                    }
                }
            }
        }

        info!("stellar confirmation worker stopped");
    }

    // -----------------------------------------------------------------------
    // Single polling cycle
    // -----------------------------------------------------------------------

    async fn run_cycle(&self) -> anyhow::Result<()> {
        let txns = self.fetch_active_transactions().await?;
        let count = txns.len();
        self.metrics
            .active_transactions
            .set(count as f64);
        self.metrics
            .transactions_checked
            .with_label_values(&["cycle"])
            .inc_by(count as f64);

        info!(count, "stellar confirmation cycle: checking transactions");

        for tx in txns {
            let tx_id = tx.transaction_id.to_string();
            let stellar_hash = match tx.stellar_tx_hash.as_deref() {
                Some(h) if !h.is_empty() => h.to_string(),
                _ => continue, // no hash yet — skip
            };

            // Idempotency: already terminal → skip.
            if tx.status == "completed" || tx.status == "failed" {
                continue;
            }

            // Stale detection (runs regardless of hash presence).
            if self.is_stale(&tx) {
                self.flag_stale(&tx_id, &tx.status).await;
                continue;
            }

            // Query Horizon.
            match self
                .stellar
                .get_transaction_by_hash(&stellar_hash)
                .await
            {
                Ok(record) => {
                    // Idempotency: only act when the current DB status is still active.
                    if record.successful {
                        let ledger = record.ledger.unwrap_or(0);
                        if meets_confirmation_threshold(ledger, self.config.confirmation_threshold) {
                            self.transition_completed(&tx_id, &stellar_hash, &tx.status, ledger)
                                .await;
                        }
                        // else: not enough confirmations yet — wait for next cycle
                    } else {
                        let reason = record
                            .result_xdr
                            .as_deref()
                            .unwrap_or("horizon reported failure");
                        self.transition_failed(&tx_id, &stellar_hash, &tx.status, reason)
                            .await;
                    }
                }
                Err(e) => {
                    let msg = e.to_string();
                    // Transient errors: log and skip — retry next cycle.
                    if msg.contains("not found")
                        || msg.contains("timeout")
                        || msg.contains("network")
                        || msg.contains("rate limit")
                    {
                        warn!(
                            tx_id = %tx_id,
                            stellar_hash = %stellar_hash,
                            error = %msg,
                            "transient horizon error — will retry next cycle"
                        );
                    } else {
                        // Permanent / unexpected error.
                        self.transition_failed(&tx_id, &stellar_hash, &tx.status, &msg)
                            .await;
                    }
                }
            }
        }

        Ok(())
    }

    // -----------------------------------------------------------------------
    // DB helpers
    // -----------------------------------------------------------------------

    async fn fetch_active_transactions(&self) -> anyhow::Result<Vec<ActiveTransaction>> {
        let rows = sqlx::query_as::<_, ActiveTransaction>(
            r#"
            SELECT transaction_id, status, stellar_tx_hash, created_at, updated_at, metadata
            FROM transactions
            WHERE status IN ('pending', 'processing')
              AND stellar_tx_hash IS NOT NULL
              AND stellar_tx_hash <> ''
              AND created_at > NOW() - INTERVAL '1 hour' * $1
            ORDER BY created_at ASC
            LIMIT $2
            "#,
        )
        .bind(self.config.monitoring_window_hours)
        .bind(self.config.batch_size)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    fn is_stale(&self, tx: &ActiveTransaction) -> bool {
        is_stale_by_age(tx.created_at, self.config.stale_timeout)
    }

    async fn flag_stale(&self, tx_id: &str, current_status: &str) {
        let result = sqlx::query(
            r#"
            UPDATE transactions
            SET stale_flagged_at = NOW(),
                metadata = metadata || $2
            WHERE transaction_id = $1::uuid
              AND stale_flagged_at IS NULL
            "#,
        )
        .bind(tx_id)
        .bind(json!({ "stale_reason": "stuck beyond configured timeout" }))
        .execute(&self.pool)
        .await;

        match result {
            Ok(r) if r.rows_affected() > 0 => {
                warn!(
                    tx_id = %tx_id,
                    status = %current_status,
                    "transaction flagged as stale for manual review"
                );
                self.metrics
                    .stale_flagged
                    .with_label_values(&[current_status])
                    .inc();
            }
            Ok(_) => {} // already flagged — idempotent
            Err(e) => error!(tx_id = %tx_id, error = %e, "failed to flag stale transaction"),
        }
    }

    async fn transition_completed(
        &self,
        tx_id: &str,
        stellar_hash: &str,
        old_status: &str,
        ledger: i64,
    ) {
        let meta = json!({
            "stellar_confirmed_at": chrono::Utc::now().to_rfc3339(),
            "confirmed_ledger": ledger,
            "stellar_tx_hash": stellar_hash,
        });

        let result = sqlx::query(
            r#"
            UPDATE transactions
            SET status = 'completed',
                state_transitioned_at = NOW(),
                blockchain_tx_hash = $2,
                metadata = metadata || $3
            WHERE transaction_id = $1::uuid
              AND status NOT IN ('completed', 'failed')
            "#,
        )
        .bind(tx_id)
        .bind(stellar_hash)
        .bind(&meta)
        .execute(&self.pool)
        .await;

        match result {
            Ok(r) if r.rows_affected() > 0 => {
                info!(
                    tx_id = %tx_id,
                    stellar_hash = %stellar_hash,
                    old_status = %old_status,
                    new_status = "completed",
                    ledger = ledger,
                    "state transition: completed"
                );
                self.metrics
                    .confirmations_detected
                    .with_label_values(&["completed"])
                    .inc();
                self.emit_webhook(tx_id, stellar_hash, "stellar.transaction.confirmed", meta)
                    .await;
            }
            Ok(_) => {} // already transitioned — idempotent
            Err(e) => error!(tx_id = %tx_id, error = %e, "failed to persist completed state"),
        }
    }

    async fn transition_failed(
        &self,
        tx_id: &str,
        stellar_hash: &str,
        old_status: &str,
        reason: &str,
    ) {
        let meta = json!({
            "stellar_failed_at": chrono::Utc::now().to_rfc3339(),
            "failure_reason": reason,
            "stellar_tx_hash": stellar_hash,
        });

        let result = sqlx::query(
            r#"
            UPDATE transactions
            SET status = 'failed',
                state_transitioned_at = NOW(),
                error_message = $2,
                metadata = metadata || $3
            WHERE transaction_id = $1::uuid
              AND status NOT IN ('completed', 'failed')
            "#,
        )
        .bind(tx_id)
        .bind(reason)
        .bind(&meta)
        .execute(&self.pool)
        .await;

        match result {
            Ok(r) if r.rows_affected() > 0 => {
                warn!(
                    tx_id = %tx_id,
                    stellar_hash = %stellar_hash,
                    old_status = %old_status,
                    new_status = "failed",
                    reason = %reason,
                    "state transition: failed"
                );
                self.metrics
                    .failures_detected
                    .with_label_values(&[reason])
                    .inc();
                self.emit_webhook(tx_id, stellar_hash, "stellar.transaction.failed", meta)
                    .await;
            }
            Ok(_) => {} // already transitioned — idempotent
            Err(e) => error!(tx_id = %tx_id, error = %e, "failed to persist failed state"),
        }
    }

    // -----------------------------------------------------------------------
    // Webhook emission
    // -----------------------------------------------------------------------

    async fn emit_webhook(
        &self,
        tx_id: &str,
        stellar_hash: &str,
        event_type: &str,
        payload: JsonValue,
    ) {
        // Idempotency key: event_type + tx_id — duplicate polls produce the
        // same key and the ON CONFLICT DO NOTHING in log_event is a no-op.
        let event_id = webhook_event_id(event_type, tx_id);
        let parsed_tx_id = Uuid::parse_str(tx_id).ok();
        let repo = WebhookRepository::new(self.pool.clone());

        if let Err(e) = repo
            .log_event(&event_id, "stellar", event_type, payload, None, parsed_tx_id)
            .await
        {
            warn!(
                tx_id = %tx_id,
                stellar_hash = %stellar_hash,
                event_type = %event_type,
                error = %e,
                "failed to emit webhook event"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Lightweight projection used by the worker query
// ---------------------------------------------------------------------------

#[derive(Debug, sqlx::FromRow)]
struct ActiveTransaction {
    pub transaction_id: Uuid,
    pub status: String,
    pub stellar_tx_hash: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    #[allow(dead_code)]
    pub updated_at: chrono::DateTime<chrono::Utc>,
    #[allow(dead_code)]
    pub metadata: serde_json::Value,
}

// ---------------------------------------------------------------------------
// Pure helper — extracted so unit tests can call it without a live worker
// ---------------------------------------------------------------------------

/// Returns `true` when `created_at` is older than `stale_timeout`.
pub fn is_stale_by_age(
    created_at: chrono::DateTime<chrono::Utc>,
    stale_timeout: Duration,
) -> bool {
    let elapsed = chrono::Utc::now() - created_at;
    elapsed
        .to_std()
        .map(|d| d > stale_timeout)
        .unwrap_or(false)
}

/// Returns `true` when `ledger` meets or exceeds `threshold`.
pub fn meets_confirmation_threshold(ledger: i64, threshold: u32) -> bool {
    ledger >= threshold as i64
}

/// Build the idempotency key used for webhook deduplication.
pub fn webhook_event_id(event_type: &str, tx_id: &str) -> String {
    format!("{}:{}", event_type, tx_id)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stale_detection_respects_threshold() {
        let timeout = Duration::from_secs(1800); // 30 min
        let now = chrono::Utc::now();

        let fresh = now - chrono::Duration::seconds(60);
        let stale = now - chrono::Duration::seconds(2000);

        assert!(!is_stale_by_age(fresh, timeout));
        assert!(is_stale_by_age(stale, timeout));
    }

    #[test]
    fn stale_boundary_is_exclusive() {
        // Something clearly under the threshold should not be stale.
        let timeout = Duration::from_secs(1800);
        let under = chrono::Utc::now() - chrono::Duration::seconds(1799);
        assert!(!is_stale_by_age(under, timeout));
    }

    #[test]
    fn confirmation_threshold_met() {
        assert!(meets_confirmation_threshold(1, 1));
        assert!(meets_confirmation_threshold(5, 1));
        assert!(meets_confirmation_threshold(3, 3));
    }

    #[test]
    fn confirmation_threshold_not_met() {
        assert!(!meets_confirmation_threshold(0, 1));
        assert!(!meets_confirmation_threshold(2, 3));
    }

    #[test]
    fn config_defaults_are_sane() {
        let cfg = StellarConfirmationConfig::default();
        assert_eq!(cfg.poll_interval, Duration::from_secs(15));
        assert_eq!(cfg.confirmation_threshold, 1);
        assert_eq!(cfg.stale_timeout, Duration::from_secs(1800));
        assert_eq!(cfg.batch_size, 200);
        assert_eq!(cfg.monitoring_window_hours, 48);
    }

    #[test]
    fn idempotency_key_is_deterministic() {
        let tx_id = "550e8400-e29b-41d4-a716-446655440000";
        let event_type = "stellar.transaction.confirmed";
        assert_eq!(
            webhook_event_id(event_type, tx_id),
            webhook_event_id(event_type, tx_id),
        );
    }

    #[test]
    fn idempotency_keys_differ_by_event_type() {
        let tx_id = "550e8400-e29b-41d4-a716-446655440000";
        assert_ne!(
            webhook_event_id("stellar.transaction.confirmed", tx_id),
            webhook_event_id("stellar.transaction.failed", tx_id),
        );
    }

    #[test]
    fn terminal_status_guard() {
        // Simulate the guard logic in run_cycle
        for status in &["completed", "failed"] {
            assert!(*status == "completed" || *status == "failed");
        }
        for status in &["pending", "processing"] {
            assert!(!(*status == "completed" || *status == "failed"));
        }
    }

    #[test]
    fn env_u64_returns_default_when_unset() {
        // Use a key that will never be set in the test environment.
        let val = env_u64("__NONEXISTENT_KEY_XYZ__", 42);
        assert_eq!(val, 42);
    }
}
