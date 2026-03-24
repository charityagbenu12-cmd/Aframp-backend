//! Database Maintenance Worker
//!
//! Runs on a low-frequency schedule (default: every 24 hours) and keeps the
//! database lean by:
//!
//! - Archiving old transactions to `transactions_archive`
//! - Deleting expired / unconsumed onramp quotes (DB + Redis)
//! - Removing successfully-processed orphaned webhook events
//! - Purging expired wallet nonces
//! - Pruning stale exchange-rate history beyond the configured keep-N window
//! - Running ANALYZE on high-traffic tables
//! - Persisting a `cleanup_reports` row per cycle
//!
//! All mutations run inside a single database transaction so a mid-cycle
//! failure rolls back cleanly.

use crate::cache::cache::RedisCache;
use redis::AsyncCommands;
use sqlx::PgPool;
use std::time::Duration;
use tokio::sync::watch;
use tokio::time::interval;
use tracing::{error, info, instrument, warn};

// ── Prometheus metrics ────────────────────────────────────────────────────────

use std::sync::OnceLock;

use prometheus::{
    register_gauge, register_int_counter, register_int_gauge, Gauge, IntCounter, IntGauge,
};

struct Metrics {
    archived: IntCounter,
    deleted: IntCounter,
    analyzed: IntGauge,
    cycle_duration_secs: Gauge,
}

static METRICS: OnceLock<Metrics> = OnceLock::new();

fn metrics() -> &'static Metrics {
    METRICS.get_or_init(|| Metrics {
        archived: register_int_counter!(
            "db_maintenance_records_archived_total",
            "Total transaction records archived per cycle"
        )
        .unwrap(),
        deleted: register_int_counter!(
            "db_maintenance_records_deleted_total",
            "Total records deleted per cycle"
        )
        .unwrap(),
        analyzed: register_int_gauge!(
            "db_maintenance_tables_analyzed",
            "Number of tables analyzed in the last cycle"
        )
        .unwrap(),
        cycle_duration_secs: register_gauge!(
            "db_maintenance_cycle_duration_seconds",
            "Duration of the last maintenance cycle in seconds"
        )
        .unwrap(),
    })
}

// ── Configuration ─────────────────────────────────────────────────────────────

/// Tables that receive an ANALYZE after each cleanup cycle.
const HIGH_TRAFFIC_TABLES: &[&str] = &[
    "transactions",
    "onramp_quotes",
    "webhook_events",
    "exchange_rate_history",
    "wallet_nonces",
];

#[derive(Debug, Clone)]
pub struct MaintenanceConfig {
    /// How often the worker wakes up.
    pub interval: Duration,
    /// Transactions older than this are archived.
    pub transaction_retention: Duration,
    /// Webhook events older than this (and status = 'completed') are deleted.
    pub webhook_retention: Duration,
    /// Nonces older than their `expires_at` are deleted.
    pub nonce_retention: Duration,
    /// Rate-history rows older than this are pruned.
    pub rate_history_retention: Duration,
    /// Keep at most this many rate-history rows per currency pair.
    pub rate_history_keep_n: i64,
}

impl Default for MaintenanceConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(86_400), // 24 h
            transaction_retention: Duration::from_secs(90 * 86_400), // 90 days
            webhook_retention: Duration::from_secs(30 * 86_400),     // 30 days
            nonce_retention: Duration::from_secs(86_400),            // 1 day
            rate_history_retention: Duration::from_secs(30 * 86_400),
            rate_history_keep_n: 1_000,
        }
    }
}

impl MaintenanceConfig {
    pub fn from_env() -> Self {
        let mut c = Self::default();
        macro_rules! env_secs {
            ($var:expr, $field:expr) => {
                if let Ok(v) = std::env::var($var) {
                    if let Ok(n) = v.parse::<u64>() {
                        $field = Duration::from_secs(n);
                    }
                }
            };
        }
        env_secs!("MAINTENANCE_INTERVAL_SECS", c.interval);
        env_secs!(
            "MAINTENANCE_TX_RETENTION_SECS",
            c.transaction_retention
        );
        env_secs!(
            "MAINTENANCE_WEBHOOK_RETENTION_SECS",
            c.webhook_retention
        );
        env_secs!("MAINTENANCE_NONCE_RETENTION_SECS", c.nonce_retention);
        env_secs!(
            "MAINTENANCE_RATE_HISTORY_RETENTION_SECS",
            c.rate_history_retention
        );
        if let Ok(v) = std::env::var("MAINTENANCE_RATE_HISTORY_KEEP_N") {
            if let Ok(n) = v.parse::<i64>() {
                c.rate_history_keep_n = n;
            }
        }
        c
    }
}

// ── Worker ────────────────────────────────────────────────────────────────────

pub struct MaintenanceWorker {
    pool: PgPool,
    cache: Option<RedisCache>,
    config: MaintenanceConfig,
}

impl MaintenanceWorker {
    pub fn new(pool: PgPool, cache: Option<RedisCache>, config: MaintenanceConfig) -> Self {
        Self {
            pool,
            cache,
            config,
        }
    }

    /// Entry point — runs until the shutdown signal fires.
    pub async fn run(self, mut shutdown: watch::Receiver<bool>) {
        // Eagerly initialise metrics so they appear in /metrics from the start.
        let _ = metrics();

        let mut ticker = interval(self.config.interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        info!(
            interval_secs = self.config.interval.as_secs(),
            "Database maintenance worker started"
        );

        loop {
            tokio::select! {
                biased;
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        info!("Maintenance worker received shutdown signal — finishing current cycle");
                        // Run one final cycle to completion before exiting.
                        self.run_cycle().await;
                        info!("Maintenance worker shut down cleanly");
                        return;
                    }
                }
                _ = ticker.tick() => {
                    self.run_cycle().await;
                }
            }
        }
    }

    /// Execute one full maintenance cycle.
    #[instrument(skip(self), name = "maintenance_cycle")]
    async fn run_cycle(&self) {
        let started = chrono::Utc::now();
        let start_instant = std::time::Instant::now();

        info!("Starting database maintenance cycle");

        match self.execute_cycle(started).await {
            Ok(report) => {
                let elapsed = start_instant.elapsed().as_secs_f64();
                metrics().cycle_duration_secs.set(elapsed);

                info!(
                    transactions_archived = report.transactions_archived,
                    quotes_deleted = report.quotes_deleted,
                    webhooks_deleted = report.webhooks_deleted,
                    nonces_deleted = report.nonces_deleted,
                    rate_history_deleted = report.rate_history_deleted,
                    tables_analyzed = report.tables_analyzed,
                    duration_secs = elapsed,
                    "Maintenance cycle completed"
                );
            }
            Err(e) => {
                error!(error = %e, "Maintenance cycle failed — transaction rolled back");
            }
        }
    }

    async fn execute_cycle(
        &self,
        started: chrono::DateTime<chrono::Utc>,
    ) -> Result<CycleReport, sqlx::Error> {
        let mut tx = self.pool.begin().await?;

        // 1. Archive old transactions
        let transactions_archived = archive_old_transactions(&mut tx, &self.config).await?;
        info!(
            table = "transactions",
            records_affected = transactions_archived,
            "Archived old transactions"
        );

        // 2. Delete expired quotes
        let quotes_deleted = delete_expired_quotes(&mut tx).await?;
        info!(
            table = "onramp_quotes",
            records_affected = quotes_deleted,
            "Deleted expired quotes"
        );

        // 3. Delete orphaned webhook events
        let webhooks_deleted = delete_orphaned_webhooks(&mut tx, &self.config).await?;
        info!(
            table = "webhook_events",
            records_affected = webhooks_deleted,
            "Deleted orphaned webhook events"
        );

        // 4. Delete expired nonces
        let nonces_deleted = delete_expired_nonces(&mut tx).await?;
        info!(
            table = "wallet_nonces",
            records_affected = nonces_deleted,
            "Deleted expired nonces"
        );

        // 5. Prune stale rate history
        let rate_history_deleted = prune_rate_history(&mut tx, &self.config).await?;
        info!(
            table = "exchange_rate_history",
            records_affected = rate_history_deleted,
            "Pruned stale rate history"
        );

        // 6. Persist cleanup report inside the same transaction
        let finished = chrono::Utc::now();
        let report = CycleReport {
            transactions_archived,
            quotes_deleted,
            webhooks_deleted,
            nonces_deleted,
            rate_history_deleted,
            tables_analyzed: HIGH_TRAFFIC_TABLES.len() as i32,
        };
        persist_report(&mut tx, started, finished, &report).await?;

        tx.commit().await?;

        // 7. ANALYZE runs outside the transaction (DDL-adjacent, non-transactional)
        analyze_tables(&self.pool).await;

        // 8. Purge expired quote keys from Redis (best-effort, outside transaction)
        if let Some(cache) = &self.cache {
            purge_redis_quotes(cache).await;
        }

        // Update Prometheus counters
        metrics()
            .archived
            .inc_by(transactions_archived as u64);
        metrics().deleted.inc_by(
            (quotes_deleted + webhooks_deleted + nonces_deleted + rate_history_deleted) as u64,
        );
        metrics()
            .analyzed
            .set(HIGH_TRAFFIC_TABLES.len() as i64);

        Ok(report)
    }
}

// ── Individual cleanup operations ─────────────────────────────────────────────

async fn archive_old_transactions(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    config: &MaintenanceConfig,
) -> Result<i32, sqlx::Error> {
    let cutoff = chrono::Utc::now()
        - chrono::Duration::from_std(config.transaction_retention).unwrap_or_default();

    // Move rows to archive table
    let archived = sqlx::query_scalar::<_, i64>(
        r#"
        WITH moved AS (
            INSERT INTO transactions_archive
            SELECT * FROM transactions
            WHERE created_at < $1
              AND status IN ('completed', 'failed')
            ON CONFLICT (transaction_id) DO NOTHING
            RETURNING transaction_id
        )
        SELECT COUNT(*) FROM moved
        "#,
    )
    .bind(cutoff)
    .fetch_one(&mut **tx)
    .await?;

    // Remove from main table only what was successfully inserted into archive
    sqlx::query(
        r#"
        DELETE FROM transactions
        WHERE created_at < $1
          AND status IN ('completed', 'failed')
          AND transaction_id IN (SELECT transaction_id FROM transactions_archive WHERE created_at < $1)
        "#,
    )
    .bind(cutoff)
    .execute(&mut **tx)
    .await?;

    Ok(archived as i32)
}

async fn delete_expired_quotes(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<i32, sqlx::Error> {
    let result = sqlx::query_scalar::<_, i64>(
        r#"
        WITH deleted AS (
            DELETE FROM onramp_quotes
            WHERE expires_at < now()
              AND status != 'consumed'
            RETURNING id
        )
        SELECT COUNT(*) FROM deleted
        "#,
    )
    .fetch_one(&mut **tx)
    .await?;

    Ok(result as i32)
}

async fn delete_orphaned_webhooks(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    config: &MaintenanceConfig,
) -> Result<i32, sqlx::Error> {
    let cutoff = chrono::Utc::now()
        - chrono::Duration::from_std(config.webhook_retention).unwrap_or_default();

    let result = sqlx::query_scalar::<_, i64>(
        r#"
        WITH deleted AS (
            DELETE FROM webhook_events
            WHERE status = 'completed'
              AND created_at < $1
            RETURNING id
        )
        SELECT COUNT(*) FROM deleted
        "#,
    )
    .bind(cutoff)
    .fetch_one(&mut **tx)
    .await?;

    Ok(result as i32)
}

async fn delete_expired_nonces(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<i32, sqlx::Error> {
    let result = sqlx::query_scalar::<_, i64>(
        r#"
        WITH deleted AS (
            DELETE FROM wallet_nonces
            WHERE expires_at < now()
            RETURNING id
        )
        SELECT COUNT(*) FROM deleted
        "#,
    )
    .fetch_one(&mut **tx)
    .await?;

    Ok(result as i32)
}

async fn prune_rate_history(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    config: &MaintenanceConfig,
) -> Result<i32, sqlx::Error> {
    let cutoff = chrono::Utc::now()
        - chrono::Duration::from_std(config.rate_history_retention).unwrap_or_default();

    // Delete rows beyond the retention window
    let by_age = sqlx::query_scalar::<_, i64>(
        r#"
        WITH deleted AS (
            DELETE FROM exchange_rate_history
            WHERE recorded_at < $1
            RETURNING id
        )
        SELECT COUNT(*) FROM deleted
        "#,
    )
    .bind(cutoff)
    .fetch_one(&mut **tx)
    .await?;

    // Keep only the most recent N rows per currency pair
    let by_count = sqlx::query_scalar::<_, i64>(
        r#"
        WITH ranked AS (
            SELECT id,
                   ROW_NUMBER() OVER (
                       PARTITION BY from_currency, to_currency
                       ORDER BY recorded_at DESC
                   ) AS rn
            FROM exchange_rate_history
        ),
        deleted AS (
            DELETE FROM exchange_rate_history
            WHERE id IN (SELECT id FROM ranked WHERE rn > $1)
            RETURNING id
        )
        SELECT COUNT(*) FROM deleted
        "#,
    )
    .bind(config.rate_history_keep_n)
    .fetch_one(&mut **tx)
    .await?;

    Ok((by_age + by_count) as i32)
}

async fn persist_report(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    started: chrono::DateTime<chrono::Utc>,
    finished: chrono::DateTime<chrono::Utc>,
    r: &CycleReport,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO cleanup_reports
            (cycle_started_at, cycle_finished_at,
             transactions_archived, quotes_deleted, webhooks_deleted,
             nonces_deleted, rate_history_deleted, tables_analyzed)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        "#,
    )
    .bind(started)
    .bind(finished)
    .bind(r.transactions_archived)
    .bind(r.quotes_deleted)
    .bind(r.webhooks_deleted)
    .bind(r.nonces_deleted)
    .bind(r.rate_history_deleted)
    .bind(r.tables_analyzed)
    .execute(&mut **tx)
    .await?;

    Ok(())
}

/// ANALYZE must run outside a transaction.
async fn analyze_tables(pool: &PgPool) {
    for table in HIGH_TRAFFIC_TABLES {
        // ANALYZE cannot be parameterised; table names are compile-time constants.
        let sql = format!("ANALYZE {table}");
        if let Err(e) = sqlx::query(&sql).execute(pool).await {
            warn!(table = table, error = %e, "ANALYZE failed");
        } else {
            info!(table = table, "ANALYZE completed");
        }
    }
}

/// Scan Redis for quote keys whose TTL has expired and delete them.
async fn purge_redis_quotes(cache: &RedisCache) {
    let mut conn = match cache.get_connection().await {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, "Redis connection unavailable for quote purge");
            return;
        }
    };

    let keys: Vec<String> = match conn.keys::<_, Vec<String>>("quote:*").await {
        Ok(k) => k,
        Err(e) => {
            warn!(error = %e, "Failed to scan Redis quote keys");
            return;
        }
    };

    let mut purged = 0u64;
    for key in &keys {
        let ttl: i64 = conn.ttl(key).await.unwrap_or(1);
        if ttl <= 0 {
            let _: Result<(), _> = conn.del(key).await;
            purged += 1;
        }
    }

    if purged > 0 {
        info!(purged, "Purged expired Redis quote keys");
    }
}

// ── Internal report struct ────────────────────────────────────────────────────

#[derive(Debug, Default)]
struct CycleReport {
    transactions_archived: i32,
    quotes_deleted: i32,
    webhooks_deleted: i32,
    nonces_deleted: i32,
    rate_history_deleted: i32,
    tables_analyzed: i32,
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    // ── Unit: retention period calculations ───────────────────────────────────

    #[test]
    fn test_transaction_cutoff_is_in_the_past() {
        let config = MaintenanceConfig {
            transaction_retention: Duration::from_secs(90 * 86_400),
            ..Default::default()
        };
        let cutoff = chrono::Utc::now()
            - chrono::Duration::from_std(config.transaction_retention).unwrap();
        assert!(cutoff < chrono::Utc::now());
    }

    #[test]
    fn test_config_from_env_defaults() {
        let config = MaintenanceConfig::default();
        assert_eq!(config.interval, Duration::from_secs(86_400));
        assert_eq!(
            config.transaction_retention,
            Duration::from_secs(90 * 86_400)
        );
        assert_eq!(config.rate_history_keep_n, 1_000);
    }

    #[test]
    fn test_config_env_override() {
        std::env::set_var("MAINTENANCE_INTERVAL_SECS", "3600");
        std::env::set_var("MAINTENANCE_RATE_HISTORY_KEEP_N", "500");
        let config = MaintenanceConfig::from_env();
        assert_eq!(config.interval, Duration::from_secs(3600));
        assert_eq!(config.rate_history_keep_n, 500);
        std::env::remove_var("MAINTENANCE_INTERVAL_SECS");
        std::env::remove_var("MAINTENANCE_RATE_HISTORY_KEEP_N");
    }

    #[test]
    fn test_high_traffic_tables_non_empty() {
        assert!(!HIGH_TRAFFIC_TABLES.is_empty());
    }

    // ── Unit: archival logic ──────────────────────────────────────────────────

    #[test]
    fn test_retention_cutoff_respects_duration() {
        let retention = Duration::from_secs(7 * 86_400); // 7 days
        let cutoff =
            chrono::Utc::now() - chrono::Duration::from_std(retention).unwrap();
        let old_record = chrono::Utc::now() - chrono::Duration::days(8);
        let new_record = chrono::Utc::now() - chrono::Duration::days(6);
        assert!(old_record < cutoff, "8-day-old record should be archived");
        assert!(new_record > cutoff, "6-day-old record should be kept");
    }

    #[test]
    fn test_rate_history_keep_n_boundary() {
        // Simulate the ranked-delete logic: rows with rn > keep_n are deleted.
        let keep_n: i64 = 3;
        let row_ranks: Vec<i64> = vec![1, 2, 3, 4, 5];
        let to_delete: Vec<i64> = row_ranks.into_iter().filter(|&r| r > keep_n).collect();
        assert_eq!(to_delete, vec![4, 5]);
    }
}
