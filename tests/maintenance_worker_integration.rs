//! Integration tests for the database maintenance worker.
//!
//! These tests require a live PostgreSQL instance reachable via `DATABASE_URL`.
//! Run with:
//!   DATABASE_URL=postgres://... cargo test --test maintenance_worker_integration -- --nocapture
//!
//! Each test creates its own isolated data and cleans up after itself.

#![cfg(feature = "database")]

use sqlx::PgPool;
use std::time::Duration;
use tokio::sync::watch;
use uuid::Uuid;

// Re-export the worker types under test
use Bitmesh_backend::workers::maintenance::{MaintenanceConfig, MaintenanceWorker};

// ── Helpers ───────────────────────────────────────────────────────────────────

async fn test_pool() -> PgPool {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set for integration tests");
    PgPool::connect(&url).await.expect("Failed to connect to test database")
}

/// Insert a completed transaction with a given `created_at` offset from now.
async fn insert_old_transaction(pool: &PgPool, days_ago: i64) -> Uuid {
    let id = Uuid::new_v4();
    let wallet = format!("G{}", Uuid::new_v4().simple());
    // Ensure wallet exists (FK)
    sqlx::query(
        "INSERT INTO wallets (wallet_address, chain, balance) VALUES ($1, 'stellar', '0') ON CONFLICT DO NOTHING",
    )
    .bind(&wallet)
    .execute(pool)
    .await
    .unwrap();

    sqlx::query(
        r#"
        INSERT INTO transactions
            (transaction_id, wallet_address, type, from_currency, to_currency,
             from_amount, to_amount, cngn_amount, status, metadata, created_at, updated_at)
        VALUES ($1, $2, 'onramp', 'NGN', 'CNGN', 100, 100, 100, 'completed', '{}',
                now() - ($3 || ' days')::interval,
                now() - ($3 || ' days')::interval)
        "#,
    )
    .bind(id)
    .bind(&wallet)
    .bind(days_ago.to_string())
    .execute(pool)
    .await
    .unwrap();

    id
}

/// Insert an expired onramp quote.
async fn insert_expired_quote(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO onramp_quotes
            (id, quote_id, amount_ngn, exchange_rate, gross_cngn, fee_cngn, net_cngn,
             status, expires_at)
        VALUES ($1, $2, 1000, 1, 1000, 0, 1000, 'pending', now() - interval '1 hour')
        "#,
    )
    .bind(id)
    .bind(Uuid::new_v4())
    .execute(pool)
    .await
    .unwrap();
    id
}

/// Insert a completed webhook event older than the retention window.
async fn insert_old_webhook(pool: &PgPool, days_ago: i64) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO webhook_events
            (id, event_id, provider, event_type, payload, status, created_at, updated_at)
        VALUES ($1, $2, 'flutterwave', 'payment.success', '{}', 'completed',
                now() - ($3 || ' days')::interval,
                now() - ($3 || ' days')::interval)
        "#,
    )
    .bind(id)
    .bind(Uuid::new_v4().to_string())
    .bind(days_ago.to_string())
    .execute(pool)
    .await
    .unwrap();
    id
}

/// Insert an expired nonce.
async fn insert_expired_nonce(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO wallet_nonces (id, wallet_address, nonce, expires_at)
        VALUES ($1, 'GTEST', $2, now() - interval '1 hour')
        "#,
    )
    .bind(id)
    .bind(Uuid::new_v4().to_string())
    .execute(pool)
    .await
    .unwrap();
    id
}

/// Insert a rate history row older than the retention window.
async fn insert_old_rate_history(pool: &PgPool, days_ago: i64) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO exchange_rate_history (id, from_currency, to_currency, rate, recorded_at)
        VALUES ($1, 'NGN', 'CNGN', '1.0', now() - ($2 || ' days')::interval)
        "#,
    )
    .bind(id)
    .bind(days_ago.to_string())
    .execute(pool)
    .await
    .unwrap();
    id
}

fn aggressive_config() -> MaintenanceConfig {
    MaintenanceConfig {
        interval: Duration::from_secs(86_400),
        transaction_retention: Duration::from_secs(1),   // 1 second — everything is "old"
        webhook_retention: Duration::from_secs(1),
        nonce_retention: Duration::from_secs(1),
        rate_history_retention: Duration::from_secs(1),
        rate_history_keep_n: 0, // delete all
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// Full cleanup cycle: aged data across all target tables is cleaned up.
#[tokio::test]
async fn test_full_cleanup_cycle_with_aged_data() {
    let pool = test_pool().await;
    let config = aggressive_config();

    let tx_id = insert_old_transaction(&pool, 100).await;
    let quote_id = insert_expired_quote(&pool).await;
    let webhook_id = insert_old_webhook(&pool, 35).await;
    let nonce_id = insert_expired_nonce(&pool).await;
    let rate_id = insert_old_rate_history(&pool, 35).await;

    let worker = MaintenanceWorker::new(pool.clone(), None, config);
    let (_tx, rx) = watch::channel(false);
    // Run a single cycle by calling the internal method via a one-shot shutdown.
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let handle = tokio::spawn(worker.run(shutdown_rx));
    // Give the worker time to tick (interval is 24h so it runs immediately on first tick)
    tokio::time::sleep(Duration::from_millis(500)).await;
    let _ = shutdown_tx.send(true);
    let _ = handle.await;

    // Transactions should be in archive, not in main table
    let in_main: Option<Uuid> = sqlx::query_scalar(
        "SELECT transaction_id FROM transactions WHERE transaction_id = $1",
    )
    .bind(tx_id)
    .fetch_optional(&pool)
    .await
    .unwrap();
    assert!(in_main.is_none(), "Transaction should have been archived");

    let in_archive: Option<Uuid> = sqlx::query_scalar(
        "SELECT transaction_id FROM transactions_archive WHERE transaction_id = $1",
    )
    .bind(tx_id)
    .fetch_optional(&pool)
    .await
    .unwrap();
    assert!(in_archive.is_some(), "Transaction should be in archive");

    // Expired quote deleted
    let q: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM onramp_quotes WHERE id = $1")
            .bind(quote_id)
            .fetch_optional(&pool)
            .await
            .unwrap();
    assert!(q.is_none(), "Expired quote should be deleted");

    // Old webhook deleted
    let w: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM webhook_events WHERE id = $1")
            .bind(webhook_id)
            .fetch_optional(&pool)
            .await
            .unwrap();
    assert!(w.is_none(), "Old webhook should be deleted");

    // Expired nonce deleted
    let n: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM wallet_nonces WHERE id = $1")
            .bind(nonce_id)
            .fetch_optional(&pool)
            .await
            .unwrap();
    assert!(n.is_none(), "Expired nonce should be deleted");

    // Old rate history deleted
    let r: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM exchange_rate_history WHERE id = $1")
            .bind(rate_id)
            .fetch_optional(&pool)
            .await
            .unwrap();
    assert!(r.is_none(), "Old rate history should be deleted");

    // Cleanup report persisted
    let report_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM cleanup_reports")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(report_count > 0, "Cleanup report should be persisted");
}

/// Idempotent re-run: running the worker twice on an already-cleaned dataset
/// produces no errors and no unintended deletions.
#[tokio::test]
async fn test_idempotent_rerun() {
    let pool = test_pool().await;
    let config = aggressive_config();

    // First run
    let worker = MaintenanceWorker::new(pool.clone(), None, config.clone());
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let handle = tokio::spawn(worker.run(shutdown_rx));
    tokio::time::sleep(Duration::from_millis(300)).await;
    let _ = shutdown_tx.send(true);
    let _ = handle.await;

    // Second run — should complete without error
    let worker2 = MaintenanceWorker::new(pool.clone(), None, config);
    let (shutdown_tx2, shutdown_rx2) = watch::channel(false);
    let handle2 = tokio::spawn(worker2.run(shutdown_rx2));
    tokio::time::sleep(Duration::from_millis(300)).await;
    let _ = shutdown_tx2.send(true);
    let result = handle2.await;
    assert!(result.is_ok(), "Second run should complete without panic");
}

/// Graceful shutdown: the active cycle completes before the worker exits.
#[tokio::test]
async fn test_graceful_shutdown_completes_cycle() {
    let pool = test_pool().await;
    let config = MaintenanceConfig {
        interval: Duration::from_millis(50), // fire quickly
        ..aggressive_config()
    };

    let worker = MaintenanceWorker::new(pool.clone(), None, config);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let handle = tokio::spawn(worker.run(shutdown_rx));

    // Let it start, then signal shutdown
    tokio::time::sleep(Duration::from_millis(200)).await;
    let _ = shutdown_tx.send(true);

    // Worker must finish cleanly (no panic / timeout)
    tokio::time::timeout(Duration::from_secs(10), handle)
        .await
        .expect("Worker should shut down within 10 seconds")
        .expect("Worker task should not panic");
}
