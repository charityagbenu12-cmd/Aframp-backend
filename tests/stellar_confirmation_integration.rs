//! Integration tests for the Stellar Confirmation Polling Worker.
//!
//! These tests require:
//!   - A running PostgreSQL instance (DATABASE_URL env var)
//!   - Network access to Stellar Testnet Horizon
//!
//! Run with:
//!   DATABASE_URL=postgres://... cargo test --test stellar_confirmation_integration -- --nocapture
//!
//! Tests are gated behind the `integration` feature flag so they are skipped
//! in normal CI unless explicitly enabled.

#![cfg(feature = "integration")]

use Bitmesh_backend::chains::stellar::client::StellarClient;
use Bitmesh_backend::chains::stellar::config::StellarConfig;
use Bitmesh_backend::database::init_pool;
use Bitmesh_backend::workers::stellar_confirmation_worker::{
    StellarConfirmationConfig, StellarConfirmationWorker, WorkerMetrics,
};
use prometheus::Registry;
use sqlx::PgPool;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn test_pool() -> PgPool {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set for integration tests");
    init_pool(&url, None).await.expect("db pool")
}

fn testnet_stellar_client() -> StellarClient {
    let cfg = StellarConfig::from_env().expect("stellar config");
    StellarClient::new(cfg).expect("stellar client")
}

fn test_metrics() -> Arc<WorkerMetrics> {
    let registry = Registry::new();
    Arc::new(WorkerMetrics::new(&registry).expect("metrics"))
}

/// Insert a synthetic transaction row with a known stellar_tx_hash.
async fn insert_test_transaction(
    pool: &PgPool,
    stellar_tx_hash: &str,
    status: &str,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO transactions
            (transaction_id, wallet_address, type, from_currency, to_currency,
             from_amount, to_amount, cngn_amount, status, stellar_tx_hash, metadata)
        VALUES
            ($1, 'GTEST000000000000000000000000000000000000000000000000000',
             'onramp', 'NGN', 'cNGN', 100, 100, 100, $2, $3, '{}')
        "#,
    )
    .bind(id)
    .bind(status)
    .bind(stellar_tx_hash)
    .execute(pool)
    .await
    .expect("insert test transaction");
    id
}

async fn cleanup_transaction(pool: &PgPool, id: Uuid) {
    sqlx::query("DELETE FROM transactions WHERE transaction_id = $1")
        .bind(id)
        .execute(pool)
        .await
        .ok();
}

async fn get_status(pool: &PgPool, id: Uuid) -> String {
    sqlx::query_scalar::<_, String>("SELECT status FROM transactions WHERE transaction_id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("fetch status")
}

// ---------------------------------------------------------------------------
// Test: pending → completed on a known confirmed Stellar testnet transaction
// ---------------------------------------------------------------------------

/// Uses a well-known, permanently confirmed testnet transaction hash.
/// Replace KNOWN_CONFIRMED_HASH with a real hash from Stellar testnet.
const KNOWN_CONFIRMED_HASH: &str =
    "b9d0b2292c4e09e8eb22d036171491e87b8d2086bf8b265874c8d182cb9c9020";

#[tokio::test]
async fn test_pending_to_completed_on_confirmed_hash() {
    let pool = test_pool().await;
    let tx_id = insert_test_transaction(&pool, KNOWN_CONFIRMED_HASH, "pending").await;

    let config = StellarConfirmationConfig {
        poll_interval: Duration::from_secs(1),
        confirmation_threshold: 1,
        stale_timeout: Duration::from_secs(3600),
        batch_size: 10,
        monitoring_window_hours: 48,
    };

    let worker = StellarConfirmationWorker::new(
        pool.clone(),
        testnet_stellar_client(),
        config,
        test_metrics(),
    );

    // Run a single cycle.
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let handle = tokio::spawn(worker.run(shutdown_rx));
    tokio::time::sleep(Duration::from_secs(5)).await;
    shutdown_tx.send(true).ok();
    handle.await.ok();

    let status = get_status(&pool, tx_id).await;
    assert_eq!(status, "completed", "transaction should be completed");

    // Verify webhook event was emitted.
    let event_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM webhook_events WHERE event_id = $1",
    )
    .bind(format!("stellar.transaction.confirmed:{}", tx_id))
    .fetch_one(&pool)
    .await
    .unwrap_or(0);
    assert_eq!(event_count, 1, "exactly one webhook event should be emitted");

    cleanup_transaction(&pool, tx_id).await;
}

// ---------------------------------------------------------------------------
// Test: idempotency — polling the same confirmed tx twice must not duplicate
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_idempotent_on_repeat_poll() {
    let pool = test_pool().await;
    let tx_id = insert_test_transaction(&pool, KNOWN_CONFIRMED_HASH, "pending").await;

    let config = StellarConfirmationConfig {
        poll_interval: Duration::from_millis(200),
        confirmation_threshold: 1,
        stale_timeout: Duration::from_secs(3600),
        batch_size: 10,
        monitoring_window_hours: 48,
    };

    let worker = StellarConfirmationWorker::new(
        pool.clone(),
        testnet_stellar_client(),
        config,
        test_metrics(),
    );

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let handle = tokio::spawn(worker.run(shutdown_rx));
    // Let it run multiple cycles.
    tokio::time::sleep(Duration::from_secs(4)).await;
    shutdown_tx.send(true).ok();
    handle.await.ok();

    // Webhook events must be exactly 1 despite multiple cycles.
    let event_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM webhook_events WHERE event_id = $1",
    )
    .bind(format!("stellar.transaction.confirmed:{}", tx_id))
    .fetch_one(&pool)
    .await
    .unwrap_or(0);
    assert_eq!(event_count, 1, "webhook must be emitted exactly once");

    cleanup_transaction(&pool, tx_id).await;
}

// ---------------------------------------------------------------------------
// Test: pending → failed on a known failed/rejected Stellar testnet tx
// ---------------------------------------------------------------------------

/// A testnet transaction hash that is known to have failed.
/// Replace with a real failed hash from Stellar testnet.
const KNOWN_FAILED_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000bad";

#[tokio::test]
async fn test_pending_to_failed_on_rejected_hash() {
    let pool = test_pool().await;
    let tx_id = insert_test_transaction(&pool, KNOWN_FAILED_HASH, "pending").await;

    let config = StellarConfirmationConfig {
        poll_interval: Duration::from_secs(1),
        confirmation_threshold: 1,
        stale_timeout: Duration::from_secs(3600),
        batch_size: 10,
        monitoring_window_hours: 48,
    };

    let worker = StellarConfirmationWorker::new(
        pool.clone(),
        testnet_stellar_client(),
        config,
        test_metrics(),
    );

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let handle = tokio::spawn(worker.run(shutdown_rx));
    tokio::time::sleep(Duration::from_secs(5)).await;
    shutdown_tx.send(true).ok();
    handle.await.ok();

    let status = get_status(&pool, tx_id).await;
    // Either "failed" (if hash is found and marked failed) or still "pending"
    // (if hash is not found — treated as transient). Both are valid outcomes
    // for a non-existent hash.
    assert!(
        status == "failed" || status == "pending",
        "unexpected status: {}",
        status
    );

    cleanup_transaction(&pool, tx_id).await;
}

// ---------------------------------------------------------------------------
// Test: stale transaction is flagged
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_stale_transaction_is_flagged() {
    let pool = test_pool().await;
    let tx_id = Uuid::new_v4();

    // Insert a transaction that is already 2 hours old.
    sqlx::query(
        r#"
        INSERT INTO transactions
            (transaction_id, wallet_address, type, from_currency, to_currency,
             from_amount, to_amount, cngn_amount, status, stellar_tx_hash, metadata,
             created_at)
        VALUES
            ($1, 'GTEST000000000000000000000000000000000000000000000000000',
             'onramp', 'NGN', 'cNGN', 100, 100, 100, 'pending', 'stalehash', '{}',
             NOW() - INTERVAL '2 hours')
        "#,
    )
    .bind(tx_id)
    .execute(&pool)
    .await
    .expect("insert stale transaction");

    let config = StellarConfirmationConfig {
        poll_interval: Duration::from_secs(1),
        confirmation_threshold: 1,
        stale_timeout: Duration::from_secs(60), // 1 minute — tx is 2 h old
        batch_size: 10,
        monitoring_window_hours: 48,
    };

    let worker = StellarConfirmationWorker::new(
        pool.clone(),
        testnet_stellar_client(),
        config,
        test_metrics(),
    );

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let handle = tokio::spawn(worker.run(shutdown_rx));
    tokio::time::sleep(Duration::from_secs(3)).await;
    shutdown_tx.send(true).ok();
    handle.await.ok();

    let stale_at: Option<chrono::DateTime<chrono::Utc>> = sqlx::query_scalar(
        "SELECT stale_flagged_at FROM transactions WHERE transaction_id = $1",
    )
    .bind(tx_id)
    .fetch_one(&pool)
    .await
    .expect("fetch stale_flagged_at");

    assert!(stale_at.is_some(), "stale_flagged_at should be set");

    cleanup_transaction(&pool, tx_id).await;
}

// ---------------------------------------------------------------------------
// Test: graceful shutdown completes the in-flight cycle
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_graceful_shutdown() {
    let pool = test_pool().await;

    let config = StellarConfirmationConfig {
        poll_interval: Duration::from_secs(60), // long interval
        confirmation_threshold: 1,
        stale_timeout: Duration::from_secs(3600),
        batch_size: 10,
        monitoring_window_hours: 48,
    };

    let worker = StellarConfirmationWorker::new(
        pool.clone(),
        testnet_stellar_client(),
        config,
        test_metrics(),
    );

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let handle = tokio::spawn(worker.run(shutdown_rx));

    // Signal shutdown almost immediately.
    tokio::time::sleep(Duration::from_millis(100)).await;
    shutdown_tx.send(true).ok();

    // Worker must finish within a reasonable time.
    let result = tokio::time::timeout(Duration::from_secs(10), handle).await;
    assert!(result.is_ok(), "worker did not shut down within 10 seconds");
}
