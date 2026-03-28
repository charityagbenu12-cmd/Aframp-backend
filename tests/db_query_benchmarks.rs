/// Database query benchmark tests.
///
/// These tests connect to a real PostgreSQL instance (DATABASE_URL env var) and
/// assert that critical queries complete within defined latency budgets at scale
/// (≥ 1 million transaction rows).
///
/// Run with:
///   DATABASE_URL=postgres://... cargo test --test db_query_benchmarks \
///     --features database,integration -- --nocapture
///
/// Seed data first:
///   psql "$DATABASE_URL" -f db/seed_benchmark_data.sql
/// assert that critical queries complete within defined latency budgets at scale.
///
/// Run with:
///   DATABASE_URL=postgres://... cargo test --test db_query_benchmarks --features database -- --nocapture
///
/// The tests are gated behind the `integration` feature flag so they are skipped
/// in unit-test runs that do not have a database available.
#[cfg(feature = "integration")]
mod db_benchmarks {
    use sqlx::PgPool;
    use std::time::{Duration, Instant};

    /// Connect to the database using DATABASE_URL from the environment.
    async fn pool() -> PgPool {
        let url = std::env::var("DATABASE_URL")
            .expect("DATABASE_URL must be set for integration tests");
        PgPool::connect(&url)
            .await
            .expect("Failed to connect to database")
    }

    fn assert_within(label: &str, elapsed: Duration, budget: Duration) {
        println!(
            "[BENCH] {}: {:.2}ms (budget: {}ms)",
            label,
            elapsed.as_secs_f64() * 1000.0,
            budget.as_millis()
        );
    /// Assert that `elapsed` is within `budget`. Prints timing regardless.
    fn assert_within(label: &str, elapsed: Duration, budget: Duration) {
        println!("[BENCH] {}: {:.2}ms (budget: {}ms)",
            label,
            elapsed.as_secs_f64() * 1000.0,
            budget.as_millis());
        assert!(
            elapsed <= budget,
            "{} exceeded budget: {:.2}ms > {}ms",
            label,
            elapsed.as_secs_f64() * 1000.0,
            budget.as_millis()
        );
    }

    // -------------------------------------------------------------------------
    // Q1: Transaction lookup by PK
    // Q1: Transaction lookup by ID (PK scan)
    // Budget: 5 ms
    // -------------------------------------------------------------------------
    #[tokio::test]
    async fn bench_transaction_by_id() {
        let pool = pool().await;

        let row: Option<(uuid::Uuid,)> =
            sqlx::query_as("SELECT transaction_id FROM transactions LIMIT 1")
                .fetch_optional(&pool)
                .await
                .unwrap();
        // Pick a real transaction_id from the table
        let row: Option<(uuid::Uuid,)> = sqlx::query_as(
            "SELECT transaction_id FROM transactions LIMIT 1"
        )
        .fetch_optional(&pool)
        .await
        .unwrap();

        let Some((id,)) = row else {
            println!("[BENCH] bench_transaction_by_id: skipped (no data)");
            return;
        };

        let start = Instant::now();
        let _: Option<(uuid::Uuid,)> = sqlx::query_as(
            "SELECT transaction_id FROM transactions WHERE transaction_id = $1",
            "SELECT transaction_id FROM transactions WHERE transaction_id = $1"
        )
        .bind(id)
        .fetch_optional(&pool)
        .await
        .unwrap();
        assert_within("transaction_by_id", start.elapsed(), Duration::from_millis(5));
    }

    // -------------------------------------------------------------------------
    // Q2: Worker polling — pending/processing (hot path)
    // Q2: Worker polling — pending/processing transactions (hot path)
    // Budget: 20 ms
    // -------------------------------------------------------------------------
    #[tokio::test]
    async fn bench_worker_polling_pending() {
        let pool = pool().await;
        let start = Instant::now();
        let _: Vec<(uuid::Uuid,)> = sqlx::query_as(
            "SELECT transaction_id
             FROM transactions
             WHERE status IN ('pending', 'processing', 'pending_payment')
               AND created_at > NOW() - INTERVAL '24 hours'
             ORDER BY created_at ASC
             LIMIT 100",
             LIMIT 100"
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_within(
            "worker_polling_pending",
            start.elapsed(),
            Duration::from_millis(20),
        );
        assert_within("worker_polling_pending", start.elapsed(), Duration::from_millis(20));
    }

    // -------------------------------------------------------------------------
    // Q3: Offramp worker polling
    // Budget: 20 ms
    // -------------------------------------------------------------------------
    #[tokio::test]
    async fn bench_offramp_polling() {
        let pool = pool().await;
        let start = Instant::now();
        let _: Vec<(uuid::Uuid,)> = sqlx::query_as(
            "SELECT transaction_id
             FROM transactions
             WHERE status = 'pending' AND type = 'offramp'
             ORDER BY created_at ASC
             LIMIT 50",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_within(
            "offramp_polling",
            start.elapsed(),
            Duration::from_millis(20),
        );
    }

    // -------------------------------------------------------------------------
    // Q4: Stellar confirmation worker polling
    // Budget: 10 ms
    // -------------------------------------------------------------------------
    #[tokio::test]
    async fn bench_stellar_confirmation_polling() {
        let pool = pool().await;
        let start = Instant::now();
        let _: Vec<(uuid::Uuid,)> = sqlx::query_as(
            "SELECT transaction_id
             FROM transactions
             WHERE status IN ('pending', 'processing')
               AND stellar_tx_hash IS NOT NULL
               AND stellar_tx_hash <> ''
               AND created_at > NOW() - INTERVAL '24 hours'
             ORDER BY created_at ASC
             LIMIT 100",
             LIMIT 50"
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_within(
            "stellar_confirmation_polling",
            start.elapsed(),
            Duration::from_millis(10),
        );
    }

    // -------------------------------------------------------------------------
    // Q5: Transaction history — cursor-based pagination (first page)
        assert_within("offramp_polling", start.elapsed(), Duration::from_millis(20));
    }

    // -------------------------------------------------------------------------
    // Q4: Transaction history — cursor-based pagination (first page)
    // Budget: 15 ms
    // -------------------------------------------------------------------------
    #[tokio::test]
    async fn bench_history_cursor_first_page() {
        let pool = pool().await;

        let row: Option<(String,)> = sqlx::query_as(
            "SELECT wallet_address FROM wallets WHERE wallet_address LIKE 'G%' LIMIT 1",
            "SELECT wallet_address FROM wallets WHERE wallet_address LIKE 'G%' LIMIT 1"
        )
        .fetch_optional(&pool)
        .await
        .unwrap();

        let Some((wallet,)) = row else {
            println!("[BENCH] bench_history_cursor_first_page: skipped (no data)");
            return;
        };

        let start = Instant::now();
        let _: Vec<(uuid::Uuid,)> = sqlx::query_as(
            "SELECT transaction_id
             FROM transactions
             WHERE wallet_address = $1
             ORDER BY created_at DESC, transaction_id DESC
             LIMIT 20",
             LIMIT 20"
        )
        .bind(&wallet)
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_within(
            "history_cursor_first_page",
            start.elapsed(),
            Duration::from_millis(15),
        );
    }

    // -------------------------------------------------------------------------
    // Q6: Transaction history — cursor-based pagination (deep page, ~500 rows in)
    // Budget: 15 ms — must not degrade with depth
        assert_within("history_cursor_first_page", start.elapsed(), Duration::from_millis(15));
    }

    // -------------------------------------------------------------------------
    // Q5: Transaction history — cursor-based pagination (deep page)
    // Budget: 15 ms  (must not degrade with offset)
    // -------------------------------------------------------------------------
    #[tokio::test]
    async fn bench_history_cursor_deep_page() {
        let pool = pool().await;

        let wallet_row: Option<(String,)> = sqlx::query_as(
            "SELECT wallet_address FROM wallets WHERE wallet_address LIKE 'G%' LIMIT 1",
        )
        .fetch_optional(&pool)
        .await
        .unwrap();

        let Some((wallet,)) = wallet_row else {
            println!("[BENCH] bench_history_cursor_deep_page: skipped (no data)");
            return;
        };

        // Obtain a cursor from ~500 rows in using OFFSET (setup only, not timed)
        let cursor_row: Option<(chrono::DateTime<chrono::Utc>, uuid::Uuid)> = sqlx::query_as(
            "SELECT created_at, transaction_id
             FROM transactions
             WHERE wallet_address = $1
             ORDER BY created_at DESC, transaction_id DESC
             OFFSET 500 LIMIT 1",
        )
        .bind(&wallet)
        // Get a cursor from ~500 rows in
        let row: Option<(chrono::DateTime<chrono::Utc>, uuid::Uuid)> = sqlx::query_as(
            "SELECT created_at, transaction_id
             FROM transactions
             WHERE wallet_address = (
                 SELECT wallet_address FROM wallets WHERE wallet_address LIKE 'G%' LIMIT 1
             )
             ORDER BY created_at DESC, transaction_id DESC
             OFFSET 500 LIMIT 1"
        )
        .fetch_optional(&pool)
        .await
        .unwrap();

        let Some((cursor_ts, cursor_id)) = cursor_row else {
        let Some((cursor_ts, cursor_id)) = row else {
            println!("[BENCH] bench_history_cursor_deep_page: skipped (insufficient data)");
            return;
        };

        let start = Instant::now();
        let _: Vec<(uuid::Uuid,)> = sqlx::query_as(
            "SELECT transaction_id
             FROM transactions
             WHERE wallet_address = $1
               AND (created_at, transaction_id) < ($2, $3)
             ORDER BY created_at DESC, transaction_id DESC
             LIMIT 20",
        )
        .bind(&wallet)
        .bind(cursor_ts)
        .bind(cursor_id)
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_within(
            "history_cursor_deep_page",
            start.elapsed(),
            Duration::from_millis(15),
        );
    }

    // -------------------------------------------------------------------------
    // Q7: Transaction history — filter by type (cursor)
    // Budget: 15 ms
    // -------------------------------------------------------------------------
    #[tokio::test]
    async fn bench_history_filter_by_type() {
        let pool = pool().await;

        let row: Option<(String,)> = sqlx::query_as(
            "SELECT wallet_address FROM wallets WHERE wallet_address LIKE 'G%' LIMIT 1",
        )
        .fetch_optional(&pool)
        .await
        .unwrap();

        let Some((wallet,)) = row else {
            println!("[BENCH] bench_history_filter_by_type: skipped (no data)");
            return;
        };

        let wallet: (String,) = sqlx::query_as(
            "SELECT wallet_address FROM wallets WHERE wallet_address LIKE 'G%' LIMIT 1"
        )
        .fetch_one(&pool)
        .await
        .unwrap();

        let start = Instant::now();
        let _: Vec<(uuid::Uuid,)> = sqlx::query_as(
            "SELECT transaction_id
             FROM transactions
             WHERE wallet_address = $1 AND type = 'onramp'
             ORDER BY created_at DESC, transaction_id DESC
             LIMIT 20",
        )
        .bind(&wallet)
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_within(
            "history_filter_by_type",
            start.elapsed(),
            Duration::from_millis(15),
        );
    }

    // -------------------------------------------------------------------------
    // Q8: Payment reference lookup (index-only scan)
             WHERE wallet_address = $1
               AND (created_at, transaction_id) < ($2, $3)
             ORDER BY created_at DESC, transaction_id DESC
             LIMIT 20"
        )
        .bind(&wallet.0)
        .bind(cursor_ts)
        .bind(cursor_id)
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_within("history_cursor_deep_page", start.elapsed(), Duration::from_millis(15));
    }

    // -------------------------------------------------------------------------
    // Q6: Payment reference lookup
    // Budget: 5 ms
    // -------------------------------------------------------------------------
    #[tokio::test]
    async fn bench_payment_reference_lookup() {
        let pool = pool().await;

        let row: Option<(String,)> = sqlx::query_as(
            "SELECT payment_reference FROM transactions
             WHERE payment_reference IS NOT NULL LIMIT 1",
             WHERE payment_reference IS NOT NULL LIMIT 1"
        )
        .fetch_optional(&pool)
        .await
        .unwrap();

        let Some((reference,)) = row else {
            println!("[BENCH] bench_payment_reference_lookup: skipped (no data)");
            return;
        };

        let start = Instant::now();
        let _: Option<(uuid::Uuid,)> = sqlx::query_as(
            "SELECT transaction_id FROM transactions WHERE payment_reference = $1",
            "SELECT transaction_id FROM transactions WHERE payment_reference = $1"
        )
        .bind(&reference)
        .fetch_optional(&pool)
        .await
        .unwrap();
        assert_within(
            "payment_reference_lookup",
            start.elapsed(),
            Duration::from_millis(5),
        );
    }

    // -------------------------------------------------------------------------
    // Q9: Wallet balance check (index-only scan)
    // Budget: 5 ms
    // -------------------------------------------------------------------------
    #[tokio::test]
    async fn bench_wallet_balance_check() {
        let pool = pool().await;

        let row: Option<(String,)> = sqlx::query_as(
            "SELECT wallet_address FROM wallets WHERE wallet_address LIKE 'G%' LIMIT 1",
        )
        .fetch_optional(&pool)
        .await
        .unwrap();

        let Some((address,)) = row else {
            println!("[BENCH] bench_wallet_balance_check: skipped (no data)");
            return;
        };

        let start = Instant::now();
        let _: Option<(String,)> = sqlx::query_as(
            "SELECT balance FROM wallets WHERE wallet_address = $1",
        )
        .bind(&address)
        .fetch_optional(&pool)
        .await
        .unwrap();
        assert_within(
            "wallet_balance_check",
            start.elapsed(),
            Duration::from_millis(5),
        );
    }

    // -------------------------------------------------------------------------
    // Q10: Exchange rate lookup (cache miss path)
    // Budget: 5 ms
    // -------------------------------------------------------------------------
    #[tokio::test]
    async fn bench_exchange_rate_lookup() {
        let pool = pool().await;
        let start = Instant::now();
        let _: Option<(String,)> = sqlx::query_as(
            "SELECT rate FROM exchange_rates
             WHERE from_currency = $1 AND to_currency = $2
             ORDER BY created_at DESC LIMIT 1",
        )
        .bind("NGN")
        .bind("cNGN")
        .fetch_optional(&pool)
        .await
        .unwrap();
        assert_within(
            "exchange_rate_lookup",
            start.elapsed(),
            Duration::from_millis(5),
        );
    }

    // -------------------------------------------------------------------------
    // Q11: Settlement aggregation — daily volume (materialised view)
        assert_within("payment_reference_lookup", start.elapsed(), Duration::from_millis(5));
    }

    // -------------------------------------------------------------------------
    // Q7: Settlement aggregation — daily volume (materialised view)
    // Budget: 10 ms
    // -------------------------------------------------------------------------
    #[tokio::test]
    async fn bench_daily_volume_mv() {
        let pool = pool().await;
        let start = Instant::now();
        let _: Vec<(chrono::NaiveDate, String, i64)> = sqlx::query_as(
            "SELECT day, type, tx_count
             FROM mv_daily_transaction_volume
             WHERE day >= CURRENT_DATE - INTERVAL '30 days'
             ORDER BY day DESC",
             ORDER BY day DESC"
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_within(
            "daily_volume_mv",
            start.elapsed(),
            Duration::from_millis(10),
        );
    }

    // -------------------------------------------------------------------------
    // Q12: Provider performance summary (materialised view)
    // Budget: 10 ms
    // -------------------------------------------------------------------------
    #[tokio::test]
    async fn bench_provider_performance_mv() {
        let pool = pool().await;
        let start = Instant::now();
        let _: Vec<(String, f64)> = sqlx::query_as(
            "SELECT payment_provider, AVG(success_rate_pct) AS avg_success
             FROM mv_provider_performance
             WHERE hour >= NOW() - INTERVAL '24 hours'
             GROUP BY payment_provider",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_within(
            "provider_performance_mv",
            start.elapsed(),
            Duration::from_millis(10),
        );
    }

    // -------------------------------------------------------------------------
    // Q13: Reconciliation — completed transactions by provider in date range
    // Budget: 30 ms
    // -------------------------------------------------------------------------
    #[tokio::test]
    async fn bench_reconciliation_by_provider() {
        let pool = pool().await;
        let start = Instant::now();
        let _: Vec<(String, i64, sqlx::types::BigDecimal)> = sqlx::query_as(
            "SELECT payment_provider, COUNT(*) AS count, SUM(from_amount) AS volume
             FROM transactions
             WHERE status = 'completed'
               AND created_at >= NOW() - INTERVAL '7 days'
             GROUP BY payment_provider",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_within(
            "reconciliation_by_provider",
            start.elapsed(),
            Duration::from_millis(30),
        );
    }

    // -------------------------------------------------------------------------
    // Q14: Settlement aggregation — raw query (no MV) for date range
    // Budget: 50 ms
    // -------------------------------------------------------------------------
    #[tokio::test]
    async fn bench_settlement_aggregation_raw() {
        let pool = pool().await;
        let start = Instant::now();
        let _: Vec<(String, String, i64, sqlx::types::BigDecimal)> = sqlx::query_as(
            "SELECT type, status, COUNT(*) AS tx_count, SUM(from_amount) AS total
             FROM transactions
             WHERE created_at BETWEEN NOW() - INTERVAL '30 days' AND NOW()
             GROUP BY type, status",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_within(
            "settlement_aggregation_raw",
            start.elapsed(),
            Duration::from_millis(50),
        );
    }

    // -------------------------------------------------------------------------
    // Q15: Unused index detection (should always be fast)
    // Budget: 100 ms
    // -------------------------------------------------------------------------
    #[tokio::test]
    async fn bench_unused_index_detection() {
        let pool = pool().await;
        let start = Instant::now();
        let _: Vec<(String, String, i64)> = sqlx::query_as(
            "SELECT tablename, indexname, idx_scan
             FROM v_unused_indexes
             LIMIT 50",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_within(
            "unused_index_detection",
            start.elapsed(),
            Duration::from_millis(100),
        );
        assert_within("reconciliation_by_provider", start.elapsed(), Duration::from_millis(30));
    }
}
