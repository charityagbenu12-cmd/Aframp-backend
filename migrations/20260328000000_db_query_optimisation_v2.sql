-- migrate:up
-- =============================================================================
-- Database Query Optimisation v2 (comprehensive)
--
-- Covers:
--   1.  pg_stat_statements + slow query logging
--   2.  Balance check indexes (wallets)
--   3.  Composite indexes for all worker polling paths
--   4.  Covering indexes for high-frequency read paths
--   5.  Missing FK indexes
--   6.  Cursor-based pagination support
--   7.  Settlement / reconciliation aggregation indexes
--   8.  Exchange rate lookup optimisation
--   9.  Fee structure lookup optimisation
--   10. Materialised views: daily_tx_volume, provider_performance
--   11. Refresh helper function
--   12. Unused index detection view
-- =============================================================================

-- ---------------------------------------------------------------------------
-- 1. pg_stat_statements
-- ---------------------------------------------------------------------------
CREATE EXTENSION IF NOT EXISTS pg_stat_statements;

-- ---------------------------------------------------------------------------
-- 2. Wallet balance checks
--    find_by_account / has_sufficient_balance:
--      WHERE wallet_address = $1
--    The existing idx_wallets_address_chain covers (wallet_address, chain).
--    Add a covering index that includes balance to allow index-only scans.
-- ---------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_wallets_address_balance
    ON wallets (wallet_address)
    INCLUDE (balance, afri_balance, last_balance_check, user_id)
    WHERE wallet_address IS NOT NULL;

-- ---------------------------------------------------------------------------
-- 3. Worker polling — pending/processing transactions (hot path)
--    find_pending_payments_for_monitoring:
--      WHERE status IN ('pending','processing','pending_payment')
--        AND created_at > NOW() - INTERVAL '...'
--      ORDER BY created_at ASC
-- ---------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_transactions_status_created_asc
    ON transactions (status, created_at ASC)
    WHERE status IN ('pending', 'processing', 'pending_payment');

-- ---------------------------------------------------------------------------
-- 4. Worker polling — offramp processor
--    find_offramps_by_status:
--      WHERE status = $1 AND type = 'offramp'
--      ORDER BY created_at ASC
-- ---------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_transactions_offramp_status_created
    ON transactions (status, created_at ASC)
    WHERE type = 'offramp';

-- ---------------------------------------------------------------------------
-- 5. Worker polling — general find_by_status (payment poller)
--    WHERE status = $1 ORDER BY created_at ASC
-- ---------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_transactions_status_created_general
    ON transactions (status, created_at ASC);

-- ---------------------------------------------------------------------------
-- 6. Stellar confirmation worker
--    WHERE status IN ('pending','processing')
--      AND stellar_tx_hash IS NOT NULL AND stellar_tx_hash <> ''
--      AND created_at > NOW() - INTERVAL '...'
--    ORDER BY created_at ASC
-- ---------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_transactions_stellar_polling
    ON transactions (status, created_at ASC)
    INCLUDE (stellar_tx_hash, transaction_id)
    WHERE stellar_tx_hash IS NOT NULL
      AND status IN ('pending', 'processing');

-- ---------------------------------------------------------------------------
-- 7. Blockchain hash direct lookup
-- ---------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_transactions_blockchain_hash
    ON transactions (blockchain_tx_hash)
    WHERE blockchain_tx_hash IS NOT NULL;

-- ---------------------------------------------------------------------------
-- 8. Payment reference — covering index (index-only scan)
-- ---------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_transactions_payment_ref_covering
    ON transactions (payment_reference)
    INCLUDE (transaction_id, wallet_address, status, type, created_at)
    WHERE payment_reference IS NOT NULL;

-- ---------------------------------------------------------------------------
-- 9. Transaction history — cursor-based pagination
--    (wallet_address, created_at DESC, transaction_id DESC)
--    Already created in 20260326000000_transaction_history_indexes.sql;
--    guard with IF NOT EXISTS.
-- ---------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_transactions_history_cursor
    ON transactions (wallet_address, created_at DESC, transaction_id DESC);

-- Filter by type within a wallet
CREATE INDEX IF NOT EXISTS idx_transactions_wallet_type_cursor
    ON transactions (wallet_address, type, created_at DESC, transaction_id DESC);

-- Filter by status within a wallet
CREATE INDEX IF NOT EXISTS idx_transactions_wallet_status_cursor
    ON transactions (wallet_address, status, created_at DESC, transaction_id DESC);

-- Filter by currency pair within a wallet
CREATE INDEX IF NOT EXISTS idx_transactions_wallet_currency_cursor
    ON transactions (wallet_address, from_currency, to_currency, created_at DESC, transaction_id DESC);

-- ---------------------------------------------------------------------------
-- 10. Reconciliation / settlement aggregation
--     Queries that aggregate by (type, status, date) for daily reports.
-- ---------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_transactions_type_status_date
    ON transactions (type, status, date_trunc('day', created_at));

-- Completed transactions by provider in a date range (reconciliation)
CREATE INDEX IF NOT EXISTS idx_transactions_provider_status_created
    ON transactions (payment_provider, status, created_at DESC)
    WHERE payment_provider IS NOT NULL;

-- ---------------------------------------------------------------------------
-- 11. Missing FK indexes
-- ---------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_webhook_events_transaction_id_fk
    ON webhook_events (transaction_id);

CREATE INDEX IF NOT EXISTS idx_conversion_audits_transaction_id_fk
    ON conversion_audits (transaction_id);

-- ---------------------------------------------------------------------------
-- 12. Exchange rate lookup optimisation
--     get_current_rate: WHERE from_currency=$1 AND to_currency=$2
--                       ORDER BY created_at DESC LIMIT 1
-- ---------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_exchange_rates_pair_created
    ON exchange_rates (from_currency, to_currency, created_at DESC);

-- ---------------------------------------------------------------------------
-- 13. Fee structure lookup optimisation
--     get_active_by_type: WHERE fee_type=$1 AND is_active=TRUE
--                         AND effective_from <= $2
--                         AND (effective_until IS NULL OR effective_until >= $2)
-- ---------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_fee_structures_active_type_time
    ON fee_structures (fee_type, effective_from DESC)
    WHERE is_active = TRUE;

-- ---------------------------------------------------------------------------
-- 14. Batch items — pending items per batch
-- ---------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_batch_items_batch_status
    ON batch_items (batch_id, status);

-- ---------------------------------------------------------------------------
-- 15. Recurring payment schedules — due-date polling
-- ---------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_recurring_schedules_due_covering
    ON recurring_payment_schedules (next_execution_at ASC, status)
    INCLUDE (wallet_address, id)
    WHERE status = 'active';

-- ---------------------------------------------------------------------------
-- 16. Onramp quotes — expiry polling
-- ---------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_onramp_quotes_expires_status
    ON onramp_quotes (expires_at ASC, status)
    WHERE status != 'consumed';

-- ---------------------------------------------------------------------------
-- 17. Materialised view — daily transaction volume
--     Refreshed once per day. Staleness: ≤ 24 h.
-- ---------------------------------------------------------------------------
CREATE MATERIALIZED VIEW IF NOT EXISTS mv_daily_transaction_volume AS
SELECT
    date_trunc('day', created_at)::date  AS day,
    type,
    status,
    from_currency,
    to_currency,
    COUNT(*)                             AS tx_count,
    SUM(from_amount)                     AS total_from_amount,
    SUM(to_amount)                       AS total_to_amount,
    SUM(cngn_amount)                     AS total_cngn_amount,
    AVG(from_amount)                     AS avg_from_amount
FROM transactions
GROUP BY 1, 2, 3, 4, 5
WITH DATA;

CREATE UNIQUE INDEX IF NOT EXISTS idx_mv_daily_tx_volume_pk
    ON mv_daily_transaction_volume (day, type, status, from_currency, to_currency);

CREATE INDEX IF NOT EXISTS idx_mv_daily_tx_volume_day
    ON mv_daily_transaction_volume (day DESC);

COMMENT ON MATERIALIZED VIEW mv_daily_transaction_volume IS
    'Pre-aggregated daily transaction volume. Refresh daily (00:05 UTC) via '
    'REFRESH MATERIALIZED VIEW CONCURRENTLY mv_daily_transaction_volume';

-- ---------------------------------------------------------------------------
-- 18. Materialised view — provider performance summary
--     Refreshed every hour. Staleness: ≤ 1 h.
-- ---------------------------------------------------------------------------
CREATE MATERIALIZED VIEW IF NOT EXISTS mv_provider_performance AS
SELECT
    payment_provider,
    type,
    date_trunc('hour', created_at)                AS hour,
    COUNT(*)                                       AS tx_count,
    COUNT(*) FILTER (WHERE status = 'completed')   AS completed_count,
    COUNT(*) FILTER (WHERE status = 'failed')      AS failed_count,
    COUNT(*) FILTER (WHERE status IN ('pending','processing')) AS in_flight_count,
    ROUND(
        COUNT(*) FILTER (WHERE status = 'completed')::numeric
        / NULLIF(COUNT(*), 0) * 100, 2
    )                                              AS success_rate_pct,
    AVG(
        EXTRACT(EPOCH FROM (updated_at - created_at))
    ) FILTER (WHERE status = 'completed')          AS avg_completion_secs
FROM transactions
WHERE payment_provider IS NOT NULL
GROUP BY 1, 2, 3
WITH DATA;

CREATE UNIQUE INDEX IF NOT EXISTS idx_mv_provider_perf_pk
    ON mv_provider_performance (payment_provider, type, hour);

CREATE INDEX IF NOT EXISTS idx_mv_provider_perf_hour
    ON mv_provider_performance (hour DESC);

COMMENT ON MATERIALIZED VIEW mv_provider_performance IS
    'Hourly provider performance metrics. Refresh hourly via '
    'REFRESH MATERIALIZED VIEW CONCURRENTLY mv_provider_performance';

-- ---------------------------------------------------------------------------
-- 19. Refresh helper function
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION refresh_analytics_views()
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
    REFRESH MATERIALIZED VIEW CONCURRENTLY mv_provider_performance;

    -- Refresh daily view at most once per 23 h to avoid heavy I/O
    IF NOT EXISTS (
        SELECT 1
        FROM pg_stat_user_tables
        WHERE relname = 'mv_daily_transaction_volume'
          AND last_analyze > now() - INTERVAL '23 hours'
    ) THEN
        REFRESH MATERIALIZED VIEW CONCURRENTLY mv_daily_transaction_volume;
    END IF;
END;
$$;

COMMENT ON FUNCTION refresh_analytics_views() IS
    'Refreshes mv_provider_performance every call and mv_daily_transaction_volume '
    'at most once per 23 hours. Schedule with pg_cron or db_maintenance_worker.';

-- ---------------------------------------------------------------------------
-- 20. Slow query logging (superuser only; skipped gracefully otherwise)
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF current_setting('is_superuser') = 'on' THEN
        PERFORM set_config('log_min_duration_statement', '200', false);
    END IF;
EXCEPTION WHEN OTHERS THEN
    NULL;
END $$;

-- ---------------------------------------------------------------------------
-- 21. Unused index detection helper view
--     Query: SELECT * FROM v_unused_indexes ORDER BY index_size_bytes DESC;
-- ---------------------------------------------------------------------------
CREATE OR REPLACE VIEW v_unused_indexes AS
SELECT
    schemaname,
    tablename,
    indexname,
    idx_scan,
    idx_tup_read,
    idx_tup_fetch,
    pg_relation_size(indexrelid)            AS index_size_bytes,
    pg_size_pretty(pg_relation_size(indexrelid)) AS index_size
FROM pg_stat_user_indexes
WHERE schemaname = 'public'
  AND idx_scan = 0
ORDER BY pg_relation_size(indexrelid) DESC;

COMMENT ON VIEW v_unused_indexes IS
    'Lists indexes with zero scans since last pg_stat_reset. '
    'Review before dropping — reset stats first with SELECT pg_stat_reset();';

-- migrate:down
DROP VIEW  IF EXISTS v_unused_indexes;
DROP FUNCTION  IF EXISTS refresh_analytics_views();
DROP MATERIALIZED VIEW IF EXISTS mv_provider_performance;
DROP MATERIALIZED VIEW IF EXISTS mv_daily_transaction_volume;
DROP INDEX IF EXISTS idx_onramp_quotes_expires_status;
DROP INDEX IF EXISTS idx_recurring_schedules_due_covering;
DROP INDEX IF EXISTS idx_batch_items_batch_status;
DROP INDEX IF EXISTS idx_fee_structures_active_type_time;
DROP INDEX IF EXISTS idx_exchange_rates_pair_created;
DROP INDEX IF EXISTS idx_conversion_audits_transaction_id_fk;
DROP INDEX IF EXISTS idx_webhook_events_transaction_id_fk;
DROP INDEX IF EXISTS idx_transactions_provider_status_created;
DROP INDEX IF EXISTS idx_transactions_type_status_date;
DROP INDEX IF EXISTS idx_transactions_wallet_currency_cursor;
DROP INDEX IF EXISTS idx_transactions_wallet_status_cursor;
DROP INDEX IF EXISTS idx_transactions_wallet_type_cursor;
DROP INDEX IF EXISTS idx_transactions_payment_ref_covering;
DROP INDEX IF EXISTS idx_transactions_blockchain_hash;
DROP INDEX IF EXISTS idx_transactions_stellar_polling;
DROP INDEX IF EXISTS idx_transactions_status_created_general;
DROP INDEX IF EXISTS idx_transactions_offramp_status_created;
DROP INDEX IF EXISTS idx_transactions_status_created_asc;
DROP INDEX IF EXISTS idx_wallets_address_balance;
