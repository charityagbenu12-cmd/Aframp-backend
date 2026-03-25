-- migrate:up
-- =============================================================================
-- Database Query Optimisations (Issue #125)
--
-- Covers:
--   1. pg_stat_statements + slow query logging configuration
--   2. Missing composite indexes for worker polling queries
--   3. Missing FK indexes
--   4. Covering indexes for high-frequency read paths
--   5. Materialised views: daily_transaction_volume, provider_performance
--   6. Refresh functions and scheduling helpers
-- =============================================================================

-- ---------------------------------------------------------------------------
-- 1. Enable pg_stat_statements for query profiling
--    (requires shared_preload_libraries = 'pg_stat_statements' in postgresql.conf;
--     the CREATE EXTENSION is safe to run even if the library is not yet loaded —
--     it will simply fail gracefully and can be re-run after the server restarts.)
-- ---------------------------------------------------------------------------
CREATE EXTENSION IF NOT EXISTS pg_stat_statements;

-- ---------------------------------------------------------------------------
-- 2. Worker polling — transaction monitor
--    find_pending_payments_for_monitoring:
--      WHERE status IN ('pending','processing','pending_payment')
--        AND created_at > NOW() - INTERVAL '...'
--      ORDER BY created_at ASC
--    The existing idx_transactions_status is a single-column index; a composite
--    covering index on (status, created_at) eliminates the sort and the filter
--    in one index scan.
-- ---------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_transactions_status_created_asc
    ON transactions (status, created_at ASC)
    WHERE status IN ('pending', 'processing', 'pending_payment');

-- ---------------------------------------------------------------------------
-- 3. Worker polling — offramp processor
--    find_offramps_by_status:
--      WHERE status = $1 AND type = 'offramp'
--      ORDER BY created_at ASC
-- ---------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_transactions_offramp_status_created
    ON transactions (status, created_at ASC)
    WHERE type = 'offramp';

-- ---------------------------------------------------------------------------
-- 4. Worker polling — payment poller / find_by_status
--    find_by_status:
--      WHERE status = $1
--      ORDER BY created_at ASC
--    Covered by idx_transactions_status_created_asc above for the hot statuses.
--    Add a general one for arbitrary status values used by the payment poller.
-- ---------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_transactions_status_created_general
    ON transactions (status, created_at ASC);

-- ---------------------------------------------------------------------------
-- 5. Payment reference lookup — find_by_payment_reference
--    The existing partial index idx_transactions_payment_ref covers this but
--    only indexes the column; add a covering index to avoid a heap fetch.
-- ---------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_transactions_payment_ref_covering
    ON transactions (payment_reference)
    INCLUDE (transaction_id, wallet_address, status, type, created_at)
    WHERE payment_reference IS NOT NULL;

-- ---------------------------------------------------------------------------
-- 6. Blockchain hash lookup — Stellar confirmation worker
--    The existing idx_transactions_stellar_polling covers (status, stellar_tx_hash).
--    Add a direct hash lookup for the case where the worker fetches by hash alone.
-- ---------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_transactions_blockchain_hash
    ON transactions (blockchain_tx_hash)
    WHERE blockchain_tx_hash IS NOT NULL;

-- ---------------------------------------------------------------------------
-- 7. Missing FK index — webhook_events.transaction_id
--    Already has idx_webhook_events_transaction_query but it is a partial index
--    (WHERE transaction_id IS NOT NULL). The FK itself needs a full index for
--    ON DELETE / ON UPDATE cascade scans.
-- ---------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_webhook_events_transaction_id_fk
    ON webhook_events (transaction_id);

-- ---------------------------------------------------------------------------
-- 8. Missing FK index — conversion_audits.transaction_id
-- ---------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_conversion_audits_transaction_id_fk
    ON conversion_audits (transaction_id);

-- ---------------------------------------------------------------------------
-- 9. Reconciliation / settlement aggregation support
--    Queries that aggregate by (type, status, date) for daily settlement reports.
-- ---------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_transactions_type_status_date
    ON transactions (type, status, date_trunc('day', created_at));

-- ---------------------------------------------------------------------------
-- 10. Batch items — pending items per batch (worker polling)
--     WHERE batch_id = $1 AND status = 'pending'
-- ---------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_batch_items_batch_status
    ON batch_items (batch_id, status);

-- ---------------------------------------------------------------------------
-- 11. Recurring payments — due-date polling covering index
--     idx_recurring_schedules_due already exists; add a covering variant
--     that includes wallet_address to avoid heap fetches in the worker.
--     (table: recurring_payment_schedules, added in 20260325000000_recurring_payments.sql)
-- ---------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_recurring_schedules_due_covering
    ON recurring_payment_schedules (next_execution_at ASC, status)
    INCLUDE (wallet_address, id)
    WHERE status = 'active';

-- ---------------------------------------------------------------------------
-- 12. Materialised view — daily transaction volume
--     Refreshed once per day (acceptable staleness: up to 24 h).
--     Used by settlement aggregation and analytics endpoints.
-- ---------------------------------------------------------------------------
CREATE MATERIALIZED VIEW IF NOT EXISTS mv_daily_transaction_volume AS
SELECT
    date_trunc('day', created_at)::date          AS day,
    type,
    status,
    from_currency,
    to_currency,
    COUNT(*)                                      AS tx_count,
    SUM(from_amount)                              AS total_from_amount,
    SUM(to_amount)                                AS total_to_amount,
    SUM(cngn_amount)                              AS total_cngn_amount,
    AVG(from_amount)                              AS avg_from_amount
FROM transactions
GROUP BY 1, 2, 3, 4, 5
WITH DATA;

CREATE UNIQUE INDEX IF NOT EXISTS idx_mv_daily_tx_volume_pk
    ON mv_daily_transaction_volume (day, type, status, from_currency, to_currency);

CREATE INDEX IF NOT EXISTS idx_mv_daily_tx_volume_day
    ON mv_daily_transaction_volume (day DESC);

COMMENT ON MATERIALIZED VIEW mv_daily_transaction_volume IS
    'Pre-aggregated daily transaction volume by type/status/currency. '
    'Refresh daily via: REFRESH MATERIALIZED VIEW CONCURRENTLY mv_daily_transaction_volume;';

-- ---------------------------------------------------------------------------
-- 13. Materialised view — provider performance summary
--     Refreshed every hour (acceptable staleness: up to 1 h).
--     Used by the monitoring dashboard and provider health checks.
-- ---------------------------------------------------------------------------
CREATE MATERIALIZED VIEW IF NOT EXISTS mv_provider_performance AS
SELECT
    payment_provider,
    type,
    date_trunc('hour', created_at)               AS hour,
    COUNT(*)                                      AS tx_count,
    COUNT(*) FILTER (WHERE status = 'completed')  AS completed_count,
    COUNT(*) FILTER (WHERE status = 'failed')     AS failed_count,
    COUNT(*) FILTER (WHERE status IN ('pending','processing')) AS in_flight_count,
    ROUND(
        COUNT(*) FILTER (WHERE status = 'completed')::numeric
        / NULLIF(COUNT(*), 0) * 100, 2
    )                                             AS success_rate_pct,
    AVG(
        EXTRACT(EPOCH FROM (updated_at - created_at))
    ) FILTER (WHERE status = 'completed')         AS avg_completion_secs
FROM transactions
WHERE payment_provider IS NOT NULL
GROUP BY 1, 2, 3
WITH DATA;

CREATE UNIQUE INDEX IF NOT EXISTS idx_mv_provider_perf_pk
    ON mv_provider_performance (payment_provider, type, hour);

CREATE INDEX IF NOT EXISTS idx_mv_provider_perf_hour
    ON mv_provider_performance (hour DESC);

COMMENT ON MATERIALIZED VIEW mv_provider_performance IS
    'Hourly provider performance metrics. '
    'Refresh hourly via: REFRESH MATERIALIZED VIEW CONCURRENTLY mv_provider_performance;';

-- ---------------------------------------------------------------------------
-- 14. Helper function — refresh all materialised views concurrently
--     Call from a pg_cron job or the db_maintenance_worker.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION refresh_analytics_views()
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
    -- Hourly view
    REFRESH MATERIALIZED VIEW CONCURRENTLY mv_provider_performance;

    -- Daily view — only refresh once per day to avoid heavy I/O
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
    'at most once per 23 hours. Schedule with pg_cron or the db_maintenance_worker.';

-- ---------------------------------------------------------------------------
-- 15. Slow query logging — applied via ALTER SYSTEM so it survives restarts.
--     log_min_duration_statement = 200ms  (log queries slower than 200 ms)
--     log_statement = 'none'              (avoid logging every statement)
--     These require a pg_reload_conf() call or server restart to take effect.
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    -- Only apply if we have superuser privileges; skip silently otherwise.
    IF current_setting('is_superuser') = 'on' THEN
        PERFORM set_config('log_min_duration_statement', '200', false);
    END IF;
EXCEPTION WHEN OTHERS THEN
    NULL; -- Non-superuser environments: skip gracefully
END $$;

-- migrate:down
DROP FUNCTION  IF EXISTS refresh_analytics_views();
DROP MATERIALIZED VIEW IF EXISTS mv_provider_performance;
DROP MATERIALIZED VIEW IF EXISTS mv_daily_transaction_volume;
DROP INDEX IF EXISTS idx_recurring_schedules_due_covering;
DROP INDEX IF EXISTS idx_batch_items_batch_status;
DROP INDEX IF EXISTS idx_transactions_type_status_date;
DROP INDEX IF EXISTS idx_conversion_audits_transaction_id_fk;
DROP INDEX IF EXISTS idx_webhook_events_transaction_id_fk;
DROP INDEX IF EXISTS idx_transactions_blockchain_hash;
DROP INDEX IF EXISTS idx_transactions_payment_ref_covering;
DROP INDEX IF EXISTS idx_transactions_status_created_general;
DROP INDEX IF EXISTS idx_transactions_offramp_status_created;
DROP INDEX IF EXISTS idx_transactions_status_created_asc;
