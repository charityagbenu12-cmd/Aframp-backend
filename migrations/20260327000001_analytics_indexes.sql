-- Analytics read-optimised indexes (Issue #113)
-- These indexes support the aggregation queries in AnalyticsRepository without
-- touching the primary write path.

-- Transaction volume queries group by (created_at, from_currency, type, status)
CREATE INDEX IF NOT EXISTS idx_transactions_analytics
    ON transactions (created_at, from_currency, type, status)
    WHERE created_at IS NOT NULL;

-- Provider performance queries filter on payment_provider
CREATE INDEX IF NOT EXISTS idx_transactions_provider_analytics
    ON transactions (payment_provider, created_at, status)
    WHERE payment_provider IS NOT NULL;

-- cNGN conversion queries filter on type + status
CREATE INDEX IF NOT EXISTS idx_transactions_cngn_analytics
    ON transactions (type, status, created_at)
    WHERE type IN ('onramp', 'offramp');
