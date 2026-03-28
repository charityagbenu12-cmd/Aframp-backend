-- Exchange rate history table for full audit trail.
-- Unique constraint on (from_currency, to_currency, window_ts) enforces idempotency.

CREATE TABLE IF NOT EXISTS exchange_rate_history (
    id            UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    from_currency TEXT            NOT NULL,
    to_currency   TEXT            NOT NULL,
    rate          NUMERIC(36, 18) NOT NULL CHECK (rate > 0),
    source        TEXT            NOT NULL,
    window_ts     TIMESTAMPTZ     NOT NULL,
    created_at    TIMESTAMPTZ     NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_exchange_rate_history_window
    ON exchange_rate_history (from_currency, to_currency, window_ts);

CREATE INDEX IF NOT EXISTS idx_exchange_rate_history_pair_time
    ON exchange_rate_history (from_currency, to_currency, created_at DESC);
