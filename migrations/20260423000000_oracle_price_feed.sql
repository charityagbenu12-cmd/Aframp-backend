-- Oracle price feed time-series storage (Issue #1.02 — Sensory System)

CREATE TABLE IF NOT EXISTS oracle_price_history (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    pair         TEXT        NOT NULL,
    price        DOUBLE PRECISION NOT NULL CHECK (price > 0),
    sources_used INT         NOT NULL,
    fetched_at   TIMESTAMPTZ NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Fast range queries for the Market Operations Dashboard
CREATE INDEX IF NOT EXISTS idx_oracle_price_history_pair_time
    ON oracle_price_history (pair, fetched_at DESC);

-- Audit trail: every time a source is excluded
CREATE TABLE IF NOT EXISTS oracle_source_exclusions (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    source_name  TEXT        NOT NULL,
    pair         TEXT        NOT NULL,
    reason       TEXT        NOT NULL,  -- 'outlier_price' | 'consecutive_failures'
    excluded_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_oracle_exclusions_time
    ON oracle_source_exclusions (excluded_at DESC);
