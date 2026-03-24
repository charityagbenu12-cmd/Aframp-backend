-- migrate:up
-- Batch Transaction Processing (Issue #125)
--
-- Tables:
--   batches      — parent batch record
--   batch_items  — individual items within a batch

-- ─── Batch Status Lookup ──────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS batch_statuses (
    code        TEXT PRIMARY KEY,
    description TEXT NOT NULL
);

INSERT INTO batch_statuses (code, description) VALUES
    ('pending',            'Batch created, not yet started'),
    ('processing',         'Batch is actively being processed'),
    ('completed',          'All items reached a terminal state, all succeeded'),
    ('partially_completed','All items reached a terminal state, some failed'),
    ('failed',             'Processing failed before any items completed')
ON CONFLICT DO NOTHING;

-- ─── Batch Item Status Lookup ─────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS batch_item_statuses (
    code        TEXT PRIMARY KEY,
    description TEXT NOT NULL
);

INSERT INTO batch_item_statuses (code, description) VALUES
    ('pending',    'Waiting to be processed'),
    ('processing', 'Being processed'),
    ('completed',  'Completed successfully'),
    ('failed',     'Processing failed')
ON CONFLICT DO NOTHING;

-- ─── Batches ──────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS batches (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    batch_type          TEXT NOT NULL CHECK (batch_type IN ('cngn_transfer', 'fiat_payout', 'bill_payment')),
    status              TEXT NOT NULL REFERENCES batch_statuses(code) DEFAULT 'pending',
    source_wallet       TEXT,                  -- Stellar address for cngn_transfer batches
    total_count         INTEGER NOT NULL DEFAULT 0,
    success_count       INTEGER NOT NULL DEFAULT 0,
    failed_count        INTEGER NOT NULL DEFAULT 0,
    pending_count       INTEGER NOT NULL DEFAULT 0,
    initiated_by        TEXT,                  -- consumer_id or user reference
    error_message       TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at        TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_batches_status    ON batches (status);
CREATE INDEX IF NOT EXISTS idx_batches_type      ON batches (batch_type);
CREATE INDEX IF NOT EXISTS idx_batches_created   ON batches (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_batches_initiated ON batches (initiated_by);

CREATE TRIGGER trg_batches_updated_at
    BEFORE UPDATE ON batches
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ─── Batch Items ──────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS batch_items (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    batch_id            UUID NOT NULL REFERENCES batches(id) ON DELETE CASCADE,
    status              TEXT NOT NULL REFERENCES batch_item_statuses(code) DEFAULT 'pending',

    -- Destination (cNGN transfer: Stellar address; fiat payout: bank account)
    destination         TEXT NOT NULL,
    amount              NUMERIC(36, 7) NOT NULL CHECK (amount > 0),
    currency            TEXT NOT NULL DEFAULT 'cNGN',

    -- Optional memo / reference for tracing
    memo                TEXT,

    -- On-chain or provider settlement details
    stellar_tx_hash     TEXT,
    stellar_op_index    INTEGER,              -- Index of this item's op within a multi-op envelope
    provider_reference  TEXT,                -- Payment provider payout reference

    -- Error tracking
    failure_reason      TEXT,
    retry_count         INTEGER NOT NULL DEFAULT 0,

    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_batch_items_batch   ON batch_items (batch_id);
CREATE INDEX IF NOT EXISTS idx_batch_items_status  ON batch_items (status);
CREATE INDEX IF NOT EXISTS idx_batch_items_hash    ON batch_items (stellar_tx_hash) WHERE stellar_tx_hash IS NOT NULL;

CREATE TRIGGER trg_batch_items_updated_at
    BEFORE UPDATE ON batch_items
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ─── Batch Processing Configuration ──────────────────────────────────────────
-- Stores tunable limits per batch type. The application reads these at startup.

CREATE TABLE IF NOT EXISTS batch_config (
    batch_type              TEXT PRIMARY KEY,
    max_items_per_batch     INTEGER NOT NULL DEFAULT 100,
    max_ops_per_envelope    INTEGER NOT NULL DEFAULT 100, -- Stellar multi-op limit
    max_processing_minutes  INTEGER NOT NULL DEFAULT 30,  -- Alert threshold
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO batch_config (batch_type, max_items_per_batch, max_ops_per_envelope, max_processing_minutes) VALUES
    ('cngn_transfer', 100, 100, 30),
    ('fiat_payout',   500, 100,  60),
    ('bill_payment',  200, 100, 45)
ON CONFLICT DO NOTHING;
