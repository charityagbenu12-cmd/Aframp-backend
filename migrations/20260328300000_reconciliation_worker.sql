-- migrate:up
-- Reconciliation Worker: discrepancy_log table and supporting indexes.
-- Tracks three-way mismatches between bank deposits, mint_requests, and on-chain events.

CREATE TYPE discrepancy_type AS ENUM (
    'MISSING_MINT',        -- Fiat received, no cNGN issued
    'UNAUTHORIZED_MINT',   -- cNGN issued, no matching fiat deposit (HIGH ALERT)
    'AMOUNT_MISMATCH'      -- Fiat and mint exist but values differ
);

CREATE TYPE discrepancy_status AS ENUM (
    'OPEN',
    'INVESTIGATING',
    'RESOLVED'
);

CREATE TABLE discrepancy_log (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    transaction_id      UUID REFERENCES transactions(transaction_id) ON DELETE SET NULL,
    discrepancy_type    discrepancy_type NOT NULL,
    status              discrepancy_status NOT NULL DEFAULT 'OPEN',

    -- Three-way match evidence
    fiat_amount         NUMERIC(36, 18),
    mint_amount         NUMERIC(36, 18),
    stellar_tx_hash     TEXT,
    payment_reference   TEXT,

    -- Audit fields
    detected_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at         TIMESTAMPTZ,
    resolved_by         TEXT,
    notes               TEXT,

    -- Alert tracking
    alert_sent          BOOLEAN NOT NULL DEFAULT FALSE,
    alert_sent_at       TIMESTAMPTZ,

    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TRIGGER set_updated_at_discrepancy_log
    BEFORE UPDATE ON discrepancy_log
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Reconciliation health reports (end-of-day summaries)
CREATE TABLE reconciliation_reports (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    report_date         DATE NOT NULL UNIQUE,
    total_transactions  INT NOT NULL DEFAULT 0,
    matched_count       INT NOT NULL DEFAULT 0,
    discrepancy_count   INT NOT NULL DEFAULT 0,
    missing_mint_count  INT NOT NULL DEFAULT 0,
    unauthorized_mint_count INT NOT NULL DEFAULT 0,
    amount_mismatch_count   INT NOT NULL DEFAULT 0,
    has_open_discrepancies  BOOLEAN NOT NULL DEFAULT FALSE,
    period_closed       BOOLEAN NOT NULL DEFAULT FALSE,  -- admin UI lock flag
    generated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Indexes
CREATE INDEX idx_discrepancy_log_status ON discrepancy_log (status) WHERE status != 'RESOLVED';
CREATE INDEX idx_discrepancy_log_type   ON discrepancy_log (discrepancy_type);
CREATE INDEX idx_discrepancy_log_tx     ON discrepancy_log (transaction_id);
CREATE INDEX idx_discrepancy_log_detected ON discrepancy_log (detected_at);

-- migrate:down
DROP INDEX IF EXISTS idx_discrepancy_log_detected;
DROP INDEX IF EXISTS idx_discrepancy_log_tx;
DROP INDEX IF EXISTS idx_discrepancy_log_type;
DROP INDEX IF EXISTS idx_discrepancy_log_status;
DROP TABLE IF EXISTS reconciliation_reports;
DROP TABLE IF EXISTS discrepancy_log;
DROP TYPE IF EXISTS discrepancy_status;
DROP TYPE IF EXISTS discrepancy_type;
