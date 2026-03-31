-- Reconciliation Reports Table
CREATE TABLE reconciliation_reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    internal_total NUMERIC(20, 7) NOT NULL,
    on_chain_total NUMERIC(20, 7) NOT NULL,
    bank_total NUMERIC(20, 7) NOT NULL,
    mints_in_progress NUMERIC(20, 7) NOT NULL DEFAULT 0,
    redemptions_in_progress NUMERIC(20, 7) NOT NULL DEFAULT 0,
    delta_value NUMERIC(20, 7) NOT NULL,
    status TEXT NOT NULL, -- 'EQUILIBRIUM', 'RESERVE_DEFICIT', 'SURPLUS_UNKNOWN_ORIGIN', 'ERROR'
    metadata JSONB NOT NULL DEFAULT '{}'
);

CREATE INDEX idx_reconciliation_timestamp ON reconciliation_reports(timestamp);
CREATE INDEX idx_reconciliation_status ON reconciliation_reports(status);
