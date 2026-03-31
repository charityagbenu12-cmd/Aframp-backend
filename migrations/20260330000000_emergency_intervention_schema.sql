-- Emergency Intervention Framework Schema
-- Stores every treasury market intervention with a full audit trail.

CREATE TYPE intervention_operation_type AS ENUM ('market_buy', 'market_sell');
CREATE TYPE intervention_status AS ENUM ('pending', 'executing', 'confirmed', 'failed', 'resolved');

CREATE TABLE emergency_interventions (
    id                        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    triggered_by              TEXT NOT NULL,
    operation_type            intervention_operation_type NOT NULL,
    amount_cngn               NUMERIC(28, 7) NOT NULL,
    source_account            TEXT NOT NULL,
    stellar_tx_hash           TEXT,
    status                    intervention_status NOT NULL DEFAULT 'pending',
    failure_reason            TEXT,
    -- Reserve capital consumed to restore the peg (populated post-confirmation).
    cost_of_stability_cngn    NUMERIC(28, 7),
    peg_deviation_at_trigger  NUMERIC(10, 6) NOT NULL,
    -- SHA-256 of the serialised Crisis Report — tamper-evident.
    crisis_report_hash        CHAR(64),
    triggered_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    confirmed_at              TIMESTAMPTZ,
    resolved_at               TIMESTAMPTZ
);

-- Fast lookup for the peg-monitor auto-revert query.
CREATE INDEX idx_emergency_interventions_status
    ON emergency_interventions (status, triggered_at DESC);

COMMENT ON TABLE emergency_interventions IS
    'Tamper-evident log of every treasury emergency market intervention.';
COMMENT ON COLUMN emergency_interventions.cost_of_stability_cngn IS
    'Total reserve capital consumed to restore the 1:1 cNGN peg.';
COMMENT ON COLUMN emergency_interventions.crisis_report_hash IS
    'SHA-256 of the serialised CrisisReport JSON — locked in the audit chain.';
