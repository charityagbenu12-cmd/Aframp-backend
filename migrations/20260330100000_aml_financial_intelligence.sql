-- Migration: AML Financial Intelligence Layer
-- Creates tables for sanctions screening, AML cases, and audit trail

-- AML compliance cases for flagged cross-border transactions
CREATE TABLE IF NOT EXISTS aml_cases (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    transaction_id      UUID NOT NULL,
    wallet_address      TEXT NOT NULL,
    risk_score          DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    flag_level          TEXT NOT NULL CHECK (flag_level IN ('LOW', 'MEDIUM', 'CRITICAL')),
    flags_json          JSONB NOT NULL DEFAULT '[]'::JSONB,
    status              TEXT NOT NULL DEFAULT 'PendingComplianceReview'
                            CHECK (status IN ('PendingComplianceReview', 'Cleared', 'PermanentlyBlocked')),
    reviewed_by         TEXT,
    review_notes        TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Corridor risk weight configuration (Basel AML Index / FATF Grey List)
CREATE TABLE IF NOT EXISTS aml_corridor_risk_weights (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    origin_country      CHAR(2) NOT NULL,
    destination_country CHAR(2) NOT NULL,
    weight              DOUBLE PRECISION NOT NULL CHECK (weight BETWEEN 0.0 AND 1.0),
    reason              TEXT NOT NULL,
    effective_from      DATE NOT NULL DEFAULT CURRENT_DATE,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (origin_country, destination_country)
);

-- Velocity tracking for smurfing detection (supplemented by Redis counters)
CREATE TABLE IF NOT EXISTS aml_velocity_events (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    wallet_address  TEXT NOT NULL,
    recipient_id    TEXT NOT NULL,
    transaction_id  UUID NOT NULL,
    amount          NUMERIC(36, 18) NOT NULL,
    corridor_id     TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_aml_cases_transaction_id ON aml_cases(transaction_id);
CREATE INDEX IF NOT EXISTS idx_aml_cases_status ON aml_cases(status) WHERE status = 'PendingComplianceReview';
CREATE INDEX IF NOT EXISTS idx_aml_cases_flag_level ON aml_cases(flag_level, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_aml_velocity_wallet_recipient ON aml_velocity_events(wallet_address, recipient_id, created_at DESC);

-- Trigger: update updated_at
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN NEW.updated_at = NOW(); RETURN NEW; END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER aml_cases_updated_at
    BEFORE UPDATE ON aml_cases
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Seed default corridor risk weights (FATF 2024)
INSERT INTO aml_corridor_risk_weights (origin_country, destination_country, weight, reason)
VALUES
    ('NG', 'KE', 0.40, 'Moderate risk corridor'),
    ('NG', 'GH', 0.35, 'Moderate risk corridor'),
    ('NG', 'ZA', 0.30, 'Lower risk corridor'),
    ('NG', 'MM', 0.90, 'FATF Grey List — Myanmar'),
    ('NG', 'PK', 0.80, 'FATF Grey List — Pakistan'),
    ('NG', 'SY', 0.95, 'FATF Black List — Syria'),
    ('NG', 'KP', 1.00, 'FATF Black List — North Korea')
ON CONFLICT (origin_country, destination_country) DO NOTHING;

COMMENT ON TABLE aml_cases IS 'AML compliance cases for flagged cross-border transactions';
COMMENT ON TABLE aml_corridor_risk_weights IS 'Per-corridor risk weights based on Basel AML Index / FATF status';
