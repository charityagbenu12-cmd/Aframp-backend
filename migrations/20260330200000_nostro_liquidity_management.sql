-- Migration: Nostro Account & Liquidity Management
-- Shadow ledger, balance polling, low-balance alerts, EOD reconciliation

-- Nostro accounts (pre-funded foreign bank accounts)
CREATE TABLE IF NOT EXISTS nostro_accounts (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    corridor_id             TEXT NOT NULL UNIQUE,   -- e.g. "NG-KE"
    currency                CHAR(3) NOT NULL,        -- ISO 4217
    bank_name               TEXT NOT NULL,
    account_reference       TEXT NOT NULL,           -- Account number or Virtual IBAN
    safety_buffer_fraction  DOUBLE PRECISION NOT NULL DEFAULT 0.20,
    corridor_status         TEXT NOT NULL DEFAULT 'active'
                                CHECK (corridor_status IN ('active', 'disabled_insufficient_funds', 'disabled_manual')),
    is_active               BOOLEAN NOT NULL DEFAULT TRUE,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Shadow ledger balance snapshots (polled every 15 minutes)
CREATE TABLE IF NOT EXISTS nostro_balances (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id      UUID NOT NULL REFERENCES nostro_accounts(id) ON DELETE CASCADE,
    cleared_balance NUMERIC(36, 18) NOT NULL,
    pending_balance NUMERIC(36, 18) NOT NULL DEFAULT 0,
    source          TEXT NOT NULL DEFAULT 'bank_api' CHECK (source IN ('bank_api', 'manual')),
    polled_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Fiat outflow records (for EOD reconciliation)
CREATE TABLE IF NOT EXISTS nostro_fiat_outflows (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id      UUID NOT NULL REFERENCES nostro_accounts(id) ON DELETE CASCADE,
    transaction_id  UUID NOT NULL,
    amount          NUMERIC(36, 18) NOT NULL,
    currency        CHAR(3) NOT NULL,
    reference       TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Liquidity alerts sent to Treasury
CREATE TABLE IF NOT EXISTS nostro_liquidity_alerts (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id              UUID NOT NULL REFERENCES nostro_accounts(id),
    corridor_id             TEXT NOT NULL,
    currency                CHAR(3) NOT NULL,
    current_balance         NUMERIC(36, 18) NOT NULL,
    safety_buffer_amount    NUMERIC(36, 18) NOT NULL,
    shortfall               NUMERIC(36, 18) NOT NULL,
    alerted_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- End-of-Day reconciliation results
CREATE TABLE IF NOT EXISTS nostro_eod_reconciliation (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id      UUID NOT NULL REFERENCES nostro_accounts(id),
    corridor_id     TEXT NOT NULL,
    date            DATE NOT NULL,
    onchain_burns   NUMERIC(36, 18) NOT NULL DEFAULT 0,
    fiat_outflows   NUMERIC(36, 18) NOT NULL DEFAULT 0,
    discrepancy     NUMERIC(36, 18) NOT NULL DEFAULT 0,
    status          TEXT NOT NULL DEFAULT 'matched' CHECK (status IN ('matched', 'discrepant')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (account_id, date)
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_nostro_balances_account_polled
    ON nostro_balances(account_id, polled_at DESC);
CREATE INDEX IF NOT EXISTS idx_nostro_fiat_outflows_account_date
    ON nostro_fiat_outflows(account_id, created_at);
CREATE INDEX IF NOT EXISTS idx_nostro_eod_date
    ON nostro_eod_reconciliation(date, status);

-- Trigger
CREATE TRIGGER nostro_accounts_updated_at
    BEFORE UPDATE ON nostro_accounts
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Seed active corridors
INSERT INTO nostro_accounts (corridor_id, currency, bank_name, account_reference, safety_buffer_fraction)
VALUES
    ('NG-KE', 'KES', 'KCB Kenya',    'VIRTUAL-IBAN-NG-KE-001', 0.20),
    ('NG-GH', 'GHS', 'Zenith Ghana', 'VIRTUAL-IBAN-NG-GH-001', 0.20),
    ('NG-ZA', 'ZAR', 'FNB South Africa', 'VIRTUAL-IBAN-NG-ZA-001', 0.20)
ON CONFLICT (corridor_id) DO NOTHING;

COMMENT ON TABLE nostro_accounts IS 'Pre-funded foreign bank accounts (Nostro) per payment corridor';
COMMENT ON TABLE nostro_balances IS 'Shadow ledger balance snapshots polled every 15 minutes';
COMMENT ON TABLE nostro_eod_reconciliation IS 'Daily reconciliation of on-chain burns vs fiat outflows';
