-- Migration: Create settlement schema (20261001)
-- settlement_batches: Tracks provider settlements for completed transactions
-- reconciliation_reports: Provider-reported vs internal totals

-- Settlement batches table
CREATE TABLE IF NOT EXISTS settlement_batches (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cycle_started_at TIMESTAMPTZ NOT NULL,
    provider TEXT NOT NULL CHECK (provider IN ('Flutterwave', 'Paystack', 'M-Pesa')),
    settlement_currency TEXT NOT NULL CHECK (settlement_currency IN ('NGN', 'USD', 'KES', 'GHS')),
    gross_amount NUMERIC(36,18) NOT NULL,
    platform_fee NUMERIC(36,18) NOT NULL,
    provider_charge NUMERIC(36,18) DEFAULT 0,
    net_amount NUMERIC(36,18) NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (
        status IN ('pending', 'processing', 'settled', 'failed', 'reconciled', 'discrepant')
    ),
    provider_settlement_ref TEXT,
    metadata JSONB DEFAULT '{}'::JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Reconciliation reports table
CREATE TABLE IF NOT EXISTS reconciliation_reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    batch_id UUID NOT NULL REFERENCES settlement_batches(id) ON DELETE CASCADE,
    expected_amount NUMERIC(36,18) NOT NULL,
    provider_reported_amount NUMERIC(36,18),
    discrepancy_amount NUMERIC(36,18),
    discrepancy_reason TEXT,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (
        status IN ('matched', 'discrepant', 'pending_manual')
    ),
    metadata JSONB DEFAULT '{}'::JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_settlement_batches_status_created 
ON settlement_batches(status, cycle_started_at) 
WHERE status IN ('pending', 'processing');

CREATE INDEX IF NOT EXISTS idx_settlement_batches_provider 
ON settlement_batches(provider, settlement_currency);

CREATE INDEX IF NOT EXISTS idx_reconciliation_batch_id 
ON reconciliation_reports(batch_id);

CREATE INDEX IF NOT EXISTS idx_transactions_not_settled 
ON transactions(status, type, updated_at) 
WHERE status = 'completed' 
  AND type IN ('onramp', 'offramp', 'bill_payment', 'exchange');

-- Function to update updated_at
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Triggers
CREATE TRIGGER update_settlement_batches_updated_at
    BEFORE UPDATE ON settlement_batches
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_reconciliation_reports_updated_at
    BEFORE UPDATE ON reconciliation_reports
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Comments for documentation
COMMENT ON TABLE settlement_batches IS 
'Stores settlement batches grouped by provider/currency for completed transactions';

COMMENT ON COLUMN settlement_batches.gross_amount IS 
'Sum of completed transaction from_amounts before any deductions';

COMMENT ON COLUMN settlement_batches.platform_fee IS 
'Sum of platform fees deducted from gross_amount';

COMMENT ON COLUMN settlement_batches.provider_charge IS 
'Estimated/detected provider charges deducted from gross_amount';

COMMENT ON COLUMN settlement_batches.net_amount IS 
'gross_amount - platform_fee - provider_charge (amount sent to provider)';

COMMENT ON TABLE reconciliation_reports IS 
'Reconciliation of internal batch totals vs provider-reported settlement amounts';

-- Rollback: (for manual reference)
-- DROP TABLE IF EXISTS reconciliation_reports CASCADE;
-- DROP TABLE IF EXISTS settlement_batches CASCADE;
-- DROP INDEX IF EXISTS idx_transactions_not_settled;

