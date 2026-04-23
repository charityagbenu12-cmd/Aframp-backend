-- ============================================================================
-- POS QR Payment System — Physical Retail Integration
-- ============================================================================
-- Implements SEP-7 compliant QR code payment protocol for brick-and-mortar
-- merchants to accept cNGN payments via Stellar-enabled wallets.
--
-- Features:
-- - Dynamic QR generation with payment intent tracking
-- - Real-time payment confirmation monitoring
-- - Legacy POS system integration
-- - Offline-to-online validation
-- - Overpayment/underpayment detection
-- ============================================================================

-- Payment status enum
CREATE TYPE pos_payment_status AS ENUM (
    'pending',      -- QR generated, awaiting scan
    'submitted',    -- Transaction submitted to Stellar
    'confirmed',    -- Payment confirmed on ledger
    'discrepancy',  -- Amount mismatch detected
    'failed',       -- Payment failed or expired
    'refunded'      -- Payment refunded
);

-- Merchant configuration table
CREATE TABLE pos_merchants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    business_name VARCHAR(255) NOT NULL,
    stellar_address VARCHAR(56) NOT NULL,
    webhook_url TEXT,
    static_qr_enabled BOOLEAN NOT NULL DEFAULT false,
    auto_refund_discrepancy BOOLEAN NOT NULL DEFAULT false,
    payment_timeout_secs INTEGER NOT NULL DEFAULT 900 CHECK (payment_timeout_secs >= 60),
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE pos_merchants IS 'POS merchant configuration for QR payment acceptance';
COMMENT ON COLUMN pos_merchants.stellar_address IS 'Merchant Stellar address for receiving cNGN payments';
COMMENT ON COLUMN pos_merchants.webhook_url IS 'Optional webhook URL for payment notifications';
COMMENT ON COLUMN pos_merchants.static_qr_enabled IS 'Enable static QR code for variable amount checkout';
COMMENT ON COLUMN pos_merchants.auto_refund_discrepancy IS 'Automatically refund payments with amount discrepancies';
COMMENT ON COLUMN pos_merchants.payment_timeout_secs IS 'Payment expiry timeout in seconds (minimum 60)';

-- Payment intents table
CREATE TABLE pos_payment_intents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    merchant_id UUID NOT NULL REFERENCES pos_merchants(id) ON DELETE CASCADE,
    order_id VARCHAR(100) NOT NULL,
    amount_cngn DECIMAL(20,7) NOT NULL CHECK (amount_cngn > 0),
    destination_address VARCHAR(56) NOT NULL,
    memo VARCHAR(100) NOT NULL UNIQUE,
    qr_code_data TEXT NOT NULL,
    status pos_payment_status NOT NULL DEFAULT 'pending',
    stellar_tx_hash VARCHAR(64),
    actual_amount_received DECIMAL(20,7),
    customer_address VARCHAR(56),
    expires_at TIMESTAMPTZ NOT NULL,
    confirmed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE pos_payment_intents IS 'POS payment intents with QR code data';
COMMENT ON COLUMN pos_payment_intents.memo IS 'Unique memo for Stellar transaction matching';
COMMENT ON COLUMN pos_payment_intents.qr_code_data IS 'SEP-7 compliant QR code SVG data';
COMMENT ON COLUMN pos_payment_intents.actual_amount_received IS 'Actual amount received (for discrepancy detection)';

-- Static QR configurations table
CREATE TABLE pos_static_qr_configs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    merchant_id UUID NOT NULL REFERENCES pos_merchants(id) ON DELETE CASCADE,
    qr_code_data TEXT NOT NULL,
    variable_amount_url TEXT NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (merchant_id)
);

COMMENT ON TABLE pos_static_qr_configs IS 'Static QR code configurations for small vendors';
COMMENT ON COLUMN pos_static_qr_configs.variable_amount_url IS 'Checkout page URL for variable amount entry';

-- Payment discrepancies table (for audit trail)
CREATE TABLE pos_payment_discrepancies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    payment_id UUID NOT NULL REFERENCES pos_payment_intents(id) ON DELETE CASCADE,
    expected_amount DECIMAL(20,7) NOT NULL,
    received_amount DECIMAL(20,7) NOT NULL,
    difference DECIMAL(20,7) NOT NULL,
    discrepancy_type VARCHAR(20) NOT NULL CHECK (discrepancy_type IN ('overpayment', 'underpayment')),
    resolution_status VARCHAR(20) NOT NULL DEFAULT 'pending' CHECK (resolution_status IN ('pending', 'refunded', 'accepted', 'disputed')),
    resolved_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE pos_payment_discrepancies IS 'Audit trail for payment amount discrepancies';

-- Indexes for performance
CREATE INDEX idx_pos_payment_intents_merchant ON pos_payment_intents(merchant_id, created_at DESC);
CREATE INDEX idx_pos_payment_intents_status ON pos_payment_intents(status, created_at DESC);
CREATE INDEX idx_pos_payment_intents_order_id ON pos_payment_intents(order_id);
CREATE INDEX idx_pos_payment_intents_memo ON pos_payment_intents(memo);
CREATE INDEX idx_pos_payment_intents_expires_at ON pos_payment_intents(expires_at) WHERE status IN ('pending', 'submitted');
CREATE INDEX idx_pos_payment_discrepancies_payment ON pos_payment_discrepancies(payment_id);
CREATE INDEX idx_pos_merchants_active ON pos_merchants(is_active) WHERE is_active = true;

-- Trigger for updated_at
CREATE TRIGGER set_updated_at_pos_merchants
    BEFORE UPDATE ON pos_merchants
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER set_updated_at_pos_payment_intents
    BEFORE UPDATE ON pos_payment_intents
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Function to automatically detect and record discrepancies
CREATE OR REPLACE FUNCTION detect_payment_discrepancy()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.status = 'confirmed' AND NEW.actual_amount_received IS NOT NULL THEN
        IF ABS(NEW.actual_amount_received - NEW.amount_cngn) > 0.01 THEN
            -- Discrepancy detected (tolerance: 0.01 cNGN)
            INSERT INTO pos_payment_discrepancies (
                payment_id,
                expected_amount,
                received_amount,
                difference,
                discrepancy_type
            ) VALUES (
                NEW.id,
                NEW.amount_cngn,
                NEW.actual_amount_received,
                NEW.actual_amount_received - NEW.amount_cngn,
                CASE
                    WHEN NEW.actual_amount_received > NEW.amount_cngn THEN 'overpayment'
                    ELSE 'underpayment'
                END
            );
            
            -- Update status to discrepancy
            NEW.status = 'discrepancy';
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_detect_payment_discrepancy
    BEFORE UPDATE ON pos_payment_intents
    FOR EACH ROW
    WHEN (NEW.status = 'confirmed' AND NEW.actual_amount_received IS NOT NULL)
    EXECUTE FUNCTION detect_payment_discrepancy();

-- Seed a test merchant for development
INSERT INTO pos_merchants (
    business_name,
    stellar_address,
    static_qr_enabled,
    payment_timeout_secs,
    is_active
) VALUES (
    'Test Retail Store',
    'GXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX',
    true,
    900,
    true
) ON CONFLICT DO NOTHING;

-- Performance monitoring view
CREATE OR REPLACE VIEW pos_payment_metrics AS
SELECT
    DATE_TRUNC('hour', created_at) AS hour,
    merchant_id,
    status,
    COUNT(*) AS payment_count,
    SUM(amount_cngn) AS total_volume,
    AVG(EXTRACT(EPOCH FROM (confirmed_at - created_at))) AS avg_confirmation_time_secs,
    PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY EXTRACT(EPOCH FROM (confirmed_at - created_at))) AS p95_confirmation_time_secs
FROM pos_payment_intents
WHERE created_at >= CURRENT_TIMESTAMP - INTERVAL '7 days'
GROUP BY DATE_TRUNC('hour', created_at), merchant_id, status;

COMMENT ON VIEW pos_payment_metrics IS 'Hourly POS payment performance metrics';
