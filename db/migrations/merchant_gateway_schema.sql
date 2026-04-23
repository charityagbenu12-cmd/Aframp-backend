-- ============================================================================
-- MERCHANT GATEWAY SCHEMA
-- Entry point for commercial adoption - Invoice & Payment Intent Management
-- ============================================================================

-- ============================================================================
-- 1. MERCHANTS TABLE
-- ============================================================================
CREATE TABLE merchants (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    business_name           VARCHAR(255)    NOT NULL,
    business_email          VARCHAR(255)    NOT NULL UNIQUE,
    business_phone          VARCHAR(50),
    stellar_address         VARCHAR(56)     NOT NULL,
    webhook_url             VARCHAR(500),
    webhook_secret          VARCHAR(255)    NOT NULL, -- HMAC signing secret
    is_active               BOOLEAN         NOT NULL DEFAULT true,
    kyb_status              VARCHAR(20)     NOT NULL DEFAULT 'pending'
        CHECK (kyb_status IN ('pending', 'approved', 'rejected', 'suspended')),
    monthly_volume_limit    DECIMAL(18,2),
    gas_fee_sponsor         BOOLEAN         NOT NULL DEFAULT false, -- Meta-transactions
    metadata                JSONB           NOT NULL DEFAULT '{}',
    created_at              TIMESTAMPTZ     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at              TIMESTAMPTZ     NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_merchants_email ON merchants(business_email);
CREATE INDEX idx_merchants_active ON merchants(is_active) WHERE is_active = true;
CREATE INDEX idx_merchants_stellar ON merchants(stellar_address);

-- ============================================================================
-- 2. MERCHANT API KEYS (extends existing api_keys table)
-- ============================================================================
-- Add merchant-specific columns to existing api_keys table
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS merchant_id UUID REFERENCES merchants(id);
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS key_scope VARCHAR(50) DEFAULT 'full'
    CHECK (key_scope IN ('full', 'read_only', 'write_only', 'refund_only'));

CREATE INDEX idx_api_keys_merchant ON api_keys(merchant_id) WHERE merchant_id IS NOT NULL;

-- ============================================================================
-- 3. PAYMENT INTENTS (Unified Checkout Object)
-- ============================================================================
CREATE TABLE merchant_payment_intents (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    merchant_id             UUID            NOT NULL REFERENCES merchants(id),
    merchant_reference      VARCHAR(255)    NOT NULL, -- Order ID from merchant
    amount_cngn             DECIMAL(18,8)   NOT NULL CHECK (amount_cngn > 0),
    currency                VARCHAR(10)     NOT NULL DEFAULT 'cNGN',
    
    -- Payment details
    customer_email          VARCHAR(255),
    customer_phone          VARCHAR(50),
    customer_address        VARCHAR(56),    -- Stellar address if known
    
    -- Blockchain details
    destination_address     VARCHAR(56)     NOT NULL, -- Merchant's Stellar address
    memo                    VARCHAR(28)     NOT NULL UNIQUE, -- Stellar memo for matching
    stellar_tx_hash         VARCHAR(64),
    actual_amount_received  DECIMAL(18,8),
    
    -- Status tracking
    status                  VARCHAR(20)     NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'paid', 'expired', 'cancelled', 'refunded')),
    
    -- Timing
    expires_at              TIMESTAMPTZ     NOT NULL,
    paid_at                 TIMESTAMPTZ,
    confirmed_at            TIMESTAMPTZ,    -- Blockchain confirmation
    
    -- Metadata
    metadata                JSONB           NOT NULL DEFAULT '{}', -- SKU, product details, etc.
    callback_url            VARCHAR(500),   -- Override merchant default webhook
    
    created_at              TIMESTAMPTZ     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at              TIMESTAMPTZ     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    
    -- Idempotency: one merchant_reference per merchant
    CONSTRAINT unique_merchant_order UNIQUE (merchant_id, merchant_reference)
);

CREATE INDEX idx_payment_intents_merchant ON merchant_payment_intents(merchant_id);
CREATE INDEX idx_payment_intents_status ON merchant_payment_intents(status, created_at DESC);
CREATE INDEX idx_payment_intents_memo ON merchant_payment_intents(memo);
CREATE INDEX idx_payment_intents_expires ON merchant_payment_intents(expires_at) 
    WHERE status = 'pending';
CREATE INDEX idx_payment_intents_stellar_hash ON merchant_payment_intents(stellar_tx_hash) 
    WHERE stellar_tx_hash IS NOT NULL;

-- ============================================================================
-- 4. WEBHOOK DELIVERY LOG (High-Speed Webhook Engine)
-- ============================================================================
CREATE TABLE merchant_webhook_deliveries (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    payment_intent_id       UUID            NOT NULL REFERENCES merchant_payment_intents(id),
    merchant_id             UUID            NOT NULL REFERENCES merchants(id),
    
    -- Delivery details
    webhook_url             VARCHAR(500)    NOT NULL,
    event_type              VARCHAR(50)     NOT NULL, -- payment.confirmed, payment.expired, etc.
    payload                 JSONB           NOT NULL,
    signature               VARCHAR(255)    NOT NULL, -- HMAC-SHA256 signature
    
    -- Status tracking
    status                  VARCHAR(20)     NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'delivered', 'failed', 'abandoned')),
    http_status_code        INTEGER,
    response_body           TEXT,
    error_message           TEXT,
    
    -- Retry logic
    retry_count             INTEGER         NOT NULL DEFAULT 0,
    next_retry_at           TIMESTAMPTZ,
    last_attempt_at         TIMESTAMPTZ,
    delivered_at            TIMESTAMPTZ,
    
    created_at              TIMESTAMPTZ     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at              TIMESTAMPTZ     NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_webhook_deliveries_payment ON merchant_webhook_deliveries(payment_intent_id);
CREATE INDEX idx_webhook_deliveries_merchant ON merchant_webhook_deliveries(merchant_id);
CREATE INDEX idx_webhook_deliveries_pending ON merchant_webhook_deliveries(status, next_retry_at) 
    WHERE status = 'pending';
CREATE INDEX idx_webhook_deliveries_created ON merchant_webhook_deliveries(created_at DESC);

-- ============================================================================
-- 5. REFUNDS TABLE
-- ============================================================================
CREATE TABLE merchant_refunds (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    payment_intent_id       UUID            NOT NULL REFERENCES merchant_payment_intents(id),
    merchant_id             UUID            NOT NULL REFERENCES merchants(id),
    
    -- Refund details
    amount_cngn             DECIMAL(18,8)   NOT NULL CHECK (amount_cngn > 0),
    reason                  TEXT,
    refund_reference        VARCHAR(255)    NOT NULL UNIQUE,
    
    -- Blockchain details
    stellar_tx_hash         VARCHAR(64),
    status                  VARCHAR(20)     NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'processing', 'completed', 'failed')),
    
    -- Timing
    initiated_by            VARCHAR(50)     NOT NULL, -- 'merchant', 'admin', 'system'
    completed_at            TIMESTAMPTZ,
    
    metadata                JSONB           NOT NULL DEFAULT '{}',
    created_at              TIMESTAMPTZ     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at              TIMESTAMPTZ     NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_refunds_payment ON merchant_refunds(payment_intent_id);
CREATE INDEX idx_refunds_merchant ON merchant_refunds(merchant_id);
CREATE INDEX idx_refunds_status ON merchant_refunds(status, created_at DESC);

-- ============================================================================
-- 6. MERCHANT ANALYTICS (for dashboard)
-- ============================================================================
CREATE TABLE merchant_analytics_daily (
    id                      BIGSERIAL PRIMARY KEY,
    merchant_id             UUID            NOT NULL REFERENCES merchants(id),
    date                    DATE            NOT NULL,
    
    -- Volume metrics
    total_payments          INTEGER         NOT NULL DEFAULT 0,
    successful_payments     INTEGER         NOT NULL DEFAULT 0,
    failed_payments         INTEGER         NOT NULL DEFAULT 0,
    expired_payments        INTEGER         NOT NULL DEFAULT 0,
    
    -- Amount metrics
    total_volume_cngn       DECIMAL(18,8)   NOT NULL DEFAULT 0,
    total_refunds_cngn      DECIMAL(18,8)   NOT NULL DEFAULT 0,
    net_volume_cngn         DECIMAL(18,8)   NOT NULL DEFAULT 0,
    
    -- Performance metrics
    avg_confirmation_time_secs INTEGER,
    webhook_success_rate    DECIMAL(5,2),
    
    created_at              TIMESTAMPTZ     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at              TIMESTAMPTZ     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    
    CONSTRAINT unique_merchant_date UNIQUE (merchant_id, date)
);

CREATE INDEX idx_analytics_merchant_date ON merchant_analytics_daily(merchant_id, date DESC);

-- ============================================================================
-- HELPER FUNCTIONS
-- ============================================================================

-- Generate unique memo for payment intent
CREATE OR REPLACE FUNCTION generate_payment_memo()
RETURNS VARCHAR(28)
LANGUAGE plpgsql
AS $$
DECLARE
    new_memo VARCHAR(28);
    memo_exists BOOLEAN;
BEGIN
    LOOP
        -- Format: MER-<8 random chars>
        new_memo := 'MER-' || upper(substring(md5(random()::text) from 1 for 8));
        
        -- Check if memo already exists
        SELECT EXISTS(
            SELECT 1 FROM merchant_payment_intents WHERE memo = new_memo
        ) INTO memo_exists;
        
        EXIT WHEN NOT memo_exists;
    END LOOP;
    
    RETURN new_memo;
END;
$$;

-- Update merchant analytics
CREATE OR REPLACE FUNCTION update_merchant_analytics()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'UPDATE' AND OLD.status != NEW.status THEN
        INSERT INTO merchant_analytics_daily (
            merchant_id, date, total_payments, successful_payments, 
            failed_payments, expired_payments, total_volume_cngn
        )
        VALUES (
            NEW.merchant_id,
            CURRENT_DATE,
            1,
            CASE WHEN NEW.status = 'paid' THEN 1 ELSE 0 END,
            CASE WHEN NEW.status = 'cancelled' THEN 1 ELSE 0 END,
            CASE WHEN NEW.status = 'expired' THEN 1 ELSE 0 END,
            CASE WHEN NEW.status = 'paid' THEN NEW.amount_cngn ELSE 0 END
        )
        ON CONFLICT (merchant_id, date) DO UPDATE SET
            total_payments = merchant_analytics_daily.total_payments + 1,
            successful_payments = merchant_analytics_daily.successful_payments + 
                CASE WHEN NEW.status = 'paid' THEN 1 ELSE 0 END,
            failed_payments = merchant_analytics_daily.failed_payments + 
                CASE WHEN NEW.status = 'cancelled' THEN 1 ELSE 0 END,
            expired_payments = merchant_analytics_daily.expired_payments + 
                CASE WHEN NEW.status = 'expired' THEN 1 ELSE 0 END,
            total_volume_cngn = merchant_analytics_daily.total_volume_cngn + 
                CASE WHEN NEW.status = 'paid' THEN NEW.amount_cngn ELSE 0 END,
            updated_at = CURRENT_TIMESTAMP;
    END IF;
    
    RETURN NEW;
END;
$$;

-- Trigger for analytics
CREATE TRIGGER trg_update_merchant_analytics
AFTER UPDATE ON merchant_payment_intents
FOR EACH ROW
EXECUTE FUNCTION update_merchant_analytics();

-- Auto-update updated_at timestamps
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_merchants_updated_at
BEFORE UPDATE ON merchants
FOR EACH ROW
EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER trg_payment_intents_updated_at
BEFORE UPDATE ON merchant_payment_intents
FOR EACH ROW
EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER trg_webhook_deliveries_updated_at
BEFORE UPDATE ON merchant_webhook_deliveries
FOR EACH ROW
EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER trg_refunds_updated_at
BEFORE UPDATE ON merchant_refunds
FOR EACH ROW
EXECUTE FUNCTION update_updated_at_column();
