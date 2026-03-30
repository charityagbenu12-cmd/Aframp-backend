-- ============================================================================
-- NIGERIA → KENYA CORRIDOR — Issue #2.03
-- Extends the transactions table with Kenya-specific metadata and adds
-- the M-Pesa daily volume tracker for CBK limit enforcement.
-- ============================================================================

-- ---------------------------------------------------------------------------
-- 1. Ensure the transactions table has the columns we need.
--    (These are additive; safe to run on an existing table.)
-- ---------------------------------------------------------------------------

ALTER TABLE transactions
    ADD COLUMN IF NOT EXISTS corridor VARCHAR(10),          -- e.g. 'NG-KE'
    ADD COLUMN IF NOT EXISTS cbk_reference VARCHAR(100);    -- CBK reporting ref

CREATE INDEX IF NOT EXISTS idx_transactions_corridor
    ON transactions (corridor, created_at DESC)
    WHERE corridor IS NOT NULL;

-- ---------------------------------------------------------------------------
-- 2. M-Pesa daily volume tracker (per recipient phone, per day).
--    Used to enforce the KES 300,000 daily cap per recipient.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS mpesa_daily_volume (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    recipient_phone VARCHAR(20) NOT NULL,
    date            DATE NOT NULL DEFAULT CURRENT_DATE,
    total_kes       DECIMAL(20, 4) NOT NULL DEFAULT 0,
    tx_count        INTEGER NOT NULL DEFAULT 0,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT uq_mpesa_daily UNIQUE (recipient_phone, date)
);

CREATE INDEX IF NOT EXISTS idx_mpesa_daily_phone_date
    ON mpesa_daily_volume (recipient_phone, date DESC);

-- ---------------------------------------------------------------------------
-- 3. Kenya corridor fee seed data.
--    Inserts a fee structure row for the NG→KE corridor so the
--    FeeCalculationService can look it up at runtime.
-- ---------------------------------------------------------------------------

INSERT INTO fee_structures (
    transaction_type,
    payment_provider,
    payment_method,
    min_amount,
    max_amount,
    provider_fee_percent,
    provider_fee_flat,
    provider_fee_cap,
    platform_fee_percent,
    is_active,
    effective_from
)
SELECT
    'kenya_corridor',
    'mpesa_kenya',
    'mobile_money',
    0,
    NULL,
    1.5,    -- 1.5% platform corridor fee
    30,     -- KES 30 flat M-Pesa B2C fee
    NULL,
    0,
    TRUE,
    NOW()
WHERE NOT EXISTS (
    SELECT 1 FROM fee_structures
    WHERE transaction_type = 'kenya_corridor'
      AND payment_provider = 'mpesa_kenya'
);

-- ---------------------------------------------------------------------------
-- 4. Seed the NG→KE payment corridor in the compliance registry.
--    (Only inserts if not already present.)
-- ---------------------------------------------------------------------------

INSERT INTO payment_corridors (
    source_country, destination_country,
    source_currency, destination_currency,
    status
)
SELECT 'NG', 'KE', 'NGN', 'KES', 'active'
WHERE NOT EXISTS (
    SELECT 1 FROM payment_corridors
    WHERE source_country = 'NG'
      AND destination_country = 'KE'
      AND source_currency = 'NGN'
      AND destination_currency = 'KES'
);

-- ---------------------------------------------------------------------------
-- 5. Seed the NGN/KES exchange rate (placeholder — overwritten by live feed).
-- ---------------------------------------------------------------------------

INSERT INTO exchange_rates (currency_pair, rate, source)
SELECT 'NGN/KES', 0.5800, 'seed'
WHERE NOT EXISTS (
    SELECT 1 FROM exchange_rates WHERE currency_pair = 'NGN/KES'
);
