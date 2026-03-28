-- migrate:up
-- Add onramp processor state machine statuses and refund tracking columns.
-- These statuses drive the full onramp lifecycle:
--   pending → payment_received → processing → completed
--                                           ↘ failed → refund_initiated → refunded
--                                                                        ↘ refund_failed

-- 1. Extend transaction_statuses with onramp-specific states
INSERT INTO transaction_statuses (code, description) VALUES
    ('payment_received',  'Fiat payment confirmed by provider, awaiting Stellar transfer'),
    ('refund_initiated',  'Stellar transfer failed; fiat refund has been requested'),
    ('refunded',          'Fiat refund successfully processed by provider'),
    ('refund_failed',     'Fiat refund failed after all retries; requires manual review')
ON CONFLICT (code) DO NOTHING;

-- 2. Index to efficiently find onramp transactions awaiting Stellar confirmation
CREATE INDEX IF NOT EXISTS idx_transactions_onramp_processing
    ON transactions (status, type, updated_at)
    WHERE type = 'onramp' AND status = 'processing';

-- 3. Index for the polling fallback (pending onramps with no webhook)
CREATE INDEX IF NOT EXISTS idx_transactions_onramp_pending
    ON transactions (status, type, created_at)
    WHERE type = 'onramp' AND status = 'pending';

-- 4. Index for timeout expiry scan
CREATE INDEX IF NOT EXISTS idx_transactions_onramp_timeout
    ON transactions (type, status, created_at)
    WHERE type = 'onramp' AND status IN ('pending', 'payment_received');

-- 5. Index for refund tracking
CREATE INDEX IF NOT EXISTS idx_transactions_refund_states
    ON transactions (status, type, updated_at)
    WHERE status IN ('refund_initiated', 'refund_failed');

COMMENT ON INDEX idx_transactions_onramp_processing IS
    'Supports the onramp processor Stellar confirmation polling loop.';
COMMENT ON INDEX idx_transactions_onramp_pending IS
    'Supports the onramp processor payment polling fallback.';
