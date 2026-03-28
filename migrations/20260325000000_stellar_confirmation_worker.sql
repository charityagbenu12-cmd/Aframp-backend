-- migrate:up
-- Adds columns required by the Stellar Confirmation Polling Worker.

-- stellar_tx_hash: the on-chain hash the worker polls Horizon for.
-- stale_flagged_at: set when a transaction is stuck beyond the stale timeout.
-- state_transitioned_at: timestamp of the last status change (audit trail).

ALTER TABLE transactions
    ADD COLUMN IF NOT EXISTS stellar_tx_hash       TEXT,
    ADD COLUMN IF NOT EXISTS stale_flagged_at      TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS state_transitioned_at TIMESTAMPTZ;

-- Index for the worker's primary query: active txns with a stellar hash.
CREATE INDEX IF NOT EXISTS idx_transactions_stellar_polling
    ON transactions (status, stellar_tx_hash)
    WHERE status IN ('pending', 'processing') AND stellar_tx_hash IS NOT NULL;

-- Index for stale-transaction detection.
CREATE INDEX IF NOT EXISTS idx_transactions_stale_check
    ON transactions (status, created_at)
    WHERE status IN ('pending', 'processing');

-- migrate:down
DROP INDEX IF EXISTS idx_transactions_stale_check;
DROP INDEX IF EXISTS idx_transactions_stellar_polling;
ALTER TABLE transactions
    DROP COLUMN IF EXISTS state_transitioned_at,
    DROP COLUMN IF EXISTS stale_flagged_at,
    DROP COLUMN IF EXISTS stellar_tx_hash;
