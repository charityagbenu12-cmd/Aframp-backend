-- migrate:up
-- Add priority and tiering to transactions for Mint Queue Management (Issue #126)

ALTER TABLE transactions ADD COLUMN IF NOT EXISTS priority_level INTEGER DEFAULT 0; -- 0: standard, 1: urgent/gold
ALTER TABLE transactions ADD COLUMN IF NOT EXISTS partner_tier TEXT DEFAULT 'standard'; -- 'standard', 'gold', 'platinum'

CREATE INDEX IF NOT EXISTS idx_transactions_priority ON transactions (priority_level DESC, created_at ASC);

-- migrate:down
ALTER TABLE transactions DROP COLUMN IF EXISTS priority_level;
ALTER TABLE transactions DROP COLUMN IF EXISTS partner_tier;
DROP INDEX IF EXISTS idx_transactions_priority;
