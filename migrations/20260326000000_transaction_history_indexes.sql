-- migrate:up
-- Transaction history: indexes for cursor-based pagination and filtering

-- Primary history query: wallet + created_at DESC (cursor pagination)
CREATE INDEX IF NOT EXISTS idx_transactions_history_cursor
    ON transactions(wallet_address, created_at DESC, transaction_id DESC);

-- Filter by type
CREATE INDEX IF NOT EXISTS idx_transactions_wallet_type
    ON transactions(wallet_address, type, created_at DESC);

-- Filter by status
CREATE INDEX IF NOT EXISTS idx_transactions_wallet_status
    ON transactions(wallet_address, status, created_at DESC);

-- Filter by date range
CREATE INDEX IF NOT EXISTS idx_transactions_wallet_created
    ON transactions(wallet_address, created_at);

-- Filter by currency pair
CREATE INDEX IF NOT EXISTS idx_transactions_wallet_currencies
    ON transactions(wallet_address, from_currency, to_currency, created_at DESC);

-- Sort by amount
CREATE INDEX IF NOT EXISTS idx_transactions_wallet_amount
    ON transactions(wallet_address, from_amount DESC, created_at DESC);
