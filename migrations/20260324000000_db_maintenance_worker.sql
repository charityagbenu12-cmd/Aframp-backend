-- migrate:up
-- Database maintenance worker support tables

-- Archive table for old transactions
CREATE TABLE IF NOT EXISTS transactions_archive (
    LIKE transactions INCLUDING ALL
);

COMMENT ON TABLE transactions_archive IS 'Long-term archive of transactions older than the configured retention period.';

-- Cleanup reports persisted per cycle
CREATE TABLE IF NOT EXISTS cleanup_reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cycle_started_at TIMESTAMPTZ NOT NULL,
    cycle_finished_at TIMESTAMPTZ NOT NULL,
    transactions_archived INTEGER NOT NULL DEFAULT 0,
    quotes_deleted INTEGER NOT NULL DEFAULT 0,
    webhooks_deleted INTEGER NOT NULL DEFAULT 0,
    nonces_deleted INTEGER NOT NULL DEFAULT 0,
    rate_history_deleted INTEGER NOT NULL DEFAULT 0,
    tables_analyzed INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE cleanup_reports IS 'One row per maintenance cycle summarising all cleanup operations.';

-- Nonces table (wallet signature authentication)
CREATE TABLE IF NOT EXISTS wallet_nonces (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    wallet_address VARCHAR(255) NOT NULL,
    nonce TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    used BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_wallet_nonces_expires_at ON wallet_nonces(expires_at);
CREATE INDEX IF NOT EXISTS idx_wallet_nonces_wallet ON wallet_nonces(wallet_address);

COMMENT ON TABLE wallet_nonces IS 'One-time nonces for wallet signature authentication.';

-- Rate history table (append-only, pruned by maintenance worker)
CREATE TABLE IF NOT EXISTS exchange_rate_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    from_currency TEXT NOT NULL,
    to_currency TEXT NOT NULL,
    rate TEXT NOT NULL,
    source TEXT,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_rate_history_pair ON exchange_rate_history(from_currency, to_currency, recorded_at DESC);

COMMENT ON TABLE exchange_rate_history IS 'Historical exchange rate snapshots; pruned to keep only the most recent N rows per pair.';
