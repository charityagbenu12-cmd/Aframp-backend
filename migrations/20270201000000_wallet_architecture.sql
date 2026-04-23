-- Wallet architecture, recovery, history, and portfolio schema

-- Core wallet registry
CREATE TABLE IF NOT EXISTS wallet_registry (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_account_id UUID NOT NULL,
    stellar_public_key VARCHAR(56) NOT NULL UNIQUE,
    wallet_label VARCHAR(100),
    wallet_type VARCHAR(20) NOT NULL DEFAULT 'personal' CHECK (wallet_type IN ('personal','business','savings')),
    status VARCHAR(20) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','active','suspended','closed')),
    is_primary BOOLEAN NOT NULL DEFAULT false,
    kyc_tier_at_registration INTEGER NOT NULL DEFAULT 0,
    registration_ip INET,
    last_activity_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS wallet_metadata (
    wallet_id UUID PRIMARY KEY REFERENCES wallet_registry(id) ON DELETE CASCADE,
    network VARCHAR(20) NOT NULL DEFAULT 'testnet',
    account_created_on_stellar BOOLEAN NOT NULL DEFAULT false,
    min_xlm_balance_met BOOLEAN NOT NULL DEFAULT false,
    cngn_trustline_active BOOLEAN NOT NULL DEFAULT false,
    xlm_balance NUMERIC(30,7),
    last_horizon_sync_at TIMESTAMPTZ,
    horizon_cursor VARCHAR(100),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS wallet_activity (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    wallet_id UUID NOT NULL REFERENCES wallet_registry(id) ON DELETE CASCADE,
    activity_type VARCHAR(50) NOT NULL,
    associated_transaction_id UUID,
    ip_address INET,
    metadata JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Auth challenges (single-use, time-bound)
CREATE TABLE IF NOT EXISTS wallet_auth_challenges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    stellar_public_key VARCHAR(56) NOT NULL,
    challenge TEXT NOT NULL UNIQUE,
    used BOOLEAN NOT NULL DEFAULT false,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Backup confirmation
CREATE TABLE IF NOT EXISTS wallet_backup_confirmations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    wallet_id UUID NOT NULL REFERENCES wallet_registry(id) ON DELETE CASCADE,
    confirmed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    confirmation_method VARCHAR(50) NOT NULL DEFAULT 'mnemonic',
    last_reminder_sent_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Recovery sessions
CREATE TABLE IF NOT EXISTS wallet_recovery_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    recovered_public_key VARCHAR(56),
    recovery_method VARCHAR(30) NOT NULL CHECK (recovery_method IN ('mnemonic','social','hardware')),
    status VARCHAR(20) NOT NULL DEFAULT 'initiated' CHECK (status IN ('initiated','completed','failed')),
    ip_address INET,
    user_agent TEXT,
    failure_reason TEXT,
    initiated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);

-- Recovery rate limiting
CREATE TABLE IF NOT EXISTS wallet_recovery_attempts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ip_address INET NOT NULL,
    wallet_public_key VARCHAR(56),
    attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    success BOOLEAN NOT NULL DEFAULT false,
    cooloff_until TIMESTAMPTZ
);

-- Social recovery guardians
CREATE TABLE IF NOT EXISTS wallet_guardians (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    wallet_id UUID NOT NULL REFERENCES wallet_registry(id) ON DELETE CASCADE,
    guardian_user_id UUID,
    guardian_email VARCHAR(255),
    share_index INTEGER NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'active' CHECK (status IN ('active','removed')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS social_recovery_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    wallet_id UUID NOT NULL REFERENCES wallet_registry(id) ON DELETE CASCADE,
    status VARCHAR(20) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','completed','expired','cancelled')),
    threshold_required INTEGER NOT NULL DEFAULT 2,
    shares_collected INTEGER NOT NULL DEFAULT 0,
    initiated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '48 hours'
);

CREATE TABLE IF NOT EXISTS guardian_approvals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    recovery_request_id UUID NOT NULL REFERENCES social_recovery_requests(id) ON DELETE CASCADE,
    guardian_id UUID NOT NULL REFERENCES wallet_guardians(id),
    approved_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    signature TEXT NOT NULL
);

-- Wallet migration
CREATE TABLE IF NOT EXISTS wallet_migrations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    old_wallet_id UUID NOT NULL REFERENCES wallet_registry(id),
    new_wallet_id UUID NOT NULL REFERENCES wallet_registry(id),
    status VARCHAR(20) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','completed','failed')),
    old_wallet_signature TEXT NOT NULL,
    new_wallet_signature TEXT NOT NULL,
    initiated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);

-- Transaction history
CREATE TABLE IF NOT EXISTS wallet_transaction_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    wallet_id UUID NOT NULL REFERENCES wallet_registry(id) ON DELETE CASCADE,
    entry_type VARCHAR(30) NOT NULL,
    direction VARCHAR(10) NOT NULL CHECK (direction IN ('credit','debit')),
    asset_code VARCHAR(20) NOT NULL,
    asset_issuer VARCHAR(56),
    amount NUMERIC(30,7) NOT NULL,
    fiat_equivalent NUMERIC(30,7),
    fiat_currency VARCHAR(10),
    exchange_rate NUMERIC(30,10),
    counterparty VARCHAR(256),
    platform_transaction_id UUID,
    stellar_transaction_hash VARCHAR(64),
    parent_entry_id UUID REFERENCES wallet_transaction_history(id),
    status VARCHAR(20) NOT NULL DEFAULT 'confirmed',
    description TEXT,
    failure_reason TEXT,
    horizon_cursor VARCHAR(100),
    confirmed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS stellar_sync_cursors (
    wallet_id UUID PRIMARY KEY REFERENCES wallet_registry(id) ON DELETE CASCADE,
    last_cursor VARCHAR(100),
    last_synced_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Financial statements
CREATE TABLE IF NOT EXISTS financial_statements (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_account_id UUID NOT NULL,
    wallet_id UUID REFERENCES wallet_registry(id),
    statement_type VARCHAR(30) NOT NULL CHECK (statement_type IN ('monthly','annual','custom','tax')),
    date_from DATE NOT NULL,
    date_to DATE NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','generating','completed','failed')),
    format VARCHAR(10) NOT NULL DEFAULT 'pdf' CHECK (format IN ('pdf','csv','json')),
    file_url TEXT,
    verification_code VARCHAR(64),
    download_expires_at TIMESTAMPTZ,
    generated_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Portfolio snapshots
CREATE TABLE IF NOT EXISTS portfolio_snapshots (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_account_id UUID NOT NULL,
    snapshot_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    total_value_fiat NUMERIC(30,7) NOT NULL,
    fiat_currency VARCHAR(10) NOT NULL DEFAULT 'NGN',
    asset_breakdown JSONB NOT NULL DEFAULT '{}',
    exchange_rates_applied JSONB NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS portfolio_preferences (
    user_account_id UUID PRIMARY KEY,
    preferred_fiat_currency VARCHAR(10) NOT NULL DEFAULT 'NGN',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_wallet_registry_user ON wallet_registry(user_account_id);
CREATE INDEX IF NOT EXISTS idx_wallet_registry_pubkey ON wallet_registry(stellar_public_key);
CREATE INDEX IF NOT EXISTS idx_wallet_activity_wallet ON wallet_activity(wallet_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_auth_challenges_pubkey ON wallet_auth_challenges(stellar_public_key, expires_at);
CREATE INDEX IF NOT EXISTS idx_recovery_attempts_ip ON wallet_recovery_attempts(ip_address, attempt_at DESC);
CREATE INDEX IF NOT EXISTS idx_recovery_attempts_pubkey ON wallet_recovery_attempts(wallet_public_key, attempt_at DESC);
CREATE INDEX IF NOT EXISTS idx_tx_history_wallet ON wallet_transaction_history(wallet_id, confirmed_at DESC);
CREATE INDEX IF NOT EXISTS idx_tx_history_stellar_hash ON wallet_transaction_history(stellar_transaction_hash);
CREATE INDEX IF NOT EXISTS idx_tx_history_platform_tx ON wallet_transaction_history(platform_transaction_id);
CREATE INDEX IF NOT EXISTS idx_portfolio_snapshots_user ON portfolio_snapshots(user_account_id, snapshot_at DESC);
CREATE INDEX IF NOT EXISTS idx_statements_user ON financial_statements(user_account_id, created_at DESC);
