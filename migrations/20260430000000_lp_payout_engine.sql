-- LP Payout Engine Schema
-- Supports: hourly pool snapshots, reward accrual, epoch disbursement,
--           wash-trade exclusion, and compliance flagging.

-- ---------------------------------------------------------------------------
-- Enums
-- ---------------------------------------------------------------------------
DO $$ BEGIN
    CREATE TYPE lp_reward_type AS ENUM ('fee_based', 'liquidity_mining');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    CREATE TYPE lp_payout_status AS ENUM ('pending', 'processing', 'completed', 'failed', 'flagged');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

-- ---------------------------------------------------------------------------
-- lp_providers — registered liquidity providers
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS lp_providers (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    stellar_address     TEXT NOT NULL UNIQUE,
    display_name        TEXT NOT NULL,
    is_active           BOOLEAN NOT NULL DEFAULT TRUE,
    whitelisted_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_lp_providers_active ON lp_providers (is_active);

-- ---------------------------------------------------------------------------
-- lp_pool_snapshots — hourly pro-rata share snapshots
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS lp_pool_snapshots (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    snapshot_at         TIMESTAMPTZ NOT NULL,
    lp_provider_id      UUID NOT NULL REFERENCES lp_providers(id),
    pool_id             TEXT NOT NULL,                  -- Stellar liquidity pool ID
    lp_balance_stroops  BIGINT NOT NULL,                -- LP's pool share in stroops
    total_pool_stroops  BIGINT NOT NULL,                -- Total pool size in stroops
    pro_rata_share      NUMERIC(20, 10) NOT NULL,       -- lp_balance / total_pool
    volume_stroops      BIGINT NOT NULL DEFAULT 0,      -- Volume traded in this hour
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (snapshot_at, lp_provider_id, pool_id)
);

CREATE INDEX IF NOT EXISTS idx_lp_snapshots_provider_time
    ON lp_pool_snapshots (lp_provider_id, snapshot_at DESC);
CREATE INDEX IF NOT EXISTS idx_lp_snapshots_pool_time
    ON lp_pool_snapshots (pool_id, snapshot_at DESC);

-- ---------------------------------------------------------------------------
-- lp_reward_epochs — weekly (or configurable) reward periods
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS lp_reward_epochs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    epoch_start     TIMESTAMPTZ NOT NULL,
    epoch_end       TIMESTAMPTZ NOT NULL,
    total_fees_stroops      BIGINT NOT NULL DEFAULT 0,  -- Dynamic fees collected
    total_volume_stroops    BIGINT NOT NULL DEFAULT 0,
    mining_rate_per_1000    NUMERIC(20, 10) NOT NULL DEFAULT 0, -- cNGN per 1000 NGN/hr
    is_finalized    BOOLEAN NOT NULL DEFAULT FALSE,
    finalized_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (epoch_start, epoch_end)
);

-- ---------------------------------------------------------------------------
-- lp_accrued_rewards — per-LP accrued rewards within an epoch
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS lp_accrued_rewards (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    epoch_id            UUID NOT NULL REFERENCES lp_reward_epochs(id),
    lp_provider_id      UUID NOT NULL REFERENCES lp_providers(id),
    reward_type         lp_reward_type NOT NULL,
    accrued_stroops     BIGINT NOT NULL DEFAULT 0,      -- Total accrued (stroop precision)
    paid_stroops        BIGINT NOT NULL DEFAULT 0,
    is_wash_trade_excluded BOOLEAN NOT NULL DEFAULT FALSE,
    compliance_flagged  BOOLEAN NOT NULL DEFAULT FALSE,
    compliance_reason   TEXT,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (epoch_id, lp_provider_id, reward_type)
);

CREATE INDEX IF NOT EXISTS idx_lp_accrued_epoch ON lp_accrued_rewards (epoch_id);
CREATE INDEX IF NOT EXISTS idx_lp_accrued_provider ON lp_accrued_rewards (lp_provider_id);

-- ---------------------------------------------------------------------------
-- lp_payouts — disbursement records (one per LP per epoch)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS lp_payouts (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    epoch_id            UUID NOT NULL REFERENCES lp_reward_epochs(id),
    lp_provider_id      UUID NOT NULL REFERENCES lp_providers(id),
    stellar_address     TEXT NOT NULL,
    total_stroops       BIGINT NOT NULL,
    status              lp_payout_status NOT NULL DEFAULT 'pending',
    stellar_tx_hash     TEXT,
    compliance_withheld BOOLEAN NOT NULL DEFAULT FALSE,
    compliance_reason   TEXT,
    attempted_at        TIMESTAMPTZ,
    completed_at        TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (epoch_id, lp_provider_id)
);

CREATE INDEX IF NOT EXISTS idx_lp_payouts_status ON lp_payouts (status);
CREATE INDEX IF NOT EXISTS idx_lp_payouts_epoch ON lp_payouts (epoch_id);
