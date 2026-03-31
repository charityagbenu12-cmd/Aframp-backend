-- Liquidity Monitor Schema
-- Stores order-book depth snapshots and rebalancing events.

CREATE TYPE liquidity_alert_level AS ENUM ('healthy', 'warning', 'critical');
CREATE TYPE rebalance_trigger_type AS ENUM ('deficit', 'surplus');

CREATE TABLE liquidity_depth_snapshots (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sampled_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    probe_amount_cngn   NUMERIC(28, 7) NOT NULL,
    oracle_price        NUMERIC(20, 10) NOT NULL,
    execution_price     NUMERIC(20, 10) NOT NULL,
    slippage_pct        DOUBLE PRECISION NOT NULL,
    alert_level         liquidity_alert_level NOT NULL,
    bid_depth_cngn      NUMERIC(28, 7) NOT NULL,
    ask_depth_cngn      NUMERIC(28, 7) NOT NULL,
    -- Stellar AMM constant-product k = x * y (NULL if no pool configured)
    amm_k_value         NUMERIC(40, 7),
    rebalance_triggered BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX idx_liquidity_snapshots_sampled_at ON liquidity_depth_snapshots (sampled_at DESC);
CREATE INDEX idx_liquidity_snapshots_alert      ON liquidity_depth_snapshots (alert_level, sampled_at DESC);

CREATE TABLE liquidity_rebalance_events (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    trigger         rebalance_trigger_type NOT NULL,
    amount_cngn     NUMERIC(28, 7) NOT NULL,
    snapshot_id     UUID NOT NULL REFERENCES liquidity_depth_snapshots(id),
    -- Links to vault_transfer_requests once multi-sig request is created.
    vault_request_id UUID,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE liquidity_depth_snapshots IS
    'Per-minute order-book depth and slippage snapshots for cNGN on the Stellar DEX.';
COMMENT ON TABLE liquidity_rebalance_events IS
    'Rebalancing events triggered when slippage exceeds the critical threshold.';
COMMENT ON COLUMN liquidity_depth_snapshots.amm_k_value IS
    'Stellar AMM constant-product invariant k = x * y. Tracks pool exhaustion risk.';
