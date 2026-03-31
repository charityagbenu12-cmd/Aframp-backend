-- migrate:up
CREATE TABLE cngn_supply_snapshots (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  total_issued NUMERIC(36, 18) NOT NULL,
  total_burned NUMERIC(36, 18) NOT NULL,
  circulating_supply NUMERIC(36, 18) NOT NULL,
  authorized_limit NUMERIC(36, 18),
  num_holders INTEGER NOT NULL,
  captured_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE cngn_whales (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  snapshot_id UUID NOT NULL REFERENCES cngn_supply_snapshots(id) ON DELETE CASCADE,
  wallet_address VARCHAR(255) NOT NULL,
  balance NUMERIC(36, 18) NOT NULL,
  supply_percentage NUMERIC(6, 4) NOT NULL,
  captured_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Index for time-series queries
CREATE INDEX idx_cngn_supply_snapshots_captured_at ON cngn_supply_snapshots(captured_at);

-- migrate:down
DROP TABLE cngn_whales;
DROP TABLE cngn_supply_snapshots;
