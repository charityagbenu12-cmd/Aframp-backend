-- ============================================================================
-- PAYMENT CORRIDOR ROUTER — Issue #2.04
-- Extends payment_corridors with routing metadata, health tracking,
-- bridge asset mapping, and risk scoring.
-- ============================================================================

-- ---------------------------------------------------------------------------
-- 1. Extend payment_corridors with routing fields.
--    All columns are additive — safe on an existing table.
-- ---------------------------------------------------------------------------

ALTER TABLE payment_corridors
    -- Transfer limits (in source currency)
    ADD COLUMN IF NOT EXISTS min_transfer_amount  DECIMAL(20,4),
    ADD COLUMN IF NOT EXISTS max_transfer_amount  DECIMAL(20,4),
    -- Supported delivery methods (array of: 'bank', 'mobile_money', 'cash_out')
    ADD COLUMN IF NOT EXISTS delivery_methods     TEXT[]        NOT NULL DEFAULT '{}',
    -- Bridge asset used for liquidity (e.g. 'XLM', NULL = direct swap)
    ADD COLUMN IF NOT EXISTS bridge_asset         VARCHAR(10),
    -- Risk score 0–100; influences required KYC tier
    ADD COLUMN IF NOT EXISTS risk_score           SMALLINT      NOT NULL DEFAULT 50
                                                  CHECK (risk_score BETWEEN 0 AND 100),
    -- KYC tier required for this corridor (maps to kyc_tier enum)
    ADD COLUMN IF NOT EXISTS required_kyc_tier    VARCHAR(20)   NOT NULL DEFAULT 'basic',
    -- Human-readable display name
    ADD COLUMN IF NOT EXISTS display_name         VARCHAR(100),
    -- Estimated settlement time in minutes
    ADD COLUMN IF NOT EXISTS estimated_minutes    INTEGER,
    -- Whether the corridor is featured / promoted
    ADD COLUMN IF NOT EXISTS is_featured          BOOLEAN       NOT NULL DEFAULT false,
    -- Metadata bag for provider-specific config (JSON)
    ADD COLUMN IF NOT EXISTS config               JSONB         NOT NULL DEFAULT '{}';

-- ---------------------------------------------------------------------------
-- 2. CORRIDOR_HEALTH
--    Tracks success/failure rates per corridor for monitoring.
--    One row per corridor per hour (time-bucketed).
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS corridor_health (
    id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    corridor_id         UUID        NOT NULL REFERENCES payment_corridors(id) ON DELETE CASCADE,
    bucket_start        TIMESTAMPTZ NOT NULL,   -- truncated to the hour
    total_attempts      INTEGER     NOT NULL DEFAULT 0,
    successful          INTEGER     NOT NULL DEFAULT 0,
    failed              INTEGER     NOT NULL DEFAULT 0,
    avg_latency_ms      INTEGER,
    p95_latency_ms      INTEGER,
    total_volume        DECIMAL(20,4) NOT NULL DEFAULT 0,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT uq_corridor_health_bucket UNIQUE (corridor_id, bucket_start)
);

CREATE INDEX IF NOT EXISTS idx_corridor_health_corridor_time
    ON corridor_health (corridor_id, bucket_start DESC);

CREATE INDEX IF NOT EXISTS idx_corridor_health_time
    ON corridor_health (bucket_start DESC);

-- ---------------------------------------------------------------------------
-- 3. CORRIDOR_ROUTE_HOPS
--    Defines the asset conversion path for a corridor.
--    e.g. cNGN → XLM → KES would be two hops.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS corridor_route_hops (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    corridor_id     UUID        NOT NULL REFERENCES payment_corridors(id) ON DELETE CASCADE,
    hop_order       SMALLINT    NOT NULL,   -- 1-based ordering
    from_asset      VARCHAR(10) NOT NULL,
    to_asset        VARCHAR(10) NOT NULL,
    provider        VARCHAR(50),            -- e.g. 'stellar_dex', 'flutterwave', 'mpesa_kenya'
    is_active       BOOLEAN     NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT uq_corridor_hop UNIQUE (corridor_id, hop_order)
);

CREATE INDEX IF NOT EXISTS idx_route_hops_corridor
    ON corridor_route_hops (corridor_id, hop_order);

-- ---------------------------------------------------------------------------
-- 4. CORRIDOR_AUDIT_LOG
--    Captures every admin change to corridor config (kill-switch, limits, etc.)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS corridor_audit_log (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    corridor_id     UUID        NOT NULL REFERENCES payment_corridors(id) ON DELETE CASCADE,
    action          VARCHAR(50) NOT NULL,   -- 'created'|'updated'|'enabled'|'disabled'|'kill_switch'
    changed_by      UUID,
    changed_by_role VARCHAR(100),
    previous_value  JSONB,
    new_value       JSONB,
    reason          TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_corridor_audit_corridor
    ON corridor_audit_log (corridor_id, created_at DESC);

-- ---------------------------------------------------------------------------
-- 5. Seed the NG→KE corridor with full routing metadata (upsert).
-- ---------------------------------------------------------------------------

UPDATE payment_corridors SET
    min_transfer_amount = 100,
    max_transfer_amount = 5000000,
    delivery_methods    = ARRAY['mobile_money', 'bank'],
    bridge_asset        = 'XLM',
    risk_score          = 45,
    required_kyc_tier   = 'basic',
    display_name        = 'Nigeria → Kenya',
    estimated_minutes   = 5,
    is_featured         = true,
    config              = '{"mpesa_shortcode": "", "cbk_reporting": true}'::jsonb
WHERE source_country = 'NG'
  AND destination_country = 'KE'
  AND source_currency = 'NGN'
  AND destination_currency = 'KES';

-- Seed route hops for NG→KE: cNGN → XLM → KES
INSERT INTO corridor_route_hops (corridor_id, hop_order, from_asset, to_asset, provider)
SELECT pc.id, 1, 'cNGN', 'XLM', 'stellar_dex'
FROM payment_corridors pc
WHERE pc.source_country = 'NG' AND pc.destination_country = 'KE'
  AND NOT EXISTS (
      SELECT 1 FROM corridor_route_hops h
      WHERE h.corridor_id = pc.id AND h.hop_order = 1
  );

INSERT INTO corridor_route_hops (corridor_id, hop_order, from_asset, to_asset, provider)
SELECT pc.id, 2, 'XLM', 'KES', 'mpesa_kenya'
FROM payment_corridors pc
WHERE pc.source_country = 'NG' AND pc.destination_country = 'KE'
  AND NOT EXISTS (
      SELECT 1 FROM corridor_route_hops h
      WHERE h.corridor_id = pc.id AND h.hop_order = 2
  );
