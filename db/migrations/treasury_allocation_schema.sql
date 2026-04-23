-- ============================================================================
-- SMART TREASURY ALLOCATION ENGINE — Database Schema
-- Issue #TREASURY-001
--
-- Supports:
--   • Multi-custodian reserve tracking with concentration limits
--   • Liquidity tiering (Tier 1/2/3)
--   • Risk-weighted asset (RWA) daily snapshots
--   • Rebalancing transfer orders with full audit trail
--   • Public transparency view (sanitised — no account numbers)
-- ============================================================================

-- ============================================================================
-- 1. CUSTODIAN_INSTITUTIONS
--    Master registry of all approved reserve custodians.
--    Sensitive account details stored encrypted; public view uses alias only.
-- ============================================================================
CREATE TYPE institution_type AS ENUM (
    'tier1_bank',       -- CBN-licensed Tier-1 commercial bank
    'tbill',            -- FGN Treasury Bills (DMO)
    'repo',             -- Overnight / short-term REPO
    'money_market_fund' -- SEC-registered MMF
);

CREATE TYPE risk_rating AS ENUM (
    'aaa', 'aa', 'a', 'bbb', 'bb', 'b', 'ccc', 'downgraded', 'suspended'
);

CREATE TABLE custodian_institutions (
    id                      UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Public-facing alias (never reveals bank name in public API)
    public_alias            VARCHAR(50)     NOT NULL UNIQUE,
    -- Internal name — visible only to treasury operators (RBAC-gated)
    internal_name           VARCHAR(200)    NOT NULL,
    institution_type        institution_type NOT NULL,
    -- Liquidity tier: 1=instant, 2=next-day, 3=30-day
    liquidity_tier          SMALLINT        NOT NULL CHECK (liquidity_tier IN (1, 2, 3)),
    -- Maximum allowed concentration (basis points, e.g. 3500 = 35%)
    max_concentration_bps   INTEGER         NOT NULL DEFAULT 3500
                                CHECK (max_concentration_bps BETWEEN 100 AND 10000),
    -- Current CBN/Fitch/Moody's risk rating
    risk_rating             risk_rating     NOT NULL DEFAULT 'a',
    -- AES-256-GCM encrypted account number (key from KMS)
    encrypted_account_ref   BYTEA,
    -- CBN bank code (public, non-sensitive)
    cbn_bank_code           VARCHAR(10),
    is_active               BOOLEAN         NOT NULL DEFAULT TRUE,
    created_at              TIMESTAMPTZ     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at              TIMESTAMPTZ     NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_custodian_active ON custodian_institutions(is_active, liquidity_tier);

-- ============================================================================
-- 2. RESERVE_ALLOCATIONS
--    Point-in-time balance snapshots per custodian.
--    Written by the reconciliation worker; immutable once confirmed.
-- ============================================================================
CREATE TYPE allocation_status AS ENUM (
    'pending',      -- Awaiting bank confirmation
    'confirmed',    -- Reconciled against bank statement
    'disputed',     -- Discrepancy flagged for review
    'superseded'    -- Replaced by a newer snapshot
);

CREATE TABLE reserve_allocations (
    id                  UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    custodian_id        UUID            NOT NULL REFERENCES custodian_institutions(id),
    -- Balance in NGN kobo (integer arithmetic, no floating point)
    balance_kobo        BIGINT          NOT NULL CHECK (balance_kobo >= 0),
    -- Snapshot timestamp (when the balance was observed)
    snapshot_at         TIMESTAMPTZ     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    status              allocation_status NOT NULL DEFAULT 'pending',
    -- Source of truth: bank_api | manual_entry | reconciliation_worker
    source              VARCHAR(50)     NOT NULL DEFAULT 'reconciliation_worker',
    -- SHA-256 of the raw bank statement line (tamper evidence)
    statement_hash      VARCHAR(64),
    confirmed_by        VARCHAR(100),   -- operator user_id
    confirmed_at        TIMESTAMPTZ,
    notes               TEXT,
    created_at          TIMESTAMPTZ     NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_alloc_custodian_time
    ON reserve_allocations(custodian_id, snapshot_at DESC);
CREATE INDEX idx_alloc_status
    ON reserve_allocations(status, snapshot_at DESC);

-- ============================================================================
-- 3. CONCENTRATION_SNAPSHOTS
--    Materialised view of concentration % per custodian at each reconciliation.
--    Populated by the allocation engine after every balance update.
-- ============================================================================
CREATE TABLE concentration_snapshots (
    id                      UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    custodian_id            UUID            NOT NULL REFERENCES custodian_institutions(id),
    snapshot_at             TIMESTAMPTZ     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    balance_kobo            BIGINT          NOT NULL,
    total_reserves_kobo     BIGINT          NOT NULL,
    -- Concentration in basis points (e.g. 3000 = 30.00%)
    concentration_bps       INTEGER         NOT NULL,
    max_concentration_bps   INTEGER         NOT NULL,
    -- TRUE if concentration_bps > max_concentration_bps
    is_breached             BOOLEAN         NOT NULL GENERATED ALWAYS AS
                                (concentration_bps > max_concentration_bps) STORED,
    liquidity_tier          SMALLINT        NOT NULL,
    created_at              TIMESTAMPTZ     NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_conc_custodian_time
    ON concentration_snapshots(custodian_id, snapshot_at DESC);
CREATE INDEX idx_conc_breached
    ON concentration_snapshots(is_breached, snapshot_at DESC)
    WHERE is_breached = TRUE;

-- ============================================================================
-- 4. CONCENTRATION_ALERTS
--    Fired when any custodian exceeds its max_concentration_bps.
-- ============================================================================
CREATE TYPE alert_severity AS ENUM ('warning', 'critical', 'resolved');
CREATE TYPE alert_channel  AS ENUM ('slack', 'pagerduty', 'email', 'sms');

CREATE TABLE concentration_alerts (
    id                  UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    custodian_id        UUID            NOT NULL REFERENCES custodian_institutions(id),
    snapshot_id         UUID            NOT NULL REFERENCES concentration_snapshots(id),
    severity            alert_severity  NOT NULL,
    concentration_bps   INTEGER         NOT NULL,
    max_allowed_bps     INTEGER         NOT NULL,
    -- Excess in bps (concentration_bps - max_allowed_bps)
    excess_bps          INTEGER         NOT NULL GENERATED ALWAYS AS
                                (concentration_bps - max_allowed_bps) STORED,
    message             TEXT            NOT NULL,
    channels_notified   alert_channel[] NOT NULL DEFAULT '{}',
    acknowledged_by     VARCHAR(100),
    acknowledged_at     TIMESTAMPTZ,
    resolved_at         TIMESTAMPTZ,
    created_at          TIMESTAMPTZ     NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_alerts_unresolved
    ON concentration_alerts(created_at DESC)
    WHERE resolved_at IS NULL;
CREATE INDEX idx_alerts_custodian
    ON concentration_alerts(custodian_id, created_at DESC);

-- ============================================================================
-- 5. RWA_DAILY_SNAPSHOTS
--    Daily risk-weighted asset calculation across all reserve holdings.
--    Risk weights follow CBN prudential guidelines.
-- ============================================================================
CREATE TABLE rwa_daily_snapshots (
    id                      UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    snapshot_date           DATE            NOT NULL UNIQUE,
    -- Total unweighted reserves (NGN kobo)
    total_reserves_kobo     BIGINT          NOT NULL,
    -- Total risk-weighted assets (NGN kobo)
    total_rwa_kobo          BIGINT          NOT NULL,
    -- On-chain cNGN supply (kobo equivalent)
    onchain_supply_kobo     BIGINT          NOT NULL,
    -- Peg coverage ratio (total_reserves / onchain_supply) * 10000 bps
    peg_coverage_bps        INTEGER         NOT NULL,
    -- Per-tier breakdown (JSON for flexibility)
    tier1_kobo              BIGINT          NOT NULL DEFAULT 0,
    tier2_kobo              BIGINT          NOT NULL DEFAULT 0,
    tier3_kobo              BIGINT          NOT NULL DEFAULT 0,
    -- Weighted breakdown by institution type
    rwa_breakdown           JSONB           NOT NULL DEFAULT '{}',
    calculated_by           VARCHAR(100)    NOT NULL DEFAULT 'rwa_worker',
    created_at              TIMESTAMPTZ     NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_rwa_date ON rwa_daily_snapshots(snapshot_date DESC);

-- ============================================================================
-- 6. TRANSFER_ORDERS
--    Rebalancing instructions generated by the allocation engine.
--    Semi-automated: engine generates, treasury operator approves.
-- ============================================================================
CREATE TYPE transfer_order_status AS ENUM (
    'pending_approval',
    'approved',
    'executing',
    'completed',
    'rejected',
    'cancelled'
);

CREATE TYPE transfer_order_trigger AS ENUM (
    'concentration_breach',     -- Automatic: custodian exceeded limit
    'risk_rating_downgrade',    -- Automatic: custodian rating dropped
    'manual_rebalance',         -- Manual: operator-initiated
    'scheduled_rebalance'       -- Scheduled: periodic rebalancing
);

CREATE TABLE transfer_orders (
    id                  UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Source custodian (funds move FROM here)
    from_custodian_id   UUID            NOT NULL REFERENCES custodian_institutions(id),
    -- Destination custodian (funds move TO here)
    to_custodian_id     UUID            NOT NULL REFERENCES custodian_institutions(id),
    amount_kobo         BIGINT          NOT NULL CHECK (amount_kobo > 0),
    trigger             transfer_order_trigger NOT NULL,
    -- Reference to the alert or snapshot that triggered this order
    trigger_ref_id      UUID,
    status              transfer_order_status NOT NULL DEFAULT 'pending_approval',
    -- Recommendation rationale (human-readable)
    rationale           TEXT            NOT NULL,
    -- Projected concentration after transfer (bps)
    projected_from_bps  INTEGER,
    projected_to_bps    INTEGER,
    -- Approval workflow
    requested_by        VARCHAR(100)    NOT NULL DEFAULT 'allocation_engine',
    approved_by         VARCHAR(100),
    approved_at         TIMESTAMPTZ,
    rejection_reason    TEXT,
    -- Execution tracking
    executed_at         TIMESTAMPTZ,
    bank_reference      VARCHAR(100),   -- Bank transfer reference number
    completed_at        TIMESTAMPTZ,
    created_at          TIMESTAMPTZ     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMPTZ     NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT chk_different_custodians CHECK (from_custodian_id != to_custodian_id)
);

CREATE INDEX idx_transfer_status
    ON transfer_orders(status, created_at DESC);
CREATE INDEX idx_transfer_from
    ON transfer_orders(from_custodian_id, created_at DESC);
CREATE INDEX idx_transfer_to
    ON transfer_orders(to_custodian_id, created_at DESC);

-- ============================================================================
-- 7. TRANSFER_ORDER_AUDIT_LOG
--    Immutable audit trail for every state change on a transfer order.
-- ============================================================================
CREATE TABLE transfer_order_audit_log (
    id              BIGSERIAL       PRIMARY KEY,
    order_id        UUID            NOT NULL REFERENCES transfer_orders(id),
    actor_id        VARCHAR(100)    NOT NULL,
    event_type      VARCHAR(80)     NOT NULL,
    old_status      transfer_order_status,
    new_status      transfer_order_status,
    metadata        JSONB           NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ     NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_transfer_audit_order
    ON transfer_order_audit_log(order_id, created_at ASC);

-- ============================================================================
-- 8. PUBLIC_RESERVE_DASHBOARD (materialised view)
--    Sanitised view for the public transparency endpoint.
--    Uses public_alias — never exposes internal_name or account refs.
-- ============================================================================
CREATE MATERIALIZED VIEW public_reserve_dashboard AS
SELECT
    ci.public_alias                                         AS institution_alias,
    ci.institution_type,
    ci.liquidity_tier,
    cs.balance_kobo,
    cs.total_reserves_kobo,
    cs.concentration_bps,
    cs.max_concentration_bps,
    cs.is_breached,
    cs.snapshot_at,
    -- Human-readable percentage (2 decimal places)
    ROUND(cs.concentration_bps::NUMERIC / 100, 2)          AS concentration_pct,
    ROUND(cs.max_concentration_bps::NUMERIC / 100, 2)      AS max_concentration_pct
FROM concentration_snapshots cs
JOIN custodian_institutions ci ON ci.id = cs.custodian_id
WHERE cs.snapshot_at = (
    SELECT MAX(snapshot_at) FROM concentration_snapshots cs2
    WHERE cs2.custodian_id = cs.custodian_id
)
AND ci.is_active = TRUE;

CREATE UNIQUE INDEX idx_public_dashboard_alias
    ON public_reserve_dashboard(institution_alias);

-- Refresh trigger: called by the allocation engine after each reconciliation.
-- Manual refresh: REFRESH MATERIALIZED VIEW CONCURRENTLY public_reserve_dashboard;

-- ============================================================================
-- 9. HELPER FUNCTIONS
-- ============================================================================

-- Compute concentration bps for a custodian given a total reserves figure.
CREATE OR REPLACE FUNCTION compute_concentration_bps(
    p_balance_kobo      BIGINT,
    p_total_kobo        BIGINT
) RETURNS INTEGER LANGUAGE plpgsql IMMUTABLE AS $$
BEGIN
    IF p_total_kobo = 0 THEN RETURN 0; END IF;
    RETURN ROUND((p_balance_kobo::NUMERIC / p_total_kobo) * 10000)::INTEGER;
END;
$$;

-- Auto-update updated_at on transfer_orders
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_transfer_orders_updated_at
    BEFORE UPDATE ON transfer_orders
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER trg_custodian_updated_at
    BEFORE UPDATE ON custodian_institutions
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
