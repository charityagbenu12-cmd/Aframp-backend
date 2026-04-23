-- ============================================================================
-- MINT SLA TIMERS & ESCALATION ENGINE — Database Schema
-- Issue #MINT-SLA-001
--
-- Extends the existing mint_requests workflow with:
--   • Per-request SLA state tracking (warning / escalated / expired)
--   • Escalation log (immutable, one row per action)
--   • Stellar timebound registry (links internal SLA to on-chain window)
--   • Idempotency key per worker run to prevent double-processing
-- ============================================================================

-- ============================================================================
-- 1. MINT_SLA_STATE
--    One row per mint request. Tracks which SLA thresholds have fired.
--    Written by the SLA worker; read by the Stellar submission guard.
-- ============================================================================
CREATE TYPE sla_stage AS ENUM (
    'pending',      -- No SLA action taken yet
    'warned',       -- 4-hour reminder sent to Tier-1 approver
    'escalated',    -- 12-hour escalation sent to Tier-2 manager
    'expired',      -- 24-hour auto-expiration applied
    'resolved'      -- Request left PENDING state (approved/rejected/executed)
);

CREATE TABLE mint_sla_state (
    id                  UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    mint_request_id     UUID            NOT NULL UNIQUE
                            REFERENCES mint_requests(id) ON DELETE CASCADE,
    stage               sla_stage       NOT NULL DEFAULT 'pending',
    -- Timestamps when each threshold was crossed (NULL = not yet fired)
    warned_at           TIMESTAMPTZ,
    escalated_at        TIMESTAMPTZ,
    expired_at          TIMESTAMPTZ,
    resolved_at         TIMESTAMPTZ,
    -- Escalation target (Tier-2 manager user_id, set at escalation time)
    escalated_to        VARCHAR(100),
    -- Worker idempotency: last run that touched this row
    last_worker_run_id  UUID,
    created_at          TIMESTAMPTZ     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMPTZ     NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_sla_stage
    ON mint_sla_state(stage, updated_at DESC)
    WHERE stage NOT IN ('expired', 'resolved');

CREATE INDEX idx_sla_request
    ON mint_sla_state(mint_request_id);

-- ============================================================================
-- 2. MINT_ESCALATION_LOG
--    Immutable audit trail for every SLA action (nudge, escalate, expire).
--    Satisfies Audit Trail requirement (#117).
-- ============================================================================
CREATE TYPE escalation_action AS ENUM (
    'sla_warning_sent',         -- 4-hour reminder dispatched
    'sla_escalated',            -- 12-hour escalation dispatched
    'sla_expired',              -- 24-hour auto-expiration applied
    'sla_resolved',             -- SLA resolved (request left pending state)
    'stellar_timebound_set',    -- Timebound window recorded for a request
    'stellar_timeout_failed'    -- Transaction missed its timebound window
);

CREATE TABLE mint_escalation_log (
    id                  BIGSERIAL       PRIMARY KEY,
    mint_request_id     UUID            NOT NULL REFERENCES mint_requests(id),
    action              escalation_action NOT NULL,
    actor_id            VARCHAR(100)    NOT NULL DEFAULT 'sla_worker',
    -- Elapsed hours at the time of action
    elapsed_hours       NUMERIC(6,2)    NOT NULL,
    -- Notification targets (JSON array of user_ids / channels)
    notified_targets    JSONB           NOT NULL DEFAULT '[]',
    -- Arbitrary metadata (e.g. escalated_to, reason, timebound window)
    metadata            JSONB           NOT NULL DEFAULT '{}',
    -- Worker run that produced this entry (idempotency reference)
    worker_run_id       UUID,
    created_at          TIMESTAMPTZ     NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_escalation_request
    ON mint_escalation_log(mint_request_id, created_at ASC);

CREATE INDEX idx_escalation_action
    ON mint_escalation_log(action, created_at DESC);

-- ============================================================================
-- 3. MINT_STELLAR_TIMEBOUNDS
--    Records the exact [min_time, max_time] window used for each Stellar
--    transaction envelope. Enables post-hoc verification and TIMEOUT_FAILED
--    detection.
-- ============================================================================
CREATE TABLE mint_stellar_timebounds (
    id                  UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    mint_request_id     UUID            NOT NULL UNIQUE
                            REFERENCES mint_requests(id) ON DELETE CASCADE,
    -- Unix timestamps matching the XDR TimeBounds
    min_time_unix       BIGINT          NOT NULL,
    max_time_unix       BIGINT          NOT NULL,
    -- Human-readable equivalents
    min_time_at         TIMESTAMPTZ     NOT NULL GENERATED ALWAYS AS
                            (to_timestamp(min_time_unix)) STORED,
    max_time_at         TIMESTAMPTZ     NOT NULL GENERATED ALWAYS AS
                            (to_timestamp(max_time_unix)) STORED,
    -- Internal SLA deadline at the time the envelope was built
    sla_expires_at      TIMESTAMPTZ     NOT NULL,
    -- Whether the window has been missed (set by SLA worker)
    is_timeout_failed   BOOLEAN         NOT NULL DEFAULT FALSE,
    timeout_detected_at TIMESTAMPTZ,
    created_at          TIMESTAMPTZ     NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_timebounds_active
    ON mint_stellar_timebounds(max_time_at DESC)
    WHERE is_timeout_failed = FALSE;

-- ============================================================================
-- 4. HELPER: auto-update updated_at on mint_sla_state
-- ============================================================================
CREATE OR REPLACE FUNCTION set_sla_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_mint_sla_updated_at
    BEFORE UPDATE ON mint_sla_state
    FOR EACH ROW EXECUTE FUNCTION set_sla_updated_at();

-- ============================================================================
-- 5. HELPER: initialise SLA state row when a mint request is created.
--    Keeps the SLA worker query simple (always one row per request).
-- ============================================================================
CREATE OR REPLACE FUNCTION init_mint_sla_state()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO mint_sla_state (mint_request_id)
    VALUES (NEW.id)
    ON CONFLICT (mint_request_id) DO NOTHING;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_init_mint_sla_state
    AFTER INSERT ON mint_requests
    FOR EACH ROW EXECUTE FUNCTION init_mint_sla_state();
