-- migrate:up
-- API Key Rotation & Expiry Management (Issue #137)
--
-- Adds:
--   1. NOT NULL expiry on api_keys (enforced via CHECK)
--   2. max_lifetime_days on consumer_types
--   3. key_rotations — links new key to old key with grace period tracking
--   4. key_expiry_notifications — deduplication log for warning emails
--   5. key_audit_log — immutable rotation / forced-rotation event log

-- ─── 1. Enforce expiry on api_keys ───────────────────────────────────────────
-- expires_at already exists (nullable). Add a CHECK so new rows must supply it.
-- Existing NULL rows are left as-is; the application layer enforces the policy
-- for new issuances.
ALTER TABLE api_keys
    ADD CONSTRAINT chk_api_keys_expires_at_required
        CHECK (expires_at IS NOT NULL);

-- ─── 2. Max lifetime per consumer type ───────────────────────────────────────
ALTER TABLE consumer_types
    ADD COLUMN IF NOT EXISTS max_lifetime_days INTEGER NOT NULL DEFAULT 90;

UPDATE consumer_types SET max_lifetime_days = 90  WHERE name = 'third_party_partner';
UPDATE consumer_types SET max_lifetime_days = 180 WHERE name = 'backend_microservice';
UPDATE consumer_types SET max_lifetime_days = 30  WHERE name = 'admin_dashboard';
UPDATE consumer_types SET max_lifetime_days = 90  WHERE name = 'mobile_client';

-- ─── 3. Key rotations ────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS key_rotations (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    old_key_id          UUID NOT NULL REFERENCES api_keys(id),
    new_key_id          UUID NOT NULL REFERENCES api_keys(id),
    grace_period_start  TIMESTAMPTZ NOT NULL DEFAULT now(),
    grace_period_end    TIMESTAMPTZ NOT NULL,
    -- 'active'     → grace period in progress, both keys valid
    -- 'completed'  → consumer explicitly completed rotation early
    -- 'expired'    → background job invalidated old key after grace period
    -- 'forced'     → admin forced rotation, no grace period
    status              TEXT NOT NULL DEFAULT 'active'
                            CHECK (status IN ('active','completed','expired','forced')),
    initiated_by        TEXT NOT NULL,   -- consumer identity or 'admin:<id>'
    forced              BOOLEAN NOT NULL DEFAULT FALSE,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_key_rotations_old_key UNIQUE (old_key_id)
);

CREATE INDEX IF NOT EXISTS idx_key_rotations_old_key  ON key_rotations (old_key_id);
CREATE INDEX IF NOT EXISTS idx_key_rotations_new_key  ON key_rotations (new_key_id);
CREATE INDEX IF NOT EXISTS idx_key_rotations_status   ON key_rotations (status) WHERE status = 'active';
CREATE INDEX IF NOT EXISTS idx_key_rotations_grace_end ON key_rotations (grace_period_end) WHERE status = 'active';

CREATE TRIGGER trg_key_rotations_updated_at
    BEFORE UPDATE ON key_rotations
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ─── 4. Expiry notification deduplication ────────────────────────────────────
CREATE TABLE IF NOT EXISTS key_expiry_notifications (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    api_key_id      UUID NOT NULL REFERENCES api_keys(id) ON DELETE CASCADE,
    consumer_id     UUID NOT NULL,
    -- warning_days: 30 | 14 | 7 | 1 | 0 (0 = final expiry notification)
    warning_days    INTEGER NOT NULL,
    sent_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_key_expiry_notification UNIQUE (api_key_id, warning_days)
);

CREATE INDEX IF NOT EXISTS idx_key_expiry_notif_key ON key_expiry_notifications (api_key_id);

-- ─── 5. Key audit log ────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS key_audit_log (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    api_key_id      UUID NOT NULL,
    consumer_id     UUID NOT NULL,
    -- 'rotated' | 'forced_rotation' | 'expired' | 'grace_completed' | 'issued'
    action          TEXT NOT NULL,
    initiated_by    TEXT,
    metadata        JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_key_audit_key      ON key_audit_log (api_key_id);
CREATE INDEX IF NOT EXISTS idx_key_audit_consumer ON key_audit_log (consumer_id);
CREATE INDEX IF NOT EXISTS idx_key_audit_action   ON key_audit_log (action);
CREATE INDEX IF NOT EXISTS idx_key_audit_at       ON key_audit_log (created_at DESC);
