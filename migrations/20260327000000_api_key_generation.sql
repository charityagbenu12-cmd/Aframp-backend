-- migrate:up
-- API Key Generation & Issuance System (Issue #131)
--
-- Upgrades the api_keys table to support:
--   • Argon2id hashing (replaces SHA-256)
--   • Environment scoping (testnet / mainnet)
--   • Explicit status column (active / expired / revoked)
--   • key_id prefix for fast lookup without full table scan
--   • issued_by audit field
--   • api_key_audit_log for issuance and verification events

-- ─── Extend api_keys ─────────────────────────────────────────────────────────

-- Add environment column (testnet | mainnet) — default testnet for existing rows
ALTER TABLE api_keys
    ADD COLUMN IF NOT EXISTS environment TEXT NOT NULL DEFAULT 'testnet'
        CHECK (environment IN ('testnet', 'mainnet'));

-- Add explicit status column
ALTER TABLE api_keys
    ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'expired', 'revoked'));

-- Rename is_active → keep for backward compat but drive logic from status
-- (is_active is kept so existing scope middleware still works)

-- Add issued_by (identity of admin or developer who issued the key)
ALTER TABLE api_keys
    ADD COLUMN IF NOT EXISTS issued_by TEXT;

-- Add key_id_prefix: short human-readable prefix embedded in the key string
-- e.g. "aframp_live_" or "aframp_test_"
-- Stored separately so we can reconstruct the display form without the secret.
ALTER TABLE api_keys
    ADD COLUMN IF NOT EXISTS key_id_prefix TEXT NOT NULL DEFAULT 'aframp_test_';

-- Index for fast lookup by (key_prefix, status) — avoids full table scan
CREATE INDEX IF NOT EXISTS idx_api_keys_prefix_status
    ON api_keys (key_prefix, status)
    WHERE status = 'active';

-- Index for environment-scoped lookups
CREATE INDEX IF NOT EXISTS idx_api_keys_env_status
    ON api_keys (environment, status)
    WHERE status = 'active';

-- ─── API Key Audit Log ────────────────────────────────────────────────────────
-- Immutable log of every issuance and verification event.
-- The plaintext key secret is NEVER stored here.

CREATE TABLE IF NOT EXISTS api_key_audit_log (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type      TEXT NOT NULL CHECK (event_type IN ('issued', 'verified', 'rejected', 'revoked', 'expired')),
    api_key_id      UUID,                          -- NULL for rejected events where key doesn't exist
    consumer_id     UUID,
    issuing_identity TEXT,                         -- admin wallet / developer ID who issued
    environment     TEXT,
    endpoint        TEXT,
    ip_address      TEXT,
    rejection_reason TEXT,                         -- populated on rejected events
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Never log the key secret — enforced by schema (no secret column)
COMMENT ON TABLE api_key_audit_log IS
    'Immutable audit log for API key lifecycle events. Plaintext key secrets are never stored.';

CREATE INDEX IF NOT EXISTS idx_api_key_audit_key        ON api_key_audit_log (api_key_id);
CREATE INDEX IF NOT EXISTS idx_api_key_audit_consumer   ON api_key_audit_log (consumer_id);
CREATE INDEX IF NOT EXISTS idx_api_key_audit_event      ON api_key_audit_log (event_type);
CREATE INDEX IF NOT EXISTS idx_api_key_audit_at         ON api_key_audit_log (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_api_key_audit_env        ON api_key_audit_log (environment);
