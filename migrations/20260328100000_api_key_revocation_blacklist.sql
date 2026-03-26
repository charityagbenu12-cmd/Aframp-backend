-- migrate:up
-- API Key Revocation & Blacklisting System (Issue #138)
--
-- Tables:
--   key_revocations        — immutable record of every key revocation event
--   consumer_blacklist     — consumer-level blacklist (blocks all keys for a consumer)

-- ─── Revocation Types ─────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS key_revocations (
    id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    key_id            UUID        NOT NULL REFERENCES api_keys(id) ON DELETE CASCADE,
    consumer_id       UUID        NOT NULL REFERENCES consumers(id) ON DELETE CASCADE,
    revocation_type   TEXT        NOT NULL CHECK (revocation_type IN (
                                      'consumer_requested',
                                      'admin_initiated',
                                      'forced',
                                      'automated_abuse',
                                      'automated_suspicious_ip',
                                      'automated_inactivity',
                                      'decommission',
                                      'policy_violation',
                                      'suspected_compromise'
                                  )),
    reason            TEXT        NOT NULL,
    revoked_by        TEXT        NOT NULL,   -- identity: consumer_id, admin username, or 'system'
    triggering_detail JSONB,                  -- for automated: threshold values, IP, etc.
    revoked_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_key_revocations_key_id      ON key_revocations (key_id);
CREATE INDEX IF NOT EXISTS idx_key_revocations_consumer_id ON key_revocations (consumer_id);
CREATE INDEX IF NOT EXISTS idx_key_revocations_type        ON key_revocations (revocation_type);
CREATE INDEX IF NOT EXISTS idx_key_revocations_at          ON key_revocations (revoked_at DESC);

-- ─── Consumer Blacklist ───────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS consumer_blacklist (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    consumer_id     UUID        NOT NULL REFERENCES consumers(id) ON DELETE CASCADE,
    reason          TEXT        NOT NULL,
    blacklisted_by  TEXT        NOT NULL,
    blacklisted_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ,             -- NULL = permanent
    lifted_at       TIMESTAMPTZ,             -- set when manually lifted
    is_active       BOOLEAN     NOT NULL DEFAULT TRUE
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_consumer_blacklist_active
    ON consumer_blacklist (consumer_id) WHERE is_active = TRUE;

CREATE INDEX IF NOT EXISTS idx_consumer_blacklist_consumer ON consumer_blacklist (consumer_id);
CREATE INDEX IF NOT EXISTS idx_consumer_blacklist_expires  ON consumer_blacklist (expires_at)
    WHERE expires_at IS NOT NULL AND is_active = TRUE;

-- ─── Add revoked status to api_keys ──────────────────────────────────────────
-- is_active = FALSE already covers revoked keys; we add a dedicated status
-- column so we can distinguish 'revoked' from 'expired' or 'disabled'.

ALTER TABLE api_keys
    ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'revoked', 'expired', 'disabled'));

CREATE INDEX IF NOT EXISTS idx_api_keys_status ON api_keys (status);
