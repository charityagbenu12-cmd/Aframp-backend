-- HMAC request signing audit log (Issue #139)
-- Records every signature verification failure for security observability.

CREATE TABLE IF NOT EXISTS hmac_signing_audit (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    key_id       TEXT        NOT NULL,
    endpoint     TEXT        NOT NULL,
    method       TEXT        NOT NULL,
    algorithm    TEXT,
    failure_code TEXT        NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_hmac_signing_audit_key_id_created_at
    ON hmac_signing_audit (key_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_hmac_signing_audit_failure_code_created_at
    ON hmac_signing_audit (failure_code, created_at DESC);
