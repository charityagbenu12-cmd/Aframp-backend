-- Platform Key Management Framework
-- Stores key METADATA only. Key material lives exclusively in the secrets manager.

CREATE TABLE IF NOT EXISTS platform_keys (
    id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    key_id              TEXT        NOT NULL UNIQUE,          -- human-readable e.g. "jwt-signing-v3"
    key_type            TEXT        NOT NULL CHECK (key_type IN (
                            'jwt_signing', 'payload_encryption', 'db_field_encryption',
                            'hmac_derivation', 'backup_encryption', 'tls')),
    algorithm           TEXT        NOT NULL,                 -- e.g. "RS256", "AES-256-GCM", "ECDH-ES+A256KW"
    key_length_bits     INTEGER,
    status              TEXT        NOT NULL DEFAULT 'active' CHECK (status IN (
                            'pending', 'active', 'transitional', 'retired', 'destroyed')),
    storage_location    TEXT        NOT NULL DEFAULT 'secrets_manager'
                            CHECK (storage_location IN ('secrets_manager', 'hsm', 'in_memory')),
    rotation_days       INTEGER     NOT NULL,                 -- scheduled rotation interval
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    activated_at        TIMESTAMPTZ,
    last_rotated_at     TIMESTAMPTZ,
    next_rotation_at    TIMESTAMPTZ,
    grace_period_end    TIMESTAMPTZ,
    retired_at          TIMESTAMPTZ,
    destroyed_at        TIMESTAMPTZ,
    -- For JWT keys: kid used in token headers
    jwt_kid             TEXT,
    -- For payload enc keys: version identifier
    enc_version         TEXT,
    notes               TEXT
);

CREATE INDEX IF NOT EXISTS idx_platform_keys_status       ON platform_keys (status);
CREATE INDEX IF NOT EXISTS idx_platform_keys_type         ON platform_keys (key_type);
CREATE INDEX IF NOT EXISTS idx_platform_keys_next_rotation ON platform_keys (next_rotation_at)
    WHERE status IN ('active', 'transitional');

-- Immutable audit trail for every key lifecycle event
CREATE TABLE IF NOT EXISTS platform_key_events (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    platform_key_id UUID        NOT NULL REFERENCES platform_keys(id),
    event_type      TEXT        NOT NULL CHECK (event_type IN (
                        'generated', 'activated', 'rotation_initiated', 'grace_period_started',
                        'grace_period_expired', 'retired', 'destroyed', 'emergency_revoked',
                        'reencryption_started', 'reencryption_completed')),
    initiated_by    TEXT        NOT NULL,   -- 'scheduler' | 'admin:<id>' | 'system'
    reason          TEXT,
    metadata        JSONB       NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_platform_key_events_key  ON platform_key_events (platform_key_id);
CREATE INDEX IF NOT EXISTS idx_platform_key_events_type ON platform_key_events (event_type);
CREATE INDEX IF NOT EXISTS idx_platform_key_events_at   ON platform_key_events (created_at DESC);

-- Tracks DB field re-encryption progress per table
CREATE TABLE IF NOT EXISTS reencryption_jobs (
    id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    old_key_id          UUID        NOT NULL REFERENCES platform_keys(id),
    new_key_id          UUID        NOT NULL REFERENCES platform_keys(id),
    table_name          TEXT        NOT NULL,
    total_records       BIGINT      NOT NULL DEFAULT 0,
    records_processed   BIGINT      NOT NULL DEFAULT 0,
    status              TEXT        NOT NULL DEFAULT 'pending'
                            CHECK (status IN ('pending', 'running', 'completed', 'failed')),
    started_at          TIMESTAMPTZ,
    completed_at        TIMESTAMPTZ,
    error_message       TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_reencryption_jobs_status ON reencryption_jobs (status);

COMMENT ON TABLE platform_keys IS
    'Key metadata catalogue. Key material is stored exclusively in the secrets manager or HSM.';
COMMENT ON TABLE platform_key_events IS
    'Immutable audit trail for all platform key lifecycle events.';
COMMENT ON TABLE reencryption_jobs IS
    'Tracks progress of database field re-encryption jobs during key rotation.';
