-- Migration: Payload encryption key versions
-- Tracks key version metadata for audit and rotation management.
-- Private keys are NEVER stored here — they live in the secrets manager.

CREATE TABLE IF NOT EXISTS payload_encryption_keys (
    kid                 TEXT        PRIMARY KEY,
    status              TEXT        NOT NULL CHECK (status IN ('active', 'transitional', 'retired')),
    alg                 TEXT        NOT NULL DEFAULT 'ECDH-ES+A256KW',
    enc                 TEXT        NOT NULL DEFAULT 'A256GCM',
    -- Public key PEM stored for audit; private key is in secrets manager only.
    public_key_pem      TEXT        NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    activated_at        TIMESTAMPTZ,
    retired_at          TIMESTAMPTZ,
    rotation_window_end TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_payload_enc_keys_status ON payload_encryption_keys (status);

COMMENT ON TABLE payload_encryption_keys IS
    'Payload encryption key version registry. Private keys are stored exclusively in the secrets manager.';
