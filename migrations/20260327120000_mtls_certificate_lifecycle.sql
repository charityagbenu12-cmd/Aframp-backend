-- Migration: mTLS certificate lifecycle tracking (Issue #204)
-- Stores certificate metadata for audit, inventory, and lifecycle management.
-- Private keys are NEVER stored in the database — only in-memory and secrets manager.

CREATE TABLE IF NOT EXISTS mtls_service_certificates (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    service_name    TEXT NOT NULL,
    environment     TEXT NOT NULL,
    serial          TEXT NOT NULL UNIQUE,
    subject         TEXT NOT NULL,
    issued_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ NOT NULL,
    is_revoked      BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_at      TIMESTAMPTZ,
    revocation_reason TEXT,
    rotation_in_progress BOOLEAN NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_mtls_certs_service_name ON mtls_service_certificates (service_name);
CREATE INDEX idx_mtls_certs_expires_at   ON mtls_service_certificates (expires_at);
CREATE INDEX idx_mtls_certs_is_revoked   ON mtls_service_certificates (is_revoked);

-- CRL entries for revoked certificates
CREATE TABLE IF NOT EXISTS mtls_crl_entries (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    serial          TEXT NOT NULL UNIQUE,
    service_name    TEXT NOT NULL,
    revoked_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    reason          TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_mtls_crl_serial ON mtls_crl_entries (serial);

-- mTLS handshake audit log
CREATE TABLE IF NOT EXISTS mtls_handshake_audit (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    from_service    TEXT NOT NULL,
    to_service      TEXT NOT NULL,
    client_serial   TEXT,
    result          TEXT NOT NULL CHECK (result IN ('success', 'failure')),
    failure_reason  TEXT,
    occurred_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_mtls_handshake_from_to ON mtls_handshake_audit (from_service, to_service);
CREATE INDEX idx_mtls_handshake_occurred ON mtls_handshake_audit (occurred_at);
