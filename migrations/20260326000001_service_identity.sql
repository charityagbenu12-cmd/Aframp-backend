-- Service identity registry for microservice-to-microservice authentication
-- Extends oauth_clients with service-specific metadata

-- Service call allowlist — defines which services may call which endpoints
CREATE TABLE IF NOT EXISTS service_call_allowlist (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    calling_service     VARCHAR(128) NOT NULL,  -- service name (matches oauth_clients.client_id)
    target_endpoint     TEXT NOT NULL,          -- endpoint pattern (e.g. "/api/settlement/*")
    allowed             BOOLEAN NOT NULL DEFAULT TRUE,
    created_by          VARCHAR(128),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(calling_service, target_endpoint)
);

CREATE INDEX IF NOT EXISTS idx_service_allowlist_calling ON service_call_allowlist (calling_service);
CREATE INDEX IF NOT EXISTS idx_service_allowlist_endpoint ON service_call_allowlist (target_endpoint);

-- Service client secret rotation tracking
CREATE TABLE IF NOT EXISTS service_secret_rotation (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    service_id          UUID NOT NULL REFERENCES oauth_clients (id) ON DELETE CASCADE,
    old_secret_hash     VARCHAR(256) NOT NULL,
    new_secret_hash     VARCHAR(256) NOT NULL,
    grace_period_ends   TIMESTAMPTZ NOT NULL,  -- both secrets valid until this time
    rotation_completed  BOOLEAN NOT NULL DEFAULT FALSE,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at        TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_service_rotation_service ON service_secret_rotation (service_id);
CREATE INDEX IF NOT EXISTS idx_service_rotation_grace ON service_secret_rotation (grace_period_ends) WHERE NOT rotation_completed;

-- mTLS certificate registry
CREATE TABLE IF NOT EXISTS service_certificates (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    service_id          UUID NOT NULL REFERENCES oauth_clients (id) ON DELETE CASCADE,
    certificate_pem     TEXT NOT NULL,
    private_key_ref     VARCHAR(256) NOT NULL,  -- reference to secrets manager
    serial_number       VARCHAR(128) NOT NULL UNIQUE,
    issued_at           TIMESTAMPTZ NOT NULL,
    expires_at          TIMESTAMPTZ NOT NULL,
    revoked             BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_at          TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_service_certs_service ON service_certificates (service_id);
CREATE INDEX IF NOT EXISTS idx_service_certs_expiry ON service_certificates (expires_at) WHERE NOT revoked;
CREATE INDEX IF NOT EXISTS idx_service_certs_serial ON service_certificates (serial_number);

-- Service authentication audit log
CREATE TABLE IF NOT EXISTS service_auth_audit (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    calling_service     VARCHAR(128) NOT NULL,
    target_endpoint     TEXT NOT NULL,
    token_jti           VARCHAR(128),
    auth_result         VARCHAR(32) NOT NULL CHECK (auth_result IN ('success', 'unauthorized', 'forbidden', 'impersonation_attempt')),
    failure_reason      TEXT,
    request_id          VARCHAR(128),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_service_audit_service ON service_auth_audit (calling_service);
CREATE INDEX IF NOT EXISTS idx_service_audit_result ON service_auth_audit (auth_result);
CREATE INDEX IF NOT EXISTS idx_service_audit_created ON service_auth_audit (created_at);
CREATE INDEX IF NOT EXISTS idx_service_audit_jti ON service_auth_audit (token_jti);
