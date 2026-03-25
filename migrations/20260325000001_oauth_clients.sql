-- OAuth 2.0 client registry and authorization code store
-- Supports: Authorization Code + PKCE, Client Credentials, Refresh Token

CREATE TABLE IF NOT EXISTS oauth_clients (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id           VARCHAR(128) NOT NULL UNIQUE,
    client_secret_hash  VARCHAR(256),                    -- NULL for public clients
    client_name         VARCHAR(255) NOT NULL,
    client_type         VARCHAR(32)  NOT NULL CHECK (client_type IN ('public', 'confidential')),
    allowed_grant_types TEXT[]       NOT NULL,
    allowed_scopes      TEXT[]       NOT NULL,
    redirect_uris       TEXT[]       NOT NULL DEFAULT '{}',
    status              VARCHAR(32)  NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'revoked')),
    created_by          VARCHAR(128),                    -- admin wallet or 'developer_portal'
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_oauth_clients_client_id ON oauth_clients (client_id);
CREATE INDEX IF NOT EXISTS idx_oauth_clients_status    ON oauth_clients (status);

-- Short-lived authorization codes (10 min TTL enforced in application layer via Redis)
-- We also persist to DB for audit; Redis is the authoritative single-use store.
CREATE TABLE IF NOT EXISTS oauth_authorization_codes (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code            VARCHAR(256) NOT NULL UNIQUE,
    client_id       VARCHAR(128) NOT NULL REFERENCES oauth_clients (client_id) ON DELETE CASCADE,
    subject         VARCHAR(256) NOT NULL,   -- wallet address of the authorizing user
    scope           TEXT[]       NOT NULL,
    redirect_uri    TEXT         NOT NULL,
    code_challenge  VARCHAR(256) NOT NULL,   -- S256 PKCE challenge
    used            BOOLEAN      NOT NULL DEFAULT FALSE,
    expires_at      TIMESTAMPTZ  NOT NULL,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_oauth_codes_code      ON oauth_authorization_codes (code);
CREATE INDEX IF NOT EXISTS idx_oauth_codes_client_id ON oauth_authorization_codes (client_id);
CREATE INDEX IF NOT EXISTS idx_oauth_codes_expires   ON oauth_authorization_codes (expires_at);
