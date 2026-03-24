-- migrate:up
-- API Key Scoping & Permission Model (Issue #132)
--
-- Tables:
--   consumers          — registered API consumers (mobile apps, partners, microservices, admin)
--   api_keys           — hashed API keys associated with consumers
--   scopes             — platform-wide scope catalogue
--   key_scopes         — many-to-many: which scopes are granted to which key
--   scope_audit_log    — immutable log of every scope grant/revocation and denial

-- ─── Consumer Types ───────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS consumer_types (
    name        TEXT PRIMARY KEY,
    description TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO consumer_types (name, description) VALUES
    ('mobile_client',       'Mobile application — end-user facing'),
    ('third_party_partner', 'External partner integrating the platform API'),
    ('backend_microservice','Internal microservice-to-microservice communication'),
    ('admin_dashboard',     'Admin dashboard with elevated privileges')
ON CONFLICT DO NOTHING;

-- ─── Consumers ────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS consumers (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name          TEXT NOT NULL,
    consumer_type TEXT NOT NULL REFERENCES consumer_types(name),
    environment   TEXT NOT NULL DEFAULT 'testnet' CHECK (environment IN ('testnet', 'mainnet')),
    is_active     BOOLEAN NOT NULL DEFAULT TRUE,
    created_by    TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_consumers_type ON consumers (consumer_type);
CREATE INDEX IF NOT EXISTS idx_consumers_env  ON consumers (environment);

CREATE TRIGGER trg_consumers_updated_at
    BEFORE UPDATE ON consumers
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ─── API Keys ─────────────────────────────────────────────────────────────────
-- The raw key is never stored. Only the SHA-256 hash is persisted.
-- key_prefix stores the first 8 chars of the raw key for display/lookup.

CREATE TABLE IF NOT EXISTS api_keys (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    consumer_id   UUID NOT NULL REFERENCES consumers(id) ON DELETE CASCADE,
    key_hash      TEXT NOT NULL UNIQUE,   -- SHA-256(raw_key) hex-encoded
    key_prefix    TEXT NOT NULL,          -- First 8 chars of raw key (display only)
    description   TEXT,
    is_active     BOOLEAN NOT NULL DEFAULT TRUE,
    expires_at    TIMESTAMPTZ,
    last_used_at  TIMESTAMPTZ,
    issued_by     TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_api_keys_consumer   ON api_keys (consumer_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_hash       ON api_keys (key_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_active     ON api_keys (is_active) WHERE is_active = TRUE;

CREATE TRIGGER trg_api_keys_updated_at
    BEFORE UPDATE ON api_keys
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ─── Scopes ───────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS scopes (
    name                        TEXT PRIMARY KEY,
    description                 TEXT NOT NULL,
    category                    TEXT NOT NULL,
    applicable_consumer_types   TEXT[] NOT NULL DEFAULT '{}',
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Platform scope catalogue
INSERT INTO scopes (name, description, category, applicable_consumer_types) VALUES
    ('onramp:quote',          'Request onramp quotes',                          'onramp',      ARRAY['mobile_client','third_party_partner']),
    ('onramp:initiate',       'Initiate onramp transactions',                   'onramp',      ARRAY['mobile_client','third_party_partner']),
    ('onramp:read',           'Read onramp transaction status and history',     'onramp',      ARRAY['mobile_client','third_party_partner','admin_dashboard']),
    ('offramp:quote',         'Request offramp quotes',                         'offramp',     ARRAY['mobile_client','third_party_partner']),
    ('offramp:initiate',      'Initiate offramp transactions',                  'offramp',     ARRAY['mobile_client']),
    ('offramp:read',          'Read offramp transaction status and history',    'offramp',     ARRAY['mobile_client','third_party_partner','admin_dashboard']),
    ('bills:read',            'List available bill providers',                  'bills',       ARRAY['mobile_client','admin_dashboard']),
    ('bills:pay',             'Initiate bill payments',                         'bills',       ARRAY['mobile_client']),
    ('wallet:read',           'Read wallet balances and transaction history',   'wallet',      ARRAY['mobile_client','backend_microservice','admin_dashboard']),
    ('wallet:trustline',      'Manage cNGN trustlines',                         'wallet',      ARRAY['mobile_client']),
    ('rates:read',            'Read exchange rates and fees',                   'rates',       ARRAY['mobile_client','third_party_partner','backend_microservice','admin_dashboard']),
    ('webhooks:manage',       'Register and manage webhook endpoints',          'webhooks',    ARRAY['mobile_client','third_party_partner','admin_dashboard']),
    ('analytics:read',        'Read analytics dashboard data',                  'analytics',   ARRAY['admin_dashboard']),
    ('admin:transactions',    'Access admin transaction management endpoints',  'admin',       ARRAY['admin_dashboard']),
    ('admin:consumers',       'Manage consumer identities and API keys',        'admin',       ARRAY['admin_dashboard']),
    ('batch:cngn_transfer',   'Submit batch cNGN transfer requests',            'batch',       ARRAY['mobile_client','third_party_partner','admin_dashboard']),
    ('batch:fiat_payout',     'Submit batch fiat payout requests',              'batch',       ARRAY['admin_dashboard']),
    ('batch:read',            'Read batch status and item details',             'batch',       ARRAY['mobile_client','third_party_partner','admin_dashboard']),
    ('microservice:internal', 'Internal microservice-to-microservice calls',    'microservice',ARRAY['backend_microservice'])
ON CONFLICT DO NOTHING;

-- ─── Consumer Type Default Profiles ──────────────────────────────────────────
-- Stores the default scopes that are auto-assigned when a key is issued
-- for a given consumer type.

CREATE TABLE IF NOT EXISTS consumer_type_profiles (
    consumer_type TEXT NOT NULL REFERENCES consumer_types(name),
    scope_name    TEXT NOT NULL REFERENCES scopes(name),
    PRIMARY KEY (consumer_type, scope_name)
);

INSERT INTO consumer_type_profiles (consumer_type, scope_name) VALUES
    -- Mobile client profile
    ('mobile_client', 'onramp:quote'),
    ('mobile_client', 'onramp:initiate'),
    ('mobile_client', 'onramp:read'),
    ('mobile_client', 'offramp:quote'),
    ('mobile_client', 'offramp:initiate'),
    ('mobile_client', 'offramp:read'),
    ('mobile_client', 'bills:read'),
    ('mobile_client', 'bills:pay'),
    ('mobile_client', 'wallet:read'),
    ('mobile_client', 'wallet:trustline'),
    ('mobile_client', 'rates:read'),
    ('mobile_client', 'batch:cngn_transfer'),
    ('mobile_client', 'batch:read'),
    -- Third party partner profile
    ('third_party_partner', 'onramp:quote'),
    ('third_party_partner', 'onramp:initiate'),
    ('third_party_partner', 'onramp:read'),
    ('third_party_partner', 'offramp:quote'),
    ('third_party_partner', 'offramp:read'),
    ('third_party_partner', 'rates:read'),
    ('third_party_partner', 'webhooks:manage'),
    ('third_party_partner', 'batch:cngn_transfer'),
    ('third_party_partner', 'batch:read'),
    -- Backend microservice profile
    ('backend_microservice', 'microservice:internal'),
    ('backend_microservice', 'wallet:read'),
    ('backend_microservice', 'rates:read'),
    -- Admin dashboard profile (all non-microservice scopes)
    ('admin_dashboard', 'onramp:quote'),
    ('admin_dashboard', 'onramp:initiate'),
    ('admin_dashboard', 'onramp:read'),
    ('admin_dashboard', 'offramp:quote'),
    ('admin_dashboard', 'offramp:initiate'),
    ('admin_dashboard', 'offramp:read'),
    ('admin_dashboard', 'bills:read'),
    ('admin_dashboard', 'bills:pay'),
    ('admin_dashboard', 'wallet:read'),
    ('admin_dashboard', 'wallet:trustline'),
    ('admin_dashboard', 'rates:read'),
    ('admin_dashboard', 'webhooks:manage'),
    ('admin_dashboard', 'analytics:read'),
    ('admin_dashboard', 'admin:transactions'),
    ('admin_dashboard', 'admin:consumers'),
    ('admin_dashboard', 'batch:cngn_transfer'),
    ('admin_dashboard', 'batch:fiat_payout'),
    ('admin_dashboard', 'batch:read')
ON CONFLICT DO NOTHING;

-- ─── Key Scopes (Many-to-Many) ────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS key_scopes (
    api_key_id    UUID NOT NULL REFERENCES api_keys(id) ON DELETE CASCADE,
    scope_name    TEXT NOT NULL REFERENCES scopes(name),
    granted_by    TEXT,
    granted_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (api_key_id, scope_name)
);

CREATE INDEX IF NOT EXISTS idx_key_scopes_key ON key_scopes (api_key_id);

-- ─── Scope Audit Log ──────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS scope_audit_log (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    api_key_id    UUID NOT NULL,
    consumer_id   UUID NOT NULL,
    action        TEXT NOT NULL CHECK (action IN ('grant', 'revoke', 'denied')),
    scope_name    TEXT NOT NULL,
    endpoint      TEXT,
    performed_by  TEXT,
    ip_address    TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_scope_audit_key      ON scope_audit_log (api_key_id);
CREATE INDEX IF NOT EXISTS idx_scope_audit_consumer ON scope_audit_log (consumer_id);
CREATE INDEX IF NOT EXISTS idx_scope_audit_action   ON scope_audit_log (action);
CREATE INDEX IF NOT EXISTS idx_scope_audit_at       ON scope_audit_log (created_at DESC);
