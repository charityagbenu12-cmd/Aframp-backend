
CREATE TYPE signer_role AS ENUM ('cfo','cto','cco','treasury_manager','external_auditor');
CREATE TYPE signer_status AS ENUM ('pending_onboarding','pending_identity','active','suspended','pending_removal','removed');

CREATE TABLE mint_signers (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    full_legal_name      VARCHAR(255) NOT NULL,
    role                 signer_role NOT NULL,
    organisation         VARCHAR(255) NOT NULL,
    contact_email        VARCHAR(255) NOT NULL UNIQUE,
    stellar_public_key   VARCHAR(64) UNIQUE,
    key_fingerprint      VARCHAR(64),
    key_registered_at    TIMESTAMPTZ,
    key_expires_at       TIMESTAMPTZ,
    signing_weight       SMALLINT NOT NULL DEFAULT 1,
    status               signer_status NOT NULL DEFAULT 'pending_onboarding',
    last_signing_at      TIMESTAMPTZ,
    onboarding_token     VARCHAR(128) UNIQUE,
    onboarding_token_exp TIMESTAMPTZ,
    identity_verified    BOOLEAN NOT NULL DEFAULT FALSE,
    initiated_by         UUID NOT NULL,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE mint_signer_challenges (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    signer_id      UUID NOT NULL REFERENCES mint_signers(id) ON DELETE CASCADE,
    challenge      VARCHAR(128) NOT NULL UNIQUE,
    challenge_hash VARCHAR(64) NOT NULL,
    expires_at     TIMESTAMPTZ NOT NULL,
    used_at        TIMESTAMPTZ,
    outcome        VARCHAR(32),
    ip_address     INET,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE mint_signer_activity (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    signer_id       UUID NOT NULL REFERENCES mint_signers(id) ON DELETE CASCADE,
    auth_request_id UUID,
    signing_ts      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    sig_status      VARCHAR(32) NOT NULL,
    ip_address      INET
);

CREATE TABLE mint_signer_key_rotations (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    signer_id      UUID NOT NULL REFERENCES mint_signers(id) ON DELETE CASCADE,
    old_public_key VARCHAR(64) NOT NULL,
    new_public_key VARCHAR(64) NOT NULL,
    grace_ends_at  TIMESTAMPTZ NOT NULL,
    old_removed_at TIMESTAMPTZ,
    initiated_by   UUID NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE mint_quorum_config (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    required_threshold SMALLINT NOT NULL,
    min_role_diversity JSONB NOT NULL DEFAULT '{}',
    updated_by         UUID NOT NULL,
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX ON mint_signer_activity (signer_id, signing_ts DESC);
CREATE INDEX ON mint_signers (status);
CREATE INDEX ON mint_signers (stellar_public_key);
