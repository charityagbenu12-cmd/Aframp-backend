-- Issuer Account Infrastructure
-- Stores configuration metadata only. All private key material lives in the secrets manager.

CREATE TABLE IF NOT EXISTS stellar_issuer_accounts (
    id                      UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    environment             TEXT        NOT NULL CHECK (environment IN ('testnet', 'mainnet')),
    account_id              TEXT        NOT NULL UNIQUE,          -- Stellar public key (G...)
    home_domain             TEXT        NOT NULL,
    asset_code              TEXT        NOT NULL DEFAULT 'cNGN',
    decimal_precision       INTEGER     NOT NULL DEFAULT 7,
    min_issuance_amount     NUMERIC     NOT NULL,
    max_issuance_amount     NUMERIC     NOT NULL,
    -- Multi-sig configuration
    master_weight           INTEGER     NOT NULL DEFAULT 0,
    low_threshold           INTEGER     NOT NULL,
    med_threshold           INTEGER     NOT NULL,
    high_threshold          INTEGER     NOT NULL,
    required_signers        INTEGER     NOT NULL,                 -- e.g. 3 for 3-of-5
    -- Account flags (verified state)
    flag_auth_required      BOOLEAN     NOT NULL DEFAULT false,
    flag_auth_revocable     BOOLEAN     NOT NULL DEFAULT false,
    flag_auth_clawback      BOOLEAN     NOT NULL DEFAULT false,
    -- Status
    is_configured           BOOLEAN     NOT NULL DEFAULT false,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS stellar_issuer_signers (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    issuer_id       UUID        NOT NULL REFERENCES stellar_issuer_accounts(id) ON DELETE CASCADE,
    signer_key      TEXT        NOT NULL,                         -- Stellar public key
    weight          INTEGER     NOT NULL,
    signer_identity TEXT        NOT NULL,                         -- human label e.g. "ops-key-1"
    secrets_ref     TEXT        NOT NULL,                         -- secrets manager key name
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_issuer_signers_key ON stellar_issuer_signers (issuer_id, signer_key);

CREATE TABLE IF NOT EXISTS stellar_distribution_accounts (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    issuer_id       UUID        NOT NULL REFERENCES stellar_issuer_accounts(id) ON DELETE CASCADE,
    account_id      TEXT        NOT NULL UNIQUE,
    secrets_ref     TEXT        NOT NULL,
    trustline_authorized BOOLEAN NOT NULL DEFAULT false,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS stellar_fee_accounts (
    id                      UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    issuer_id               UUID        NOT NULL REFERENCES stellar_issuer_accounts(id) ON DELETE CASCADE,
    account_id              TEXT        NOT NULL UNIQUE,
    secrets_ref             TEXT        NOT NULL,
    min_balance_threshold   NUMERIC     NOT NULL DEFAULT 10.0,    -- XLM
    alert_threshold         NUMERIC     NOT NULL DEFAULT 50.0,    -- XLM
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS issuer_verification_reports (
    id                          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    issuer_id                   UUID        NOT NULL REFERENCES stellar_issuer_accounts(id),
    check_flags_ok              BOOLEAN     NOT NULL,
    check_master_weight_zero    BOOLEAN     NOT NULL,
    check_thresholds_ok         BOOLEAN     NOT NULL,
    check_signers_ok            BOOLEAN     NOT NULL,
    check_stellar_toml_ok       BOOLEAN     NOT NULL,
    overall_pass                BOOLEAN     NOT NULL,
    details                     JSONB       NOT NULL DEFAULT '{}',
    verified_at                 TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_verification_reports_issuer ON issuer_verification_reports (issuer_id, verified_at DESC);

COMMENT ON TABLE stellar_issuer_accounts IS
    'cNGN issuer account configuration. Private keys stored exclusively in secrets manager.';
COMMENT ON TABLE stellar_issuer_signers IS
    'Authorized multi-sig signers for the issuer account. Private keys in secrets manager.';
COMMENT ON TABLE stellar_distribution_accounts IS
    'Distribution account that receives freshly minted cNGN from the issuer.';
COMMENT ON TABLE stellar_fee_accounts IS
    'Fee account that pays transaction fees on behalf of the issuer account.';
COMMENT ON TABLE issuer_verification_reports IS
    'Startup verification check results for the issuer account configuration.';
