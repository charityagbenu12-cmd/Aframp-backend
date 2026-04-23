-- LP Onboarding & Partner Portal Schema
-- Covers: partner profiles, documents, agreements, stellar key allowlist, expiry alerts

-- ── LP status enum ────────────────────────────────────────────────────────────

CREATE TYPE lp_status AS ENUM (
    'documents_pending',
    'legal_review',
    'kyb_screening',
    'agreement_pending',
    'trial',
    'active',
    'suspended',
    'revoked'
);

CREATE TYPE lp_tier AS ENUM ('trial', 'full');

-- ── Partner (LP) profiles ─────────────────────────────────────────────────────

CREATE TABLE lp_partners (
    partner_id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    legal_name              VARCHAR(255)  NOT NULL,
    registration_number     VARCHAR(100),
    tax_id                  VARCHAR(100),
    jurisdiction            VARCHAR(100)  NOT NULL,
    contact_email           VARCHAR(255)  NOT NULL UNIQUE,
    contact_name            VARCHAR(255)  NOT NULL,
    status                  lp_status     NOT NULL DEFAULT 'documents_pending',
    tier                    lp_tier       NOT NULL DEFAULT 'trial',
    -- volume caps (NGN)
    daily_volume_cap        NUMERIC(28,8) NOT NULL DEFAULT 10000000,   -- 10M trial default
    monthly_volume_cap      NUMERIC(28,8) NOT NULL DEFAULT 100000000,  -- 100M trial default
    -- KYB link
    kyb_reference_id        UUID,
    kyb_passed_at           TIMESTAMPTZ,
    -- admin
    reviewed_by             UUID,
    revoked_by              UUID,
    revocation_reason       TEXT,
    revoked_at              TIMESTAMPTZ,
    created_at              TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_lp_partners_status ON lp_partners(status);
CREATE INDEX idx_lp_partners_tier   ON lp_partners(tier);

-- ── Submitted documents ───────────────────────────────────────────────────────

CREATE TYPE lp_doc_type AS ENUM (
    'certificate_of_incorporation',
    'tax_id',
    'proof_of_address',
    'aml_policy',
    'other'
);

CREATE TYPE lp_doc_status AS ENUM ('pending', 'approved', 'rejected');

CREATE TABLE lp_documents (
    document_id     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    partner_id      UUID          NOT NULL REFERENCES lp_partners(partner_id) ON DELETE CASCADE,
    doc_type        lp_doc_type   NOT NULL,
    file_name       VARCHAR(255)  NOT NULL,
    storage_key     TEXT          NOT NULL,   -- S3 / object-store key
    doc_status      lp_doc_status NOT NULL DEFAULT 'pending',
    reviewed_by     UUID,
    review_note     TEXT,
    uploaded_at     TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    reviewed_at     TIMESTAMPTZ
);

CREATE INDEX idx_lp_docs_partner ON lp_documents(partner_id);

-- ── Liquidity Provision Agreements ───────────────────────────────────────────

CREATE TYPE agreement_status AS ENUM (
    'draft',
    'sent_for_signature',
    'signed',
    'expired',
    'superseded'
);

CREATE TABLE lp_agreements (
    agreement_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    partner_id          UUID              NOT NULL REFERENCES lp_partners(partner_id) ON DELETE CASCADE,
    version             VARCHAR(20)       NOT NULL,   -- e.g. 'v1.2'
    agreement_status    agreement_status  NOT NULL DEFAULT 'draft',
    -- DocuSign / e-sign integration
    docusign_envelope_id VARCHAR(255),
    signed_at           TIMESTAMPTZ,
    -- content hash stored in audit trail
    document_hash       VARCHAR(128),                -- SHA-256 hex of signed PDF
    -- validity window
    effective_from      DATE              NOT NULL,
    expires_on          DATE              NOT NULL,
    -- expiry alert tracking
    expiry_alert_30d_sent  BOOLEAN        NOT NULL DEFAULT FALSE,
    expiry_alert_7d_sent   BOOLEAN        NOT NULL DEFAULT FALSE,
    created_at          TIMESTAMPTZ       NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ       NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_agreement_dates CHECK (expires_on > effective_from)
);

CREATE INDEX idx_lp_agreements_partner  ON lp_agreements(partner_id);
CREATE INDEX idx_lp_agreements_status   ON lp_agreements(agreement_status);
CREATE INDEX idx_lp_agreements_expiry   ON lp_agreements(expires_on)
    WHERE agreement_status = 'signed';

-- ── Stellar G-address allowlist ───────────────────────────────────────────────

CREATE TABLE lp_stellar_keys (
    key_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    partner_id      UUID         NOT NULL REFERENCES lp_partners(partner_id) ON DELETE CASCADE,
    stellar_address VARCHAR(56)  NOT NULL,   -- G-address (56 chars)
    label           VARCHAR(100),
    is_active       BOOLEAN      NOT NULL DEFAULT TRUE,
    added_by        UUID         NOT NULL,
    revoked_by      UUID,
    revoked_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_stellar_address_format CHECK (stellar_address ~ '^G[A-Z2-7]{55}$')
);

CREATE UNIQUE INDEX idx_lp_stellar_keys_address ON lp_stellar_keys(stellar_address) WHERE is_active = TRUE;
CREATE INDEX idx_lp_stellar_keys_partner        ON lp_stellar_keys(partner_id);
