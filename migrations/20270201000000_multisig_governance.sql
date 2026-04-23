-- Multi-Signature Governance Framework
-- Implements M-of-N signing for Mint, Burn, and SetOptions treasury operations.
-- Satisfies Issue: Multi-Sig Governance for High-Privilege Stellar Operations.

-- ─────────────────────────────────────────────────────────────────────────────
-- Enum: operation type that requires multi-sig consensus
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TYPE multisig_op_type AS ENUM (
    'mint',
    'burn',
    'set_options',
    'add_signer',
    'remove_signer',
    'change_threshold'
);

-- ─────────────────────────────────────────────────────────────────────────────
-- Enum: lifecycle state of a governance proposal
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TYPE multisig_proposal_status AS ENUM (
    'pending',          -- awaiting signatures
    'time_locked',      -- threshold met but time-lock not yet elapsed (governance changes)
    'ready',            -- threshold met and time-lock elapsed (or no time-lock required)
    'submitted',        -- XDR submitted to Stellar Horizon
    'confirmed',        -- on-chain confirmation received
    'rejected',         -- explicitly rejected by a quorum signer
    'expired'           -- proposal TTL elapsed without reaching threshold
);

-- ─────────────────────────────────────────────────────────────────────────────
-- Table: multisig_proposals
-- One row per treasury operation proposal.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE multisig_proposals (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Operation metadata
    op_type             multisig_op_type NOT NULL,
    description         TEXT NOT NULL,

    -- Stellar transaction data
    -- The unsigned XDR is stored so signers can inspect it before signing.
    unsigned_xdr        TEXT NOT NULL,
    -- Accumulated XDR after each signer adds their signature.
    -- NULL until the first signature is collected.
    signed_xdr          TEXT,
    -- Stellar transaction hash after on-chain submission.
    stellar_tx_hash     VARCHAR(64),

    -- Quorum configuration snapshot at proposal time
    -- (stored so historical proposals are not affected by future quorum changes)
    required_signatures SMALLINT NOT NULL,
    total_signers       SMALLINT NOT NULL,

    -- Time-lock: for governance changes (add/remove signer, change threshold)
    -- NULL means no time-lock required.
    time_lock_until     TIMESTAMPTZ,

    -- Proposal lifecycle
    status              multisig_proposal_status NOT NULL DEFAULT 'pending',
    failure_reason      TEXT,

    -- Proposer identity
    proposed_by         UUID NOT NULL,          -- references mint_signers.id
    proposed_by_key     VARCHAR(64) NOT NULL,   -- Stellar public key at proposal time

    -- Timestamps
    expires_at          TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '72 hours'),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    submitted_at        TIMESTAMPTZ,
    confirmed_at        TIMESTAMPTZ
);

-- ─────────────────────────────────────────────────────────────────────────────
-- Table: multisig_signatures
-- One row per signer per proposal.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE multisig_signatures (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    proposal_id     UUID NOT NULL REFERENCES multisig_proposals(id) ON DELETE CASCADE,

    -- Signer identity
    signer_id       UUID NOT NULL REFERENCES mint_signers(id),
    signer_key      VARCHAR(64) NOT NULL,   -- Stellar public key used to sign
    signer_role     VARCHAR(64) NOT NULL,

    -- Cryptographic signature (base64-encoded XDR DecoratedSignature)
    -- Provided by the signer's hardware wallet or key management system.
    signature_xdr   TEXT NOT NULL,

    -- Audit fields
    signed_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ip_address      INET,
    user_agent      TEXT,

    -- Prevent duplicate signatures from the same signer on the same proposal
    UNIQUE (proposal_id, signer_id)
);

-- ─────────────────────────────────────────────────────────────────────────────
-- Table: multisig_governance_log
-- Immutable append-only audit trail for every governance event.
-- Satisfies: "Every signature, proposal, and execution must be logged with
-- a timestamp and the unique public key of the signer."
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE multisig_governance_log (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    proposal_id     UUID REFERENCES multisig_proposals(id),

    -- Event classification
    event_type      VARCHAR(64) NOT NULL,   -- e.g. 'proposal_created', 'signature_added', 'submitted', 'confirmed'
    actor_key       VARCHAR(64),            -- Stellar public key of the actor (NULL for system events)
    actor_id        UUID,                   -- references mint_signers.id (NULL for system events)

    -- Payload (JSON snapshot of relevant state at event time)
    payload         JSONB NOT NULL DEFAULT '{}',

    -- Tamper-evident hash chain (SHA-256 of previous_hash || event data)
    previous_hash   VARCHAR(64),
    current_hash    VARCHAR(64) NOT NULL,

    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ─────────────────────────────────────────────────────────────────────────────
-- Table: multisig_quorum_config
-- Active M-of-N configuration for each operation class.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE multisig_quorum_config (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    op_type             multisig_op_type NOT NULL UNIQUE,
    required_signatures SMALLINT NOT NULL CHECK (required_signatures >= 1),
    total_signers       SMALLINT NOT NULL CHECK (total_signers >= required_signatures),
    -- Time-lock duration in seconds (0 = no time-lock)
    time_lock_seconds   INTEGER NOT NULL DEFAULT 0,
    updated_by          UUID NOT NULL,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ─────────────────────────────────────────────────────────────────────────────
-- Seed: default quorum configuration (3-of-5 for critical ops, 2-of-5 for mint)
-- ─────────────────────────────────────────────────────────────────────────────
-- These are placeholder values; the treasury team must update them via the
-- admin API after onboarding signers.
INSERT INTO multisig_quorum_config (op_type, required_signatures, total_signers, time_lock_seconds, updated_by)
VALUES
    ('mint',             3, 5,     0,      gen_random_uuid()),
    ('burn',             3, 5,     0,      gen_random_uuid()),
    ('set_options',      3, 5,     0,      gen_random_uuid()),
    ('add_signer',       3, 5, 172800,     gen_random_uuid()),  -- 48-hour time-lock
    ('remove_signer',    3, 5, 172800,     gen_random_uuid()),  -- 48-hour time-lock
    ('change_threshold', 4, 5, 172800,     gen_random_uuid());  -- 48-hour time-lock

-- ─────────────────────────────────────────────────────────────────────────────
-- Indexes
-- ─────────────────────────────────────────────────────────────────────────────
CREATE INDEX idx_multisig_proposals_status     ON multisig_proposals (status);
CREATE INDEX idx_multisig_proposals_op_type    ON multisig_proposals (op_type);
CREATE INDEX idx_multisig_proposals_proposed_by ON multisig_proposals (proposed_by);
CREATE INDEX idx_multisig_proposals_expires_at ON multisig_proposals (expires_at);
CREATE INDEX idx_multisig_signatures_proposal  ON multisig_signatures (proposal_id);
CREATE INDEX idx_multisig_signatures_signer    ON multisig_signatures (signer_id);
CREATE INDEX idx_multisig_gov_log_proposal     ON multisig_governance_log (proposal_id);
CREATE INDEX idx_multisig_gov_log_actor_key    ON multisig_governance_log (actor_key);
CREATE INDEX idx_multisig_gov_log_created_at   ON multisig_governance_log (created_at DESC);
