-- ============================================================================
-- MINT APPROVAL WORKFLOW SCHEMA
-- Implements programmable multi-step, role-based approval pipeline for
-- cNGN mint requests before on-chain execution on Stellar.
-- ============================================================================

-- ============================================================================
-- 1. MINT_REQUESTS TABLE
-- Stores each mint request with its current state and tier metadata.
-- ============================================================================
CREATE TABLE mint_requests (
    id                  UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Who submitted the request (wallet or user identifier)
    submitted_by        VARCHAR(100)    NOT NULL,
    -- Stellar destination wallet address
    destination_wallet  VARCHAR(56)     NOT NULL,
    -- Amount in NGN (used to determine tier at submission time)
    amount_ngn          DECIMAL(18,2)   NOT NULL CHECK (amount_ngn > 0),
    -- Equivalent cNGN amount to mint
    amount_cngn         DECIMAL(18,8)   NOT NULL CHECK (amount_cngn > 0),
    -- Exchange rate snapshot at submission time
    rate_snapshot       DECIMAL(18,8)   NOT NULL,
    -- Approval tier: 1, 2, or 3 (calculated at submission time)
    approval_tier       SMALLINT        NOT NULL CHECK (approval_tier IN (1, 2, 3)),
    -- Number of approvals required for this tier
    required_approvals  SMALLINT        NOT NULL CHECK (required_approvals > 0),
    -- Current state machine status
    status              VARCHAR(30)     NOT NULL DEFAULT 'pending_approval'
        CHECK (status IN (
            'pending_approval',
            'partially_approved',
            'approved',
            'rejected',
            'expired',
            'executed'
        )),
    -- Optional reference (e.g., linked onramp quote or external ref)
    reference           VARCHAR(100),
    -- Arbitrary metadata (JSON)
    metadata            JSONB           NOT NULL DEFAULT '{}',
    -- Expiry: requests auto-expire after 24 hours if not fully approved
    expires_at          TIMESTAMPTZ     NOT NULL DEFAULT (CURRENT_TIMESTAMP + INTERVAL '24 hours'),
    -- Stellar transaction hash after execution
    stellar_tx_hash     VARCHAR(64),
    created_at          TIMESTAMPTZ     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMPTZ     NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_mint_requests_status
    ON mint_requests(status, created_at DESC);

CREATE INDEX idx_mint_requests_submitted_by
    ON mint_requests(submitted_by, created_at DESC);

CREATE INDEX idx_mint_requests_expires
    ON mint_requests(expires_at)
    WHERE status NOT IN ('approved', 'rejected', 'expired', 'executed');

-- ============================================================================
-- 2. MINT_APPROVALS TABLE
-- Each row is one approver's signature on a mint request.
-- ============================================================================
CREATE TABLE mint_approvals (
    id              UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    mint_request_id UUID            NOT NULL REFERENCES mint_requests(id) ON DELETE CASCADE,
    -- Approver's user identifier (from IdP / JWT sub claim)
    approver_id     VARCHAR(100)    NOT NULL,
    -- Role at time of approval (mint_operator | compliance_officer | finance_director)
    approver_role   VARCHAR(50)     NOT NULL
        CHECK (approver_role IN ('mint_operator', 'compliance_officer', 'finance_director')),
    -- approve | reject
    action          VARCHAR(10)     NOT NULL CHECK (action IN ('approve', 'reject')),
    -- Mandatory reason code on rejection
    reason_code     VARCHAR(50),
    -- Optional human-readable comment
    comment         TEXT,
    created_at      TIMESTAMPTZ     NOT NULL DEFAULT CURRENT_TIMESTAMP,

    -- Prevent the same approver from acting twice on the same request
    CONSTRAINT uq_approver_per_request UNIQUE (mint_request_id, approver_id)
);

CREATE INDEX idx_mint_approvals_request
    ON mint_approvals(mint_request_id, created_at ASC);

CREATE INDEX idx_mint_approvals_approver
    ON mint_approvals(approver_id, created_at DESC);

-- ============================================================================
-- 3. MINT_AUDIT_LOG TABLE
-- Immutable audit trail for every state change and action on a mint request.
-- ============================================================================
CREATE TABLE mint_audit_log (
    id              BIGSERIAL       PRIMARY KEY,
    mint_request_id UUID            NOT NULL REFERENCES mint_requests(id) ON DELETE CASCADE,
    -- Actor who triggered the event (user_id or 'system')
    actor_id        VARCHAR(100)    NOT NULL,
    actor_role      VARCHAR(50),
    -- Event type
    event_type      VARCHAR(50)     NOT NULL,
    -- State before the event
    from_status     VARCHAR(30),
    -- State after the event
    to_status       VARCHAR(30),
    -- Structured event payload
    payload         JSONB           NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ     NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_mint_audit_request
    ON mint_audit_log(mint_request_id, created_at ASC);

CREATE INDEX idx_mint_audit_actor
    ON mint_audit_log(actor_id, created_at DESC);

-- ============================================================================
-- Helper: auto-update updated_at on mint_requests
-- ============================================================================
CREATE OR REPLACE FUNCTION update_mint_request_timestamp()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_mint_requests_updated_at
    BEFORE UPDATE ON mint_requests
    FOR EACH ROW EXECUTE FUNCTION update_mint_request_timestamp();
