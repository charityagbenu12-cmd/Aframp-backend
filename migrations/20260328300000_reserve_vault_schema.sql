-- Reserve Vault Schema
-- Supports: account segregation, M-of-N outbound transfer requests,
--           inbound deposit event log (triggers mint lifecycle #123).

-- ---------------------------------------------------------------------------
-- Account type enum
-- ---------------------------------------------------------------------------
DO $$ BEGIN
    CREATE TYPE vault_account_type AS ENUM ('minting_reserve', 'operational_expense');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

-- ---------------------------------------------------------------------------
-- vault_accounts — logical registry of segregated reserve accounts
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS vault_accounts (
    id              TEXT PRIMARY KEY,
    account_type    vault_account_type NOT NULL,
    currency        TEXT NOT NULL DEFAULT 'NGN',
    custodian       TEXT NOT NULL,          -- e.g. 'providus', 'sterling', 'mock'
    description     TEXT,
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ---------------------------------------------------------------------------
-- vault_transfer_requests — M-of-N outbound transfer approval workflow
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS vault_transfer_requests (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id              TEXT NOT NULL REFERENCES vault_accounts(id),
    amount                  NUMERIC(20, 2) NOT NULL CHECK (amount > 0),
    currency                TEXT NOT NULL DEFAULT 'NGN',
    destination_account     TEXT NOT NULL,
    destination_bank_code   TEXT NOT NULL,
    narration               TEXT NOT NULL,
    -- 'pending_approval' | 'approved' | 'executed' | 'rejected'
    status                  TEXT NOT NULL DEFAULT 'pending_approval',
    -- JSONB array of ApprovalSignature objects
    signatures              JSONB NOT NULL DEFAULT '[]'::jsonb,
    -- Full serialised request payload for audit
    payload                 JSONB NOT NULL DEFAULT '{}'::jsonb,
    executed_at             TIMESTAMPTZ,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_vault_transfer_requests_status
    ON vault_transfer_requests (status);

CREATE INDEX IF NOT EXISTS idx_vault_transfer_requests_account
    ON vault_transfer_requests (account_id, created_at DESC);

-- ---------------------------------------------------------------------------
-- vault_inbound_deposits — immutable log of inbound NGN deposits
-- Each row triggers the Mint Request Lifecycle (Issue #123).
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS vault_inbound_deposits (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id        TEXT NOT NULL UNIQUE,   -- custodian-assigned idempotency key
    account_id      TEXT NOT NULL REFERENCES vault_accounts(id),
    amount          NUMERIC(20, 2) NOT NULL CHECK (amount > 0),
    currency        TEXT NOT NULL DEFAULT 'NGN',
    sender_name     TEXT,
    sender_account  TEXT,
    reference       TEXT NOT NULL,
    -- 'pending' → mint lifecycle picks it up; 'processed' → cNGN minted
    mint_status     TEXT NOT NULL DEFAULT 'pending',
    received_at     TIMESTAMPTZ NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_vault_inbound_deposits_mint_status
    ON vault_inbound_deposits (mint_status, created_at ASC);

CREATE INDEX IF NOT EXISTS idx_vault_inbound_deposits_account
    ON vault_inbound_deposits (account_id, received_at DESC);
