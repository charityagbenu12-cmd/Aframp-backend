-- migrate:up
-- Redemption Flow Schema for cNGN Token Burn and Fiat Settlement
-- Issues #230, #231, #232, #233
-- Purpose: Create comprehensive schema for the complete redemption lifecycle
-- Requirements:
-- - redemption_requests table for burn authorization and tracking
-- - redemption_batches table for batch processing optimization
-- - fiat_disbursements table for NGN settlement tracking
-- - burn_transactions table for Stellar on-chain burn operations

-- 1. Redemption Statuses
CREATE TABLE redemption_statuses (
    code TEXT PRIMARY KEY,
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE redemption_statuses IS 'Lookup table for redemption request statuses.';
COMMENT ON COLUMN redemption_statuses.code IS 'Machine-readable status code.';
COMMENT ON COLUMN redemption_statuses.description IS 'Human-readable status description.';

INSERT INTO redemption_statuses (code, description) VALUES
    ('REDEMPTION_REQUESTED', 'User has requested to burn cNGN tokens'),
    ('KYC_VERIFICATION', 'Verifying user KYC status'),
    ('BALANCE_VERIFICATION', 'Verifying on-chain cNGN balance'),
    ('BANK_VALIDATION', 'Validating destination bank account'),
    ('TOKENS_LOCKED', 'cNGN tokens moved to escrow/pending burn'),
    ('BURNING_IN_PROGRESS', 'Burn transaction submitted to Stellar'),
    ('BURNED_CONFIRMED', 'Burn transaction confirmed on-chain'),
    ('FIAT_DISBURSEMENT_PENDING', 'Awaiting fiat transfer'),
    ('FIAT_DISBURSED', 'NGN successfully transferred to user'),
    ('MANUAL_REVIEW', 'Requires manual intervention'),
    ('FAILED', 'Redemption process failed'),
    ('CANCELLED', 'Redemption request cancelled');

-- 2. Redemption Requests
CREATE TABLE redemption_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    redemption_id TEXT NOT NULL UNIQUE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    wallet_address VARCHAR(255) NOT NULL REFERENCES wallets(wallet_address) ON UPDATE CASCADE ON DELETE RESTRICT,
    
    -- Request details
    amount_cngn NUMERIC(36, 18) NOT NULL CHECK (amount_cngn > 0),
    amount_ngn NUMERIC(36, 18) NOT NULL CHECK (amount_ngn > 0),
    exchange_rate NUMERIC(36, 18) NOT NULL CHECK (exchange_rate > 0),
    
    -- Destination bank details
    bank_code TEXT NOT NULL,
    bank_name TEXT NOT NULL,
    account_number TEXT NOT NULL,
    account_name TEXT NOT NULL,
    account_name_verified BOOLEAN NOT NULL DEFAULT FALSE,
    
    -- Status tracking
    status TEXT NOT NULL DEFAULT 'REDEMPTION_REQUESTED' REFERENCES redemption_statuses(code),
    previous_status TEXT REFERENCES redemption_statuses(code),
    
    -- Transaction references
    burn_transaction_hash TEXT,
    batch_id UUID REFERENCES redemption_batches(id),
    
    -- Metadata and audit
    kyc_tier TEXT CHECK (kyc_tier IN ('TIER_1', 'TIER_2', 'TIER_3')),
    ip_address INET,
    user_agent TEXT,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    
    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at TIMESTAMPTZ
);

COMMENT ON TABLE redemption_requests IS 'Main table tracking individual cNGN redemption requests.';
COMMENT ON COLUMN redemption_requests.redemption_id IS 'Human-readable unique identifier for traceability.';
COMMENT ON COLUMN redemption_requests.amount_cngn IS 'Amount of cNGN tokens to burn.';
COMMENT ON COLUMN redemption_requests.amount_ngn IS 'Equivalent NGN amount to disburse.';
COMMENT ON COLUMN redemption_requests.exchange_rate IS 'cNGN to NGN exchange rate at time of request.';
COMMENT ON COLUMN redemption_requests.account_name_verified IS 'Whether bank account name was verified via NIBSS.';
COMMENT ON COLUMN redemption_requests.burn_transaction_hash IS 'Stellar transaction hash for the burn operation.';
COMMENT ON COLUMN redemption_requests.batch_id IS 'Reference to batch if this request is part of a batch.';
COMMENT ON COLUMN redemption_requests.kyc_tier IS 'User KYC tier at time of redemption request.';
COMMENT ON COLUMN redemption_requests.completed_at IS 'When the redemption process was fully completed.';

-- 3. Redemption Batches
CREATE TABLE redemption_batches (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    batch_id TEXT NOT NULL UNIQUE,
    
    -- Batch details
    total_requests INTEGER NOT NULL DEFAULT 0,
    total_amount_cngn NUMERIC(36, 18) NOT NULL DEFAULT 0 CHECK (total_amount_cngn >= 0),
    total_amount_ngn NUMERIC(36, 18) NOT NULL DEFAULT 0 CHECK (total_amount_ngn >= 0),
    
    -- Processing details
    batch_type TEXT NOT NULL CHECK (batch_type IN ('TIME_BASED', 'COUNT_BASED', 'MANUAL')),
    trigger_reason TEXT,
    
    -- Status
    status TEXT NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'PROCESSING', 'COMPLETED', 'FAILED', 'PARTIAL')),
    
    -- Transaction references
    stellar_transaction_hash TEXT,
    stellar_ledger INTEGER,
    
    -- Metadata
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    
    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    processed_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ
);

COMMENT ON TABLE redemption_batches IS 'Batch processing for multiple redemption requests.';
COMMENT ON COLUMN redemption_batches.batch_id IS 'Human-readable batch identifier.';
COMMENT ON COLUMN redemption_batches.batch_type IS 'How this batch was triggered.';
COMMENT ON COLUMN redemption_batches.stellar_transaction_hash IS 'Stellar transaction hash for batch burn operation.';
COMMENT ON COLUMN redemption_batches.stellar_ledger IS 'Stellar ledger number where batch was confirmed.';

-- 4. Burn Transactions
CREATE TABLE burn_transactions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    redemption_id UUID NOT NULL REFERENCES redemption_requests(id) ON DELETE CASCADE,
    
    -- Transaction details
    transaction_hash TEXT NOT NULL UNIQUE,
    stellar_ledger INTEGER,
    sequence_number BIGINT,
    
    -- Burn operation details
    burn_type TEXT NOT NULL CHECK (burn_type IN ('PAYMENT_TO_ISSUER', 'CLAWBACK')),
    source_address VARCHAR(255) NOT NULL,
    destination_address VARCHAR(255) NOT NULL, -- Usually the issuer
    amount_cngn NUMERIC(36, 18) NOT NULL CHECK (amount_cngn > 0),
    
    -- Transaction status
    status TEXT NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'SUCCESS', 'FAILED', 'TIMEOUT')),
    
    -- Fees and timing
    fee_paid_stroops INTEGER,
    fee_xlm NUMERIC(36, 18),
    timeout_seconds INTEGER NOT NULL DEFAULT 300,
    
    -- Error handling
    error_code TEXT,
    error_message TEXT,
    retry_count INTEGER NOT NULL DEFAULT 0,
    max_retries INTEGER NOT NULL DEFAULT 3,
    
    -- Transaction XDR
    unsigned_envelope_xdr TEXT,
    signed_envelope_xdr TEXT,
    
    -- Metadata
    memo_text TEXT,
    memo_hash TEXT,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    
    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    submitted_at TIMESTAMPTZ,
    confirmed_at TIMESTAMPTZ
);

COMMENT ON TABLE burn_transactions IS 'Detailed tracking of Stellar burn transactions.';
COMMENT ON COLUMN burn_transactions.burn_type IS 'Type of burn operation used.';
COMMENT ON COLUMN burn_transactions.destination_address IS 'Where the burned tokens were sent.';
COMMENT ON COLUMN burn_transactions.error_code IS 'Stellar error code if transaction failed.';
COMMENT ON COLUMN burn_transactions.unsigned_envelope_xdr IS 'XDR before signing for audit purposes.';
COMMENT ON COLUMN burn_transactions.signed_envelope_xdr IS 'Final signed XDR submitted to network.';
COMMENT ON COLUMN burn_transactions.memo_text IS 'Transaction memo containing redemption_id.';

-- 5. Fiat Disbursements
CREATE TABLE fiat_disbursements (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    redemption_id UUID NOT NULL REFERENCES redemption_requests(id) ON DELETE CASCADE,
    batch_id UUID REFERENCES redemption_batches(id),
    
    -- Disbursement details
    amount_ngn NUMERIC(36, 18) NOT NULL CHECK (amount_ngn > 0),
    bank_code TEXT NOT NULL,
    bank_name TEXT NOT NULL,
    account_number TEXT NOT NULL,
    account_name TEXT NOT NULL,
    
    -- Provider details
    provider TEXT NOT NULL REFERENCES payment_provider_configs(provider),
    provider_reference TEXT UNIQUE, -- Provider's unique transaction reference
    provider_status TEXT,
    
    -- Status tracking
    status TEXT NOT NULL DEFAULT 'PENDING' CHECK (status IN (
        'PENDING', 'PROCESSING', 'SUCCESS', 'FAILED', 
        'MANUAL_REVIEW', 'TIMEOUT', 'REVERSED'
    )),
    
    -- NIBSS specifics
    nibss_transaction_id TEXT,
    nibss_status TEXT,
    beneficiary_account_credits BOOLEAN DEFAULT FALSE,
    
    -- Fees and timing
    provider_fee NUMERIC(36, 18) DEFAULT 0,
    processing_time_seconds INTEGER,
    
    -- Error handling
    error_code TEXT,
    error_message TEXT,
    retry_count INTEGER NOT NULL DEFAULT 0,
    max_retries INTEGER NOT NULL DEFAULT 3,
    
    -- Receipt and documentation
    receipt_url TEXT,
    receipt_pdf_base64 TEXT,
    
    -- Metadata
    idempotency_key TEXT UNIQUE,
    narration TEXT NOT NULL DEFAULT 'cNGN Redemption',
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    
    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    processed_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    last_status_check TIMESTAMPTZ
);

COMMENT ON TABLE fiat_disbursements IS 'NGN fiat disbursement tracking for redeemed cNGN.';
COMMENT ON COLUMN fiat_disbursements.provider_reference IS 'Unique reference from payment provider.';
COMMENT ON COLUMN fiat_disbursements.nibss_transaction_id IS 'NIBSS transaction identifier for tracking.';
COMMENT ON COLUMN fiat_disbursements.beneficiary_account_credits IS 'Confirmed that beneficiary account was credited.';
COMMENT ON COLUMN fiat_disbursements.receipt_pdf_base64 IS 'Base64 encoded PDF receipt for user download.';
COMMENT ON COLUMN fiat_disbursements.idempotency_key IS 'Key to prevent duplicate disbursements (uses redemption_id).';

-- 6. Settlement Accounts (Reserve Health)
CREATE TABLE settlement_accounts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_name TEXT NOT NULL UNIQUE,
    account_number TEXT NOT NULL,
    bank_code TEXT NOT NULL,
    bank_name TEXT NOT NULL,
    
    -- Account type
    account_type TEXT NOT NULL CHECK (account_type IN ('RESERVE', 'OPERATIONAL', 'ESCROW')),
    currency TEXT NOT NULL DEFAULT 'NGN',
    
    -- Balance tracking
    current_balance NUMERIC(36, 18) NOT NULL DEFAULT 0,
    available_balance NUMERIC(36, 18) NOT NULL DEFAULT 0,
    pending_debits NUMERIC(36, 18) NOT NULL DEFAULT 0,
    
    -- Health metrics
    minimum_balance NUMERIC(36, 18) NOT NULL DEFAULT 0,
    is_healthy BOOLEAN NOT NULL DEFAULT TRUE,
    last_balance_check TIMESTAMPTZ,
    
    -- Metadata
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    
    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE settlement_accounts IS 'Reserve account health monitoring for fiat settlements.';
COMMENT ON COLUMN settlement_accounts.available_balance IS 'Balance available for immediate disbursement.';
COMMENT ON COLUMN settlement_accounts.pending_debits IS 'Amount reserved for pending disbursements.';
COMMENT ON COLUMN settlement_accounts.is_healthy IS 'Whether account has sufficient funds for operations.';

-- 7. Audit Trail for Redemption Operations
CREATE TABLE redemption_audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    redemption_id UUID REFERENCES redemption_requests(id) ON DELETE CASCADE,
    batch_id UUID REFERENCES redemption_batches(id),
    burn_transaction_id UUID REFERENCES burn_transactions(id) ON DELETE CASCADE,
    disbursement_id UUID REFERENCES fiat_disbursements(id) ON DELETE CASCADE,
    
    -- Event details
    event_type TEXT NOT NULL,
    previous_status TEXT,
    new_status TEXT,
    
    -- Event data
    event_data JSONB NOT NULL DEFAULT '{}'::jsonb,
    
    -- Context
    user_id UUID REFERENCES users(id),
    ip_address INET,
    user_agent TEXT,
    
    -- System context
    worker_id TEXT,
    service_name TEXT,
    
    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE redemption_audit_log IS 'Comprehensive audit trail for all redemption operations.';
COMMENT ON COLUMN redemption_audit_log.event_type IS 'Type of event (e.g., STATUS_CHANGE, BURN_SUBMITTED, DISBURSEMENT_COMPLETED).';
COMMENT ON COLUMN redemption_audit_log.event_data IS 'Additional event-specific data.';
COMMENT ON COLUMN redemption_audit_log.worker_id IS 'Background worker that processed the event.';

-- Triggers for updated_at
CREATE TRIGGER set_updated_at_redemption_statuses
    BEFORE UPDATE ON redemption_statuses
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER set_updated_at_redemption_requests
    BEFORE UPDATE ON redemption_requests
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER set_updated_at_redemption_batches
    BEFORE UPDATE ON redemption_batches
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER set_updated_at_burn_transactions
    BEFORE UPDATE ON burn_transactions
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER set_updated_at_fiat_disbursements
    BEFORE UPDATE ON fiat_disbursements
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER set_updated_at_settlement_accounts
    BEFORE UPDATE ON settlement_accounts
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Indexes for performance optimization
CREATE INDEX idx_redemption_requests_user_id ON redemption_requests(user_id);
CREATE INDEX idx_redemption_requests_wallet_address ON redemption_requests(wallet_address);
CREATE INDEX idx_redemption_requests_status ON redemption_requests(status);
CREATE INDEX idx_redemption_requests_created_at ON redemption_requests(created_at);
CREATE INDEX idx_redemption_requests_redemption_id ON redemption_requests(redemption_id);
CREATE INDEX idx_redemption_requests_bank_account ON redemption_requests(bank_code, account_number);
CREATE INDEX idx_redemption_requests_status_created ON redemption_requests(status, created_at);

CREATE INDEX idx_redemption_batches_status ON redemption_batches(status);
CREATE INDEX idx_redemption_batches_created_at ON redemption_batches(created_at);
CREATE INDEX idx_redemption_batches_batch_id ON redemption_batches(batch_id);

CREATE INDEX idx_burn_transactions_redemption_id ON burn_transactions(redemption_id);
CREATE INDEX idx_burn_transactions_transaction_hash ON burn_transactions(transaction_hash);
CREATE INDEX idx_burn_transactions_status ON burn_transactions(status);
CREATE INDEX idx_burn_transactions_created_at ON burn_transactions(created_at);

CREATE INDEX idx_fiat_disbursements_redemption_id ON fiat_disbursements(redemption_id);
CREATE INDEX idx_fiat_disbursements_provider_reference ON fiat_disbursements(provider_reference);
CREATE INDEX idx_fiat_disbursements_status ON fiat_disbursements(status);
CREATE INDEX idx_fiat_disbursements_provider ON fiat_disbursements(provider, status);
CREATE INDEX idx_fiat_disbursements_idempotency_key ON fiat_disbursements(idempotency_key);
CREATE INDEX idx_fiat_disbursements_created_at ON fiat_disbursements(created_at);

CREATE INDEX idx_settlement_accounts_healthy ON settlement_accounts(is_healthy, account_type);
CREATE INDEX idx_settlement_accounts_last_check ON settlement_accounts(last_balance_check);

CREATE INDEX idx_redemption_audit_log_redemption_id ON redemption_audit_log(redemption_id);
CREATE INDEX idx_redemption_audit_log_batch_id ON redemption_audit_log(batch_id);
CREATE INDEX idx_redemption_audit_log_event_type ON redemption_audit_log(event_type);
CREATE INDEX idx_redemption_audit_log_created_at ON redemption_audit_log(created_at);

-- Foreign key constraints for data integrity
ALTER TABLE redemption_requests 
    ADD CONSTRAINT fk_redemption_requests_user 
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;

ALTER TABLE redemption_requests 
    ADD CONSTRAINT fk_redemption_requests_wallet 
    FOREIGN KEY (wallet_address) REFERENCES wallets(wallet_address) ON UPDATE CASCADE ON DELETE RESTRICT;

-- Row Level Security (RLS) for sensitive data
ALTER TABLE redemption_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE fiat_disbursements ENABLE ROW LEVEL SECURITY;
ALTER TABLE settlement_accounts ENABLE ROW LEVEL SECURITY;

-- RLS Policies (basic - can be enhanced based on requirements)
CREATE POLICY redemption_requests_user_policy ON redemption_requests
    FOR SELECT USING (user_id = current_setting('app.current_user_id', true)::UUID);

CREATE POLICY fiat_disbursements_user_policy ON fiat_disbursements
    FOR SELECT USING (
        redemption_id IN (
            SELECT id FROM redemption_requests 
            WHERE user_id = current_setting('app.current_user_id', true)::UUID
        )
    );

-- migrate:down
-- Drop tables in reverse order of creation
DROP TABLE IF EXISTS redemption_audit_log;
DROP TABLE IF EXISTS settlement_accounts;
DROP TABLE IF EXISTS fiat_disbursements;
DROP TABLE IF EXISTS burn_transactions;
DROP TABLE IF EXISTS redemption_batches;
DROP TABLE IF EXISTS redemption_requests;
DROP TABLE IF EXISTS redemption_statuses;
