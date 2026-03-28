-- Migration: Create IP reputation and evidence tracking schema for Issue #166
-- Suspicious IP Detection & Automated Blocking

-- Create enum types for IP reputation system
CREATE TYPE ip_block_type AS ENUM ('temporary', 'permanent', 'shadow');
CREATE TYPE evidence_type AS ENUM (
    'auth_failure_rate',
    'signature_verification_failure',
    'rate_limit_breach',
    'impossible_travel',
    'new_ip_high_value_transaction',
    'scanning_pattern',
    'external_threat_feed'
);

-- IP Reputation Record Table
-- Stores reputation scores and block status for IP addresses/CIDR ranges
CREATE TABLE ip_reputation_records (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ip_address_or_cidr INET NOT NULL UNIQUE,
    reputation_score DECIMAL(5,2) NOT NULL DEFAULT 0.00 CHECK (reputation_score >= -100.00 AND reputation_score <= 100.00),
    detection_source TEXT NOT NULL, -- 'internal', 'external', 'manual', 'automated'
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    block_status ip_block_type,
    block_expiry_at TIMESTAMPTZ,
    is_whitelisted BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Evidence Records Table
-- Stores individual evidence instances that contributed to reputation scoring
CREATE TABLE ip_evidence_records (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ip_address_or_cidr INET NOT NULL,
    evidence_type evidence_type NOT NULL,
    evidence_detail JSONB NOT NULL DEFAULT '{}', -- Flexible storage for evidence-specific data
    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    consumer_id UUID, -- Reference to consumer if applicable
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Foreign key constraint (optional, allows evidence without reputation record)
    CONSTRAINT fk_ip_evidence_reputation
        FOREIGN KEY (ip_address_or_cidr)
        REFERENCES ip_reputation_records(ip_address_or_cidr)
        ON DELETE CASCADE
);

-- Indexes for performance
CREATE INDEX idx_ip_reputation_records_ip ON ip_reputation_records(ip_address_or_cidr);
CREATE INDEX idx_ip_reputation_records_score ON ip_reputation_records(reputation_score);
CREATE INDEX idx_ip_reputation_records_block_status ON ip_reputation_records(block_status);
CREATE INDEX idx_ip_reputation_records_whitelisted ON ip_reputation_records(is_whitelisted);
CREATE INDEX idx_ip_reputation_records_last_seen ON ip_reputation_records(last_seen_at);

CREATE INDEX idx_ip_evidence_records_ip ON ip_evidence_records(ip_address_or_cidr);
CREATE INDEX idx_ip_evidence_records_type ON ip_evidence_records(evidence_type);
CREATE INDEX idx_ip_evidence_records_detected_at ON ip_evidence_records(detected_at);
CREATE INDEX idx_ip_evidence_records_consumer ON ip_evidence_records(consumer_id);

-- Composite indexes for common queries
CREATE INDEX idx_ip_reputation_records_active_blocks
ON ip_reputation_records(block_status, block_expiry_at)
WHERE block_status IS NOT NULL AND (block_expiry_at IS NULL OR block_expiry_at > NOW());

CREATE INDEX idx_ip_evidence_records_ip_type_detected
ON ip_evidence_records(ip_address_or_cidr, evidence_type, detected_at DESC);

-- Function to update last_seen_at timestamp
CREATE OR REPLACE FUNCTION update_ip_reputation_last_seen()
RETURNS TRIGGER AS $$
BEGIN
    UPDATE ip_reputation_records
    SET last_seen_at = NOW(), updated_at = NOW()
    WHERE ip_address_or_cidr = NEW.ip_address_or_cidr;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger to automatically update last_seen_at when evidence is added
CREATE TRIGGER trigger_update_ip_last_seen
    AFTER INSERT ON ip_evidence_records
    FOR EACH ROW
    EXECUTE FUNCTION update_ip_reputation_last_seen();

-- Function to automatically update updated_at timestamp
CREATE OR REPLACE FUNCTION update_ip_reputation_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger to automatically update updated_at on reputation record changes
CREATE TRIGGER trigger_update_ip_reputation_updated_at
    BEFORE UPDATE ON ip_reputation_records
    FOR EACH ROW
    EXECUTE FUNCTION update_ip_reputation_updated_at();