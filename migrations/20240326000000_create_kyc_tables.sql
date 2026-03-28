-- Create KYC related enums and tables

-- KYC Tier enum
CREATE TYPE kyc_tier AS ENUM (
    'unverified',
    'basic',
    'standard',
    'enhanced'
);

-- KYC Status enum
CREATE TYPE kyc_status AS ENUM (
    'pending',
    'approved',
    'rejected',
    'manual_review',
    'expired'
);

-- Document Type enum
CREATE TYPE document_type AS ENUM (
    'national_id',
    'passport',
    'drivers_license',
    'utility_bill',
    'bank_statement',
    'government_letter',
    'source_of_funds',
    'business_registration'
);

-- Document Status enum
CREATE TYPE document_status AS ENUM (
    'pending',
    'approved',
    'rejected',
    'expired'
);

-- KYC Event Type enum
CREATE TYPE kyc_event_type AS ENUM (
    'session_initiated',
    'document_submitted',
    'selfie_submitted',
    'provider_callback',
    'status_updated',
    'manual_review_assigned',
    'decision_made',
    'tier_changed',
    'limits_updated',
    'resubmission_allowed',
    'enhanced_due_diligence_triggered'
);

-- EDD Status enum
CREATE TYPE edd_status AS ENUM (
    'active',
    'under_review',
    'resolved',
    'escalated'
);

-- KYC Records table
CREATE TABLE kyc_records (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    consumer_id UUID NOT NULL REFERENCES consumers(id) ON DELETE CASCADE,
    tier kyc_tier NOT NULL DEFAULT 'unverified',
    status kyc_status NOT NULL DEFAULT 'pending',
    verification_provider VARCHAR(100),
    verification_session_id VARCHAR(255),
    verification_decision VARCHAR(100),
    decision_timestamp TIMESTAMP WITH TIME ZONE,
    decision_reason TEXT,
    reviewer_identity UUID REFERENCES admin_users(id),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE,
    resubmission_allowed_at TIMESTAMP WITH TIME ZONE,
    enhanced_due_diligence_active BOOLEAN NOT NULL DEFAULT FALSE,
    effective_tier kyc_tier NOT NULL DEFAULT 'unverified'
);

-- KYC Documents table
CREATE TABLE kyc_documents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    kyc_record_id UUID NOT NULL REFERENCES kyc_records(id) ON DELETE CASCADE,
    document_type document_type NOT NULL,
    document_number VARCHAR(100),
    issuing_country VARCHAR(3), -- ISO 3166-1 alpha-3
    expiry_date TIMESTAMP WITH TIME ZONE,
    front_image_reference VARCHAR(500),
    back_image_reference VARCHAR(500),
    selfie_image_reference VARCHAR(500),
    verification_outcome document_status,
    rejection_reason TEXT,
    provider_document_id VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- KYC Events table
CREATE TABLE kyc_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    consumer_id UUID NOT NULL REFERENCES consumers(id) ON DELETE CASCADE,
    kyc_record_id UUID REFERENCES kyc_records(id) ON DELETE CASCADE,
    event_type kyc_event_type NOT NULL,
    event_detail TEXT,
    provider_response TEXT,
    metadata JSONB,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- KYC Tier Definitions table
CREATE TABLE kyc_tier_definitions (
    tier kyc_tier PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    required_documents document_type[] NOT NULL DEFAULT '{}',
    max_transaction_amount DECIMAL(20,8) NOT NULL DEFAULT 0,
    daily_volume_limit DECIMAL(20,8) NOT NULL DEFAULT 0,
    monthly_volume_limit DECIMAL(20,8) NOT NULL DEFAULT 0,
    requires_enhanced_due_diligence BOOLEAN NOT NULL DEFAULT FALSE,
    cooling_off_period_days INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Manual Review Queue table
CREATE TABLE manual_review_queue (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    kyc_record_id UUID NOT NULL REFERENCES kyc_records(id) ON DELETE CASCADE,
    consumer_id UUID NOT NULL REFERENCES consumers(id) ON DELETE CASCADE,
    priority INTEGER NOT NULL DEFAULT 1,
    assigned_to UUID REFERENCES admin_users(id),
    review_reason TEXT NOT NULL,
    provider_risk_score INTEGER,
    provider_flags JSONB,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    assigned_at TIMESTAMP WITH TIME ZONE,
    resolved_at TIMESTAMP WITH TIME ZONE
);

-- KYC Volume Trackers table
CREATE TABLE kyc_volume_trackers (
    consumer_id UUID NOT NULL REFERENCES consumers(id) ON DELETE CASCADE,
    date DATE NOT NULL,
    daily_volume DECIMAL(20,8) NOT NULL DEFAULT 0,
    monthly_volume DECIMAL(20,8) NOT NULL DEFAULT 0,
    transaction_count INTEGER NOT NULL DEFAULT 0,
    last_updated TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    PRIMARY KEY (consumer_id, date)
);

-- Enhanced Due Diligence Cases table
CREATE TABLE enhanced_due_diligence_cases (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    consumer_id UUID NOT NULL REFERENCES consumers(id) ON DELETE CASCADE,
    kyc_record_id UUID NOT NULL REFERENCES kyc_records(id) ON DELETE CASCADE,
    trigger_reason TEXT NOT NULL,
    risk_factors TEXT[] NOT NULL DEFAULT '{}',
    status edd_status NOT NULL DEFAULT 'active',
    assigned_to UUID REFERENCES admin_users(id),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    resolved_at TIMESTAMP WITH TIME ZONE,
    notes TEXT
);

-- KYC Decisions table
CREATE TABLE kyc_decisions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    kyc_record_id UUID NOT NULL REFERENCES kyc_records(id) ON DELETE CASCADE,
    decision kyc_status NOT NULL,
    reason TEXT NOT NULL,
    made_by UUID REFERENCES admin_users(id),
    provider_response TEXT,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    previous_tier kyc_tier,
    new_tier kyc_tier
);

-- Indexes for performance
CREATE INDEX idx_kyc_records_consumer_id ON kyc_records(consumer_id);
CREATE INDEX idx_kyc_records_status ON kyc_records(status);
CREATE INDEX idx_kyc_records_tier ON kyc_records(tier);
CREATE INDEX idx_kyc_records_created_at ON kyc_records(created_at);
CREATE INDEX idx_kyc_documents_kyc_record_id ON kyc_documents(kyc_record_id);
CREATE INDEX idx_kyc_documents_type ON kyc_documents(document_type);
CREATE INDEX idx_kyc_events_consumer_id ON kyc_events(consumer_id);
CREATE INDEX idx_kyc_events_timestamp ON kyc_events(timestamp);
CREATE INDEX idx_kyc_events_type ON kyc_events(event_type);
CREATE INDEX idx_manual_review_queue_status ON manual_review_queue(resolved_at);
CREATE INDEX idx_manual_review_queue_priority ON manual_review_queue(priority, created_at);
CREATE INDEX idx_kyc_volume_trackers_consumer_date ON kyc_volume_trackers(consumer_id, date);
CREATE INDEX idx_edd_cases_consumer_id ON enhanced_due_diligence_cases(consumer_id);
CREATE INDEX idx_edd_cases_status ON enhanced_due_diligence_cases(status);

-- Insert default KYC tier definitions
INSERT INTO kyc_tier_definitions (tier, name, description, required_documents, max_transaction_amount, daily_volume_limit, monthly_volume_limit, requires_enhanced_due_diligence, cooling_off_period_days) VALUES
('unverified', 'Tier 0 - Unverified', 'Sandbox and read-only access only', ARRAY[]::document_type[], 0, 0, 0, false, 0),
('basic', 'Tier 1 - Basic', 'Basic identity verification with limited transaction volumes', ARRAY['national_id', 'passport', 'drivers_license']::document_type[], 1000.00, 5000.00, 50000.00, false, 7),
('standard', 'Tier 2 - Standard', 'Full identity and address verification with standard transaction volumes', ARRAY['national_id', 'passport', 'drivers_license', 'utility_bill', 'bank_statement', 'government_letter']::document_type[], 10000.00, 50000.00, 500000.00, false, 14),
('enhanced', 'Tier 3 - Enhanced', 'Enhanced due diligence with elevated transaction volumes for high-value consumers', ARRAY['national_id', 'passport', 'drivers_license', 'utility_bill', 'bank_statement', 'government_letter', 'source_of_funds', 'business_registration']::document_type[], 100000.00, 500000.00, 5000000.00, true, 30);

-- Add updated_at trigger function
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Add triggers for updated_at columns
CREATE TRIGGER update_kyc_records_updated_at BEFORE UPDATE ON kyc_records FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_kyc_documents_updated_at BEFORE UPDATE ON kyc_documents FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_kyc_tier_definitions_updated_at BEFORE UPDATE ON kyc_tier_definitions FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
