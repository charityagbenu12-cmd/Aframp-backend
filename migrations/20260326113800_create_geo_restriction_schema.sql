-- Migration: Create geo-restriction and country-level access control schema for Issue #167
-- Geo-restriction & Country-level Access Controls

-- Create enum types for geo-restriction system
CREATE TYPE access_level AS ENUM ('allowed', 'restricted', 'blocked');
CREATE TYPE override_type AS ENUM ('allow', 'block');
CREATE TYPE transaction_type AS ENUM (
    'onramp',
    'offramp',
    'bill_payment',
    'batch_transfer',
    'wallet_balance',
    'exchange_rate',
    'fee_calculation',
    'read_only'
);

-- Country Access Policy Table
-- Stores access policies for each country
CREATE TABLE country_access_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    country_code CHAR(2) NOT NULL UNIQUE, -- ISO 3166-1 alpha-2
    country_name VARCHAR(100) NOT NULL,
    access_level access_level NOT NULL DEFAULT 'allowed',
    restriction_reason TEXT,
    applicable_transaction_types transaction_type[] DEFAULT ARRAY[]::transaction_type[],
    enhanced_verification_required BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Region Grouping Table
-- Groups countries into regions with regional policies
CREATE TABLE region_groupings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    region_name VARCHAR(100) NOT NULL UNIQUE,
    member_country_codes CHAR(2)[] NOT NULL DEFAULT ARRAY[]::CHAR(2)[],
    access_level access_level,
    restriction_reason TEXT,
    applicable_transaction_types transaction_type[] DEFAULT ARRAY[]::transaction_type[],
    enhanced_verification_required BOOLEAN,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Consumer Geo-Override Table
-- Stores consumer-specific overrides for country policies
CREATE TABLE consumer_geo_overrides (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    consumer_id UUID NOT NULL,
    country_code CHAR(2) NOT NULL,
    override_type override_type NOT NULL,
    override_reason TEXT NOT NULL,
    granted_by_admin_id UUID NOT NULL,
    expiry_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Ensure no duplicate active overrides for same consumer-country
    UNIQUE (consumer_id, country_code),
    -- Foreign key constraint (optional, allows overrides for non-existent consumers)
    CONSTRAINT fk_consumer_geo_override_consumer
        FOREIGN KEY (consumer_id)
        REFERENCES consumers(id)
        ON DELETE CASCADE
);

-- Geo-Restriction Audit Table
-- Audit log for all geo-restriction enforcement decisions
CREATE TABLE geo_restriction_audit (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_ip INET NOT NULL,
    resolved_country_code CHAR(2),
    applied_policy TEXT NOT NULL, -- JSON representation of applied policy
    access_decision VARCHAR(50) NOT NULL, -- 'allowed', 'blocked', 'restricted', 'enhanced_verification'
    consumer_id UUID,
    endpoint VARCHAR(255),
    transaction_type transaction_type,
    user_agent TEXT,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX idx_country_access_policies_country_code ON country_access_policies(country_code);
CREATE INDEX idx_country_access_policies_access_level ON country_access_policies(access_level);

CREATE INDEX idx_region_groupings_region_name ON region_groupings(region_name);
CREATE INDEX idx_region_groupings_member_countries ON region_groupings USING GIN(member_country_codes);

CREATE INDEX idx_consumer_geo_overrides_consumer_id ON consumer_geo_overrides(consumer_id);
CREATE INDEX idx_consumer_geo_overrides_country_code ON consumer_geo_overrides(country_code);
CREATE INDEX idx_consumer_geo_overrides_expiry ON consumer_geo_overrides(expiry_at) WHERE expiry_at IS NOT NULL;

CREATE INDEX idx_geo_restriction_audit_request_ip ON geo_restriction_audit(request_ip);
CREATE INDEX idx_geo_restriction_audit_country_code ON geo_restriction_audit(resolved_country_code);
CREATE INDEX idx_geo_restriction_audit_consumer_id ON geo_restriction_audit(consumer_id);
CREATE INDEX idx_geo_restriction_audit_timestamp ON geo_restriction_audit(timestamp DESC);
CREATE INDEX idx_geo_restriction_audit_decision ON geo_restriction_audit(access_decision);

-- Composite indexes for common queries
CREATE INDEX idx_geo_restriction_audit_ip_country_timestamp
ON geo_restriction_audit(request_ip, resolved_country_code, timestamp DESC);

CREATE INDEX idx_consumer_geo_overrides_active
ON consumer_geo_overrides(consumer_id, country_code, expiry_at)
WHERE expiry_at IS NULL OR expiry_at > NOW();

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_country_policy_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Function to update region grouping updated_at timestamp
CREATE OR REPLACE FUNCTION update_region_grouping_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Triggers for automatic timestamp updates
CREATE TRIGGER trigger_update_country_policy_updated_at
    BEFORE UPDATE ON country_access_policies
    FOR EACH ROW
    EXECUTE FUNCTION update_country_policy_updated_at();

CREATE TRIGGER trigger_update_region_grouping_updated_at
    BEFORE UPDATE ON region_groupings
    FOR EACH ROW
    EXECUTE FUNCTION update_region_grouping_updated_at();

-- Insert default policies for common scenarios
-- Note: These are examples - actual policies should be configured based on business requirements
INSERT INTO country_access_policies (country_code, country_name, access_level, restriction_reason) VALUES
('US', 'United States', 'blocked', 'Regulatory compliance - US financial restrictions'),
('CN', 'China', 'restricted', 'Enhanced verification required', '["onramp","offramp","bill_payment"]'),
('NG', 'Nigeria', 'allowed', NULL),
('GH', 'Ghana', 'allowed', NULL),
('KE', 'Kenya', 'allowed', NULL),
('ZA', 'South Africa', 'allowed', NULL);

-- Insert default region groupings
INSERT INTO region_groupings (region_name, member_country_codes, access_level) VALUES
('West Africa', ARRAY['NG','GH','CI','SN','BF'], 'allowed'),
('East Africa', ARRAY['KE','TZ','UG','RW','ET'], 'allowed'),
('Southern Africa', ARRAY['ZA','ZW','MZ','BW','NA'], 'allowed'),
('North Africa', ARRAY['MA','TN','EG','DZ','LY'], 'restricted');

-- Create a view for active consumer overrides (non-expired)
CREATE VIEW active_consumer_geo_overrides AS
SELECT * FROM consumer_geo_overrides
WHERE expiry_at IS NULL OR expiry_at > NOW();