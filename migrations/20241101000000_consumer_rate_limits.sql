-- Migration: Consumer Rate Limiting Tables (Issue #175)
-- Adds per-consumer-type profiles and admin overrides for advanced rate limiting

-- 1. Consumer Rate Limit Profiles (by consumer_type)
CREATE TABLE IF NOT EXISTS consumer_rate_limit_profiles (
    consumer_type VARCHAR(50) PRIMARY KEY,
    limits_json   JSONB NOT NULL,  -- {global: {limit:10,window:60,burst:2}, endpoint_standard:..., etc.}
    burst_multiplier DECIMAL(4,2) DEFAULT 2.0 CHECK (burst_multiplier >= 1.0),
    created_at    TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at    TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- Indexes
CREATE INDEX idx_consumer_profiles_type ON consumer_rate_limit_profiles (consumer_type);

-- 2. Consumer Rate Limit Overrides (admin customizations)
CREATE TABLE IF NOT EXISTS consumer_rate_limit_overrides (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    consumer_id   UUID NOT NULL REFERENCES consumers(id) ON DELETE CASCADE,
    limits_json   JSONB NOT NULL,
    expiry_at     TIMESTAMPTZ,  -- NULL = permanent
    created_by    UUID REFERENCES admin_accounts(id),  -- Optional FK
    reason        TEXT,
    created_at    TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at    TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT chk_override_expiry CHECK (expiry_at IS NULL OR expiry_at > CURRENT_TIMESTAMP)
);

-- Indexes
CREATE UNIQUE INDEX idx_override_consumer_active 
    ON consumer_rate_limit_overrides (consumer_id) 
    WHERE expiry_at IS NULL OR expiry_at > CURRENT_TIMESTAMP;

CREATE INDEX idx_override_expiry ON consumer_rate_limit_overrides (expiry_at);
CREATE INDEX idx_override_consumer ON consumer_rate_limit_overrides (consumer_id);

-- Sample Profiles (seed data for common types from requirements)
INSERT INTO consumer_rate_limit_profiles (consumer_type, limits_json, burst_multiplier) VALUES
-- Mobile Client: Conservative (sustained low-volume)
('mobile_client', 
 '{
   "global": {"limit": 10, "window": 60},
   "endpoint_standard": {"limit": 5, "window": 60},
   "endpoint_elevated": {"limit": 2, "window": 60},
   "endpoint_critical": {"limit": 1, "window": 60, "allow_burst": false},
   "tx_onramp": {"limit": 3, "window": 3600},
   "ip": {"limit": 50, "window": 60}
 }'::jsonb, 1.5),

-- Partner: Higher sustained + burst
('partner', 
 '{
   "global": {"limit": 100, "window": 60},
   "endpoint_standard": {"limit": 50, "window": 60},
   "endpoint_elevated": {"limit": 20, "window": 60},
   "endpoint_critical": {"limit": 5, "window": 60, "allow_burst": false},
   "tx_onramp": {"limit": 20, "window": 3600},
   "ip": {"limit": 200, "window": 60}
 }'::jsonb, 3.0),

-- Microservice: High burst tolerance
('microservice', 
 '{
   "global": {"limit": 500, "window": 60},
   "endpoint_standard": {"limit": 200, "window": 60},
   "endpoint_elevated": {"limit": 100, "window": 60},
   "endpoint_critical": {"limit": 20, "window": 60, "allow_burst": false},
   "tx_onramp": {"limit": 100, "window": 3600},
   "ip": {"limit": 1000, "window": 60}
 }'::jsonb, 5.0),

-- Admin: Unlimited-ish
('admin', 
 '{
   "global": {"limit": 10000, "window": 60},
   "endpoint_standard": {"limit": 5000, "window": 60},
   "endpoint_elevated": {"limit": 2000, "window": 60},
   "endpoint_critical": {"limit": 1000, "window": 60},
   "tx_onramp": {"limit": 5000, "window": 3600},
   "ip": {"limit": 10000, "window": 60}
 }'::jsonb, 10.0)
ON CONFLICT (consumer_type) DO NOTHING;

-- Functions for merging profile + override (for middleware)
CREATE OR REPLACE FUNCTION get_effective_rate_limits(consumer_id UUID)
RETURNS JSONB
LANGUAGE sql STABLE
AS $$
    SELECT COALESCE(overrides.limits_json, profiles.limits_json) as effective_limits
    FROM consumer_rate_limit_profiles profiles
    LEFT JOIN LATERAL (
        SELECT limits_json
        FROM consumer_rate_limit_overrides 
        WHERE consumer_rate_limit_overrides.consumer_id = get_effective_rate_limits.consumer_id
          AND (expiry_at IS NULL OR expiry_at > CURRENT_TIMESTAMP)
        ORDER BY created_at DESC
        LIMIT 1
    ) overrides ON true
    CROSS JOIN LATERAL (
        SELECT c.consumer_type
        FROM consumers c 
        WHERE c.id = get_effective_rate_limits.consumer_id
    ) consumer_type_cte
    WHERE profiles.consumer_type = consumer_type_cte.consumer_type;
$$;

-- Trigger: Auto-cleanup expired overrides
CREATE OR REPLACE FUNCTION cleanup_expired_overrides()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    DELETE FROM consumer_rate_limit_overrides 
    WHERE expiry_at IS NOT NULL AND expiry_at <= CURRENT_TIMESTAMP;
    RETURN NULL;
END;
$$;

CREATE TRIGGER trigger_cleanup_rate_limit_overrides
    AFTER INSERT OR UPDATE ON consumer_rate_limit_overrides
    FOR EACH STATEMENT
    EXECUTE FUNCTION cleanup_expired_overrides();

