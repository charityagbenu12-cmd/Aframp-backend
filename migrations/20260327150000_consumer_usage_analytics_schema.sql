-- migrate:up
-- Consumer Usage Analytics Schema
-- Creates tables for usage snapshots, anomalies, reports, and health scores

-- Snapshot period types
CREATE TABLE snapshot_periods (
    code TEXT PRIMARY KEY,
    description TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE snapshot_periods IS 'Lookup table for snapshot period types';

INSERT INTO snapshot_periods (code, description) VALUES
    ('hourly', 'Hourly aggregation period'),
    ('daily', 'Daily aggregation period'),
    ('monthly', 'Monthly aggregation period');

-- Endpoint categories for grouping
CREATE TABLE endpoint_categories (
    code TEXT PRIMARY KEY,
    description TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE endpoint_categories IS 'Lookup table for endpoint categories';

INSERT INTO endpoint_categories (code, description) VALUES
    ('onramp', 'On-ramp transaction endpoints'),
    ('offramp', 'Off-ramp transaction endpoints'),
    ('rates', 'Exchange rate endpoints'),
    ('fees', 'Fee calculation endpoints'),
    ('bills', 'Bill payment endpoints'),
    ('wallet', 'Wallet management endpoints'),
    ('webhooks', 'Webhook management endpoints'),
    ('auth', 'Authentication endpoints'),
    ('admin', 'Admin endpoints'),
    ('other', 'Other endpoints');

-- Usage snapshot records
CREATE TABLE usage_snapshots (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id UUID NOT NULL REFERENCES developer_applications(id) ON DELETE CASCADE,
    snapshot_period TEXT NOT NULL REFERENCES snapshot_periods(code),
    period_start TIMESTAMPTZ NOT NULL,
    period_end TIMESTAMPTZ NOT NULL,
    endpoint_category TEXT NOT NULL REFERENCES endpoint_categories(code),
    environment TEXT NOT NULL CHECK (environment IN ('sandbox', 'production')),
    
    -- Request metrics
    request_count BIGINT NOT NULL DEFAULT 0,
    success_count BIGINT NOT NULL DEFAULT 0,
    error_count BIGINT NOT NULL DEFAULT 0,
    
    -- Latency metrics (in milliseconds)
    total_latency_ms BIGINT NOT NULL DEFAULT 0,
    p50_latency_ms INTEGER,
    p95_latency_ms INTEGER,
    p99_latency_ms INTEGER,
    
    -- Volume metrics
    total_cngn_volume NUMERIC(20, 2) DEFAULT 0.00,
    total_fiat_vo