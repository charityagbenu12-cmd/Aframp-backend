-- Consumer Usage Analytics & Reporting System
-- Comprehensive business-level analytics for API consumer adoption, health, and revenue attribution.

-- ── Consumer tier enum ──────────────────────────────────────────────────────
CREATE TYPE consumer_tier AS ENUM (
    'free',
    'starter',
    'professional',
    'enterprise'
);

-- ── Snapshot period enum ─────────────────────────────────────────────────────
CREATE TYPE snapshot_period AS ENUM (
    'hourly',
    'daily',
    'weekly',
    'monthly'
);

-- ── Health score trend enum ──────────────────────────────────────────────────
CREATE TYPE health_trend AS ENUM (
    'improving',
    'stable',
    'declining'
);

-- ── Consumer usage snapshots (time-series aggregates) ────────────────────────
CREATE TABLE consumer_usage_snapshots (
    id                      UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    consumer_id             TEXT        NOT NULL,
    consumer_tier           consumer_tier NOT NULL DEFAULT 'free',
    snapshot_period         snapshot_period NOT NULL,
    period_start            TIMESTAMPTZ NOT NULL,
    period_end              TIMESTAMPTZ NOT NULL,
    
    -- Request metrics
    total_requests          BIGINT      NOT NULL DEFAULT 0,
    successful_requests     BIGINT      NOT NULL DEFAULT 0,
    failed_requests         BIGINT      NOT NULL DEFAULT 0,
    error_rate              NUMERIC(5,4) NOT NULL DEFAULT 0.0,
    
    -- Performance metrics
    p50_response_time_ms    INTEGER     NOT NULL DEFAULT 0,
    p99_response_time_ms    INTEGER     NOT NULL DEFAULT 0,
    avg_response_time_ms    INTEGER     NOT NULL DEFAULT 0,
    
    -- Rate limiting
    rate_limit_breaches     INTEGER     NOT NULL DEFAULT 0,
    
    -- Feature usage
    unique_endpoints        INTEGER     NOT NULL DEFAULT 0,
    
    -- Timestamps
    snapshot_timestamp      TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    
    UNIQUE (consumer_id, snapshot_period, period_start)
);

CREATE INDEX idx_consumer_usage_snapshots_consumer ON consumer_usage_snapshots (consumer_id, period_start DESC);
CREATE INDEX idx_consumer_usage_snapshots_period ON consumer_usage_snapshots (snapshot_period, period_start DESC);
CREATE INDEX idx_consumer_usage_snapshots_tier ON consumer_usage_snapshots (consumer_tier, period_start DESC);

-- ── Endpoint usage breakdown ─────────────────────────────────────────────────
CREATE TABLE consumer_endpoint_usage (
    id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    consumer_id         TEXT        NOT NULL,
    endpoint_path       TEXT        NOT NULL,
    http_method         TEXT        NOT NULL,
    snapshot_period     snapshot_period NOT NULL,
    period_start        TIMESTAMPTZ NOT NULL,
    period_end          TIMESTAMPTZ NOT NULL,
    
    -- Metrics
    request_count       BIGINT      NOT NULL DEFAULT 0,
    success_count       BIGINT      NOT NULL DEFAULT 0,
    error_count         BIGINT      NOT NULL DEFAULT 0,
    avg_latency_ms      INTEGER     NOT NULL DEFAULT 0,
    
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    
    UNIQUE (consumer_id, endpoint_path, http_method, snapshot_period, period_start)
);

CREATE INDEX idx_consumer_endpoint_usage_consumer ON consumer_endpoint_usage (consumer_id, period_start DESC);
CREATE INDEX idx_consumer_endpoint_usage_endpoint ON consumer_endpoint_usage (endpoint_path, period_start DESC);

-- ── Feature adoption tracking ────────────────────────────────────────────────
CREATE TABLE consumer_feature_adoption (
    id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    consumer_id         TEXT        NOT NULL,
    feature_name        TEXT        NOT NULL,
    first_used_at       TIMESTAMPTZ NOT NULL,
    last_used_at        TIMESTAMPTZ NOT NULL,
    total_usage_count   BIGINT      NOT NULL DEFAULT 1,
    is_active           BOOLEAN     NOT NULL DEFAULT true,
    
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    
    UNIQUE (consumer_id, feature_name)
);

CREATE INDEX idx_consumer_feature_adoption_consumer ON consumer_feature_adoption (consumer_id);
CREATE INDEX idx_consumer_feature_adoption_feature ON consumer_feature_adoption (feature_name, is_active);
CREATE INDEX idx_consumer_feature_adoption_last_used ON consumer_feature_adoption (last_used_at DESC);

-- ── Consumer health scores ───────────────────────────────────────────────────
CREATE TABLE consumer_health_scores (
    id                      UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    consumer_id             TEXT        NOT NULL,
    health_score            INTEGER     NOT NULL CHECK (health_score >= 0 AND health_score <= 100),
    
    -- Contributing factors (0-100 each)
    error_rate_score        INTEGER     NOT NULL DEFAULT 100,
    rate_limit_score        INTEGER     NOT NULL DEFAULT 100,
    auth_failure_score      INTEGER     NOT NULL DEFAULT 100,
    webhook_delivery_score  INTEGER     NOT NULL DEFAULT 100,
    activity_recency_score  INTEGER     NOT NULL DEFAULT 100,
    
    -- Trend analysis
    health_trend            health_trend NOT NULL DEFAULT 'stable',
    previous_score          INTEGER,
    score_change            INTEGER     NOT NULL DEFAULT 0,
    
    -- Risk flagging
    is_at_risk              BOOLEAN     NOT NULL DEFAULT false,
    risk_factors            JSONB,
    
    score_timestamp         TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    
    UNIQUE (consumer_id, score_timestamp)
);

CREATE INDEX idx_consumer_health_scores_consumer ON consumer_health_scores (consumer_id, score_timestamp DESC);
CREATE INDEX idx_consumer_health_scores_at_risk ON consumer_health_scores (is_at_risk, health_score) WHERE is_at_risk = true;
CREATE INDEX idx_consumer_health_scores_trend ON consumer_health_scores (health_trend, score_timestamp DESC);

-- ── Revenue attribution ──────────────────────────────────────────────────────
CREATE TABLE consumer_revenue_attribution (
    id                      UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    consumer_id             TEXT        NOT NULL,
    snapshot_period         snapshot_period NOT NULL,
    period_start            TIMESTAMPTZ NOT NULL,
    period_end              TIMESTAMPTZ NOT NULL,
    
    -- Transaction volume
    total_transaction_count BIGINT      NOT NULL DEFAULT 0,
    total_transaction_volume NUMERIC(20,2) NOT NULL DEFAULT 0.0,
    
    -- Fee revenue
    total_fees_generated    NUMERIC(20,2) NOT NULL DEFAULT 0.0,
    
    -- cNGN volume
    cngn_volume_transferred NUMERIC(20,2) NOT NULL DEFAULT 0.0,
    
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    
    UNIQUE (consumer_id, snapshot_period, period_start)
);

CREATE INDEX idx_consumer_revenue_consumer ON consumer_revenue_attribution (consumer_id, period_start DESC);
CREATE INDEX idx_consumer_revenue_period ON consumer_revenue_attribution (snapshot_period, period_start DESC);
CREATE INDEX idx_consumer_revenue_fees ON consumer_revenue_attribution (total_fees_generated DESC);

-- ── Usage anomalies ──────────────────────────────────────────────────────────
CREATE TABLE consumer_usage_anomalies (
    id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    consumer_id         TEXT        NOT NULL,
    anomaly_type        TEXT        NOT NULL, -- 'volume_drop', 'error_spike', 'inactivity'
    severity            TEXT        NOT NULL, -- 'low', 'medium', 'high', 'critical'
    
    -- Anomaly details
    detected_value      NUMERIC(20,4),
    expected_value      NUMERIC(20,4),
    threshold_value     NUMERIC(20,4),
    deviation_percent   NUMERIC(8,2),
    
    -- Context
    detection_window    TEXT        NOT NULL, -- e.g., 'last_24h', 'last_7d'
    anomaly_context     JSONB,
    
    -- Resolution
    is_resolved         BOOLEAN     NOT NULL DEFAULT false,
    resolved_at         TIMESTAMPTZ,
    resolution_notes    TEXT,
    
    detected_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    notified_at         TIMESTAMPTZ,
    
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_consumer_usage_anomalies_consumer ON consumer_usage_anomalies (consumer_id, detected_at DESC);
CREATE INDEX idx_consumer_usage_anomalies_unresolved ON consumer_usage_anomalies (is_resolved, detected_at DESC) WHERE is_resolved = false;
CREATE INDEX idx_consumer_usage_anomalies_type ON consumer_usage_anomalies (anomaly_type, severity, detected_at DESC);

-- ── Platform usage reports ───────────────────────────────────────────────────
CREATE TABLE platform_usage_reports (
    id                      UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    report_type             TEXT        NOT NULL, -- 'weekly', 'monthly'
    report_period_start     TIMESTAMPTZ NOT NULL,
    report_period_end       TIMESTAMPTZ NOT NULL,
    
    -- Summary metrics
    total_api_requests      BIGINT      NOT NULL DEFAULT 0,
    platform_error_rate     NUMERIC(5,4) NOT NULL DEFAULT 0.0,
    total_consumers         INTEGER     NOT NULL DEFAULT 0,
    active_consumers        INTEGER     NOT NULL DEFAULT 0,
    new_consumers           INTEGER     NOT NULL DEFAULT 0,
    at_risk_consumers       INTEGER     NOT NULL DEFAULT 0,
    
    -- Feature adoption changes
    feature_adoption_summary JSONB,
    
    -- Top consumers
    top_consumers_by_volume JSONB,
    
    -- Report file
    report_file_path        TEXT,
    report_file_size_bytes  BIGINT,
    
    generated_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    
    UNIQUE (report_type, report_period_start)
);

CREATE INDEX idx_platform_usage_reports_type ON platform_usage_reports (report_type, report_period_start DESC);
CREATE INDEX idx_platform_usage_reports_generated ON platform_usage_reports (generated_at DESC);

-- ── Consumer monthly reports ─────────────────────────────────────────────────
CREATE TABLE consumer_monthly_reports (
    id                      UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    consumer_id             TEXT        NOT NULL,
    report_month            DATE        NOT NULL, -- First day of month
    
    -- Summary metrics
    total_requests          BIGINT      NOT NULL DEFAULT 0,
    error_rate              NUMERIC(5,4) NOT NULL DEFAULT 0.0,
    avg_response_time_ms    INTEGER     NOT NULL DEFAULT 0,
    health_score            INTEGER     NOT NULL DEFAULT 100,
    
    -- Feature usage
    features_used           JSONB,
    
    -- Integration health
    integration_health_summary TEXT,
    
    -- Report file
    report_file_path        TEXT,
    report_file_size_bytes  BIGINT,
    
    delivered_at            TIMESTAMPTZ,
    generated_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    
    UNIQUE (consumer_id, report_month)
);

CREATE INDEX idx_consumer_monthly_reports_consumer ON consumer_monthly_reports (consumer_id, report_month DESC);
CREATE INDEX idx_consumer_monthly_reports_month ON consumer_monthly_reports (report_month DESC);
CREATE INDEX idx_consumer_monthly_reports_delivered ON consumer_monthly_reports (delivered_at) WHERE delivered_at IS NOT NULL;

-- ── Health score configuration ───────────────────────────────────────────────
CREATE TABLE health_score_config (
    id                      UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    config_name             TEXT        NOT NULL UNIQUE,
    
    -- Factor weights (must sum to 1.0)
    error_rate_weight       NUMERIC(3,2) NOT NULL DEFAULT 0.30,
    rate_limit_weight       NUMERIC(3,2) NOT NULL DEFAULT 0.20,
    auth_failure_weight     NUMERIC(3,2) NOT NULL DEFAULT 0.15,
    webhook_delivery_weight NUMERIC(3,2) NOT NULL DEFAULT 0.20,
    activity_recency_weight NUMERIC(3,2) NOT NULL DEFAULT 0.15,
    
    -- Thresholds
    at_risk_threshold       INTEGER     NOT NULL DEFAULT 60,
    critical_threshold      INTEGER     NOT NULL DEFAULT 40,
    
    -- Trend calculation
    trend_lookback_days     INTEGER     NOT NULL DEFAULT 7,
    
    is_active               BOOLEAN     NOT NULL DEFAULT true,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Insert default configuration
INSERT INTO health_score_config (config_name) VALUES ('default');

-- ── Snapshot generation tracking ─────────────────────────────────────────────
CREATE TABLE snapshot_generation_log (
    id                      UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    snapshot_period         snapshot_period NOT NULL,
    period_start            TIMESTAMPTZ NOT NULL,
    period_end              TIMESTAMPTZ NOT NULL,
    
    consumers_processed     INTEGER     NOT NULL DEFAULT 0,
    snapshots_created       INTEGER     NOT NULL DEFAULT 0,
    computation_duration_ms BIGINT      NOT NULL,
    
    status                  TEXT        NOT NULL, -- 'success', 'partial', 'failed'
    error_message           TEXT,
    
    started_at              TIMESTAMPTZ NOT NULL,
    completed_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    
    UNIQUE (snapshot_period, period_start)
);

CREATE INDEX idx_snapshot_generation_log_period ON snapshot_generation_log (snapshot_period, started_at DESC);
CREATE INDEX idx_snapshot_generation_log_status ON snapshot_generation_log (status, started_at DESC);
