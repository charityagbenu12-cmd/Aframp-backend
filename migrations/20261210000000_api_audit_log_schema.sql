-- API Request Audit Logging System (Issue #183)
-- Comprehensive, tamper-evident, queryable audit log for every significant API interaction.
-- Partitioned by month for query performance at scale.

-- ── Event category enum ───────────────────────────────────────────────────────
CREATE TYPE audit_event_category AS ENUM (
    'authentication',
    'credential',
    'financial_transaction',
    'configuration',
    'security',
    'admin',
    'data_access'
);

-- ── Actor type enum ───────────────────────────────────────────────────────────
CREATE TYPE audit_actor_type AS ENUM (
    'consumer',
    'admin',
    'microservice',
    'system'
);

-- ── Outcome enum ─────────────────────────────────────────────────────────────
CREATE TYPE audit_outcome AS ENUM (
    'success',
    'failure',
    'partial'
);

-- ── Parent table (partitioned by month on timestamp) ─────────────────────────
CREATE TABLE api_audit_logs (
    id              UUID        NOT NULL DEFAULT gen_random_uuid(),
    -- Event classification
    event_type      TEXT        NOT NULL,
    event_category  audit_event_category NOT NULL,
    -- Actor
    actor_type      audit_actor_type NOT NULL,
    actor_id        TEXT,                       -- consumer_id, admin_id, service name
    actor_ip        INET,
    actor_consumer_type TEXT,                   -- mobile_client | partner | microservice | admin
    session_id      TEXT,                       -- session UUID or token JTI
    -- Target
    target_resource_type TEXT,
    target_resource_id   TEXT,
    -- Request
    request_method  TEXT        NOT NULL,
    request_path    TEXT        NOT NULL,
    request_body_hash TEXT,                     -- SHA-256 of request body; never raw body
    -- Response
    response_status INTEGER     NOT NULL,
    response_latency_ms BIGINT  NOT NULL,
    -- Outcome
    outcome         audit_outcome NOT NULL,
    failure_reason  TEXT,
    -- Environment
    environment     TEXT        NOT NULL DEFAULT 'mainnet',
    -- Hash chain
    previous_entry_hash TEXT,                   -- SHA-256 of previous entry
    current_entry_hash  TEXT    NOT NULL,       -- SHA-256 of this entry
    -- Timestamp (partition key)
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (id, created_at)
) PARTITION BY RANGE (created_at);

-- ── Bootstrap partitions (current month + next two) ──────────────────────────
-- Additional partitions should be created by a maintenance job before month end.
DO $$
DECLARE
    start_date DATE;
    end_date   DATE;
    tbl_name   TEXT;
BEGIN
    FOR i IN 0..2 LOOP
        start_date := DATE_TRUNC('month', NOW()) + (i || ' months')::INTERVAL;
        end_date   := start_date + INTERVAL '1 month';
        tbl_name   := 'api_audit_logs_' || TO_CHAR(start_date, 'YYYY_MM');

        EXECUTE FORMAT(
            'CREATE TABLE IF NOT EXISTS %I PARTITION OF api_audit_logs
             FOR VALUES FROM (%L) TO (%L)',
            tbl_name, start_date, end_date
        );
    END LOOP;
END;
$$;

-- ── Indexes on the parent table (inherited by each partition) ─────────────────
CREATE INDEX idx_api_audit_logs_created_at       ON api_audit_logs (created_at);
CREATE INDEX idx_api_audit_logs_event_category   ON api_audit_logs (event_category, created_at);
CREATE INDEX idx_api_audit_logs_actor_id         ON api_audit_logs (actor_id, created_at);
CREATE INDEX idx_api_audit_logs_actor_type       ON api_audit_logs (actor_type, created_at);
CREATE INDEX idx_api_audit_logs_target           ON api_audit_logs (target_resource_type, target_resource_id, created_at);
CREATE INDEX idx_api_audit_logs_outcome          ON api_audit_logs (outcome, created_at);
CREATE INDEX idx_api_audit_logs_environment      ON api_audit_logs (environment, created_at);
CREATE INDEX idx_api_audit_logs_response_status  ON api_audit_logs (response_status, created_at);

-- ── Append-only enforcement: block UPDATE and DELETE ─────────────────────────
CREATE OR REPLACE FUNCTION audit_log_immutable()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit_log is append-only: % on api_audit_logs is forbidden', TG_OP;
END;
$$;

CREATE TRIGGER trg_audit_log_no_update
    BEFORE UPDATE ON api_audit_logs
    FOR EACH ROW EXECUTE FUNCTION audit_log_immutable();

CREATE TRIGGER trg_audit_log_no_delete
    BEFORE DELETE ON api_audit_logs
    FOR EACH ROW EXECUTE FUNCTION audit_log_immutable();

-- ── Partition maintenance function ───────────────────────────────────────────
-- Call this from a cron job / DB maintenance worker at the start of each month.
CREATE OR REPLACE FUNCTION create_next_audit_partition()
RETURNS VOID LANGUAGE plpgsql AS $$
DECLARE
    next_month DATE := DATE_TRUNC('month', NOW() + INTERVAL '1 month');
    tbl_name   TEXT := 'api_audit_logs_' || TO_CHAR(next_month, 'YYYY_MM');
BEGIN
    EXECUTE FORMAT(
        'CREATE TABLE IF NOT EXISTS %I PARTITION OF api_audit_logs
         FOR VALUES FROM (%L) TO (%L)',
        tbl_name, next_month, next_month + INTERVAL '1 month'
    );
END;
$$;
