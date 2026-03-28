CREATE TABLE IF NOT EXISTS security_audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    consumer_id TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    method TEXT NOT NULL,
    validation_layer TEXT NOT NULL,
    error_code TEXT NOT NULL,
    error_message TEXT NOT NULL,
    field_name TEXT,
    request_body JSONB NOT NULL DEFAULT '{}'::jsonb,
    request_headers JSONB NOT NULL DEFAULT '{}'::jsonb,
    context JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_security_audit_log_consumer_created_at
    ON security_audit_log (consumer_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_security_audit_log_endpoint_created_at
    ON security_audit_log (endpoint, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_security_audit_log_layer_created_at
    ON security_audit_log (validation_layer, created_at DESC);
