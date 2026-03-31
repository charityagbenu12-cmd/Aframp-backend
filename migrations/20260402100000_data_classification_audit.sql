-- migrate:up
-- Data Classification Framework — Audit Table
-- Purpose: Persist policy violation events, field access audit trails, and
--          retention purge records for compliance reporting.
--
-- This table is append-only.  Rows are never updated or deleted.
-- Retention: 7 years (AML/KYC regulatory requirement).

CREATE TABLE IF NOT EXISTS data_classification_audit (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    -- The kind of event: field_access | policy_violation | field_masked |
    --                    transmission_denied | retention_purge
    event_kind      TEXT        NOT NULL,
    -- The DataField variant name (e.g. "WalletPrivateKey", "UserEmail")
    field_name      TEXT        NOT NULL,
    -- The classification tier label (CRITICAL / RESTRICTED / CONFIDENTIAL / INTERNAL / PUBLIC)
    tier            TEXT        NOT NULL,
    -- The TransmissionContext variant name (e.g. "LogLine", "ApiResponse")
    context         TEXT        NOT NULL,
    -- The actor that triggered the event (wallet address, admin UUID, service name)
    actor           TEXT,
    -- Correlation ID from the HTTP request
    request_id      TEXT,
    -- Additional human-readable detail (violation reason, purge count, etc.)
    detail          TEXT,
    occurred_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE data_classification_audit IS
    'Append-only audit trail for data classification policy events. '
    'Covers field access, policy violations, and retention purges.';

COMMENT ON COLUMN data_classification_audit.event_kind IS
    'Type of event: field_access, policy_violation, field_masked, transmission_denied, retention_purge.';
COMMENT ON COLUMN data_classification_audit.field_name IS
    'The DataField variant that was involved (matches registry::DataField enum name).';
COMMENT ON COLUMN data_classification_audit.tier IS
    'Classification tier label at the time of the event.';
COMMENT ON COLUMN data_classification_audit.context IS
    'Transmission context: LogLine, ApiResponse, WebhookDelivery, InternalRpc, Cache, Database.';
COMMENT ON COLUMN data_classification_audit.actor IS
    'Authenticated actor (wallet address, admin ID, or background service name).';
COMMENT ON COLUMN data_classification_audit.request_id IS
    'HTTP request correlation ID (X-Request-Id header value).';
COMMENT ON COLUMN data_classification_audit.detail IS
    'Free-text detail: violation reason, purge row count, etc.';

-- Indexes for compliance queries
CREATE INDEX idx_dca_event_kind       ON data_classification_audit (event_kind);
CREATE INDEX idx_dca_tier             ON data_classification_audit (tier);
CREATE INDEX idx_dca_field_name       ON data_classification_audit (field_name);
CREATE INDEX idx_dca_occurred_at      ON data_classification_audit (occurred_at DESC);
CREATE INDEX idx_dca_actor            ON data_classification_audit (actor) WHERE actor IS NOT NULL;
CREATE INDEX idx_dca_violations       ON data_classification_audit (occurred_at DESC)
    WHERE event_kind = 'policy_violation';

-- migrate:down
DROP TABLE IF EXISTS data_classification_audit;
