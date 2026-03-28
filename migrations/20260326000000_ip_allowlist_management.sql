-- ==============================================================================
-- IP ALLOWLIST MANAGEMENT TABLES (Issue #165)
-- ==============================================================================

-- ─────────────────────────────────────────────────────────────────────────────
-- 1. ip_allowlist - Consumer IP allowlist entries
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE ip_allowlist (
    id                  BIGSERIAL PRIMARY KEY,
    consumer_id         TEXT            NOT NULL,
    label               VARCHAR(255)    NOT NULL,
    entry_type          VARCHAR(20)     NOT NULL CHECK (entry_type IN ('IPv4', 'IPv6', 'CIDR4', 'CIDR6')),
    entry_value         VARCHAR(45)     NOT NULL,  -- Can hold IPv4, IPv6, or CIDR notation
    expiry_at           TIMESTAMPTZ,
    status              VARCHAR(20)     NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'expired', 'deleted')),
    created_by          TEXT            NOT NULL,  -- consumer_id or admin_id
    created_at          TIMESTAMPTZ     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMPTZ     DEFAULT CURRENT_TIMESTAMP,
    deleted_at          TIMESTAMPTZ,
    deleted_by          TEXT,

    CONSTRAINT chk_expiry_format CHECK (expiry_at IS NULL OR expiry_at > created_at),
    CONSTRAINT chk_label_not_empty CHECK (label != '')
);

-- Indexes for fast lookups
CREATE INDEX idx_allowlist_consumer_active
    ON ip_allowlist(consumer_id, status)
    WHERE status = 'active';

CREATE INDEX idx_allowlist_consumer_created
    ON ip_allowlist(consumer_id, created_at DESC);

CREATE INDEX idx_allowlist_entry_value
    ON ip_allowlist(entry_value);

CREATE INDEX idx_allowlist_expiry
    ON ip_allowlist(expiry_at)
    WHERE expiry_at IS NOT NULL AND status = 'active';

-- Unique constraint: no duplicate active entries per consumer
CREATE UNIQUE INDEX idx_allowlist_unique_active_entry
    ON ip_allowlist(consumer_id, entry_value)
    WHERE status = 'active';


-- ─────────────────────────────────────────────────────────────────────────────
-- 2. global_ip_blocks - Globally blocked IP ranges (admin-managed)
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE global_ip_blocks (
    id                  BIGSERIAL PRIMARY KEY,
    entry_type          VARCHAR(20)     NOT NULL CHECK (entry_type IN ('IPv4', 'IPv6', 'CIDR4', 'CIDR6')),
    entry_value         VARCHAR(45)     NOT NULL,
    reason              TEXT,
    blocked_by          TEXT            NOT NULL,  -- admin_id
    created_at          TIMESTAMPTZ     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at          TIMESTAMPTZ,
    status              VARCHAR(20)     NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'expired', 'removed')),

    CONSTRAINT chk_block_expiry CHECK (expires_at IS NULL OR expires_at > created_at),
    CONSTRAINT chk_reason_not_empty CHECK (reason != '')
);

-- Indexes for fast lookups
CREATE INDEX idx_global_blocks_value
    ON global_ip_blocks(entry_value);

CREATE INDEX idx_global_blocks_active
    ON global_ip_blocks(status)
    WHERE status = 'active';

CREATE UNIQUE INDEX idx_global_blocks_unique_active
    ON global_ip_blocks(entry_value)
    WHERE status = 'active';


-- ─────────────────────────────────────────────────────────────────────────────
-- 3. allowlist_audit_trail - Complete audit trail of all allowlist changes
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE allowlist_audit_trail (
    id                      BIGSERIAL PRIMARY KEY,
    consumer_id             TEXT,                      -- NULL for global blocks
    entry_id                BIGINT,                    -- references ip_allowlist.id
    global_block_id         BIGINT,                    -- references global_ip_blocks.id (mutually exclusive with entry_id)
    action_type             VARCHAR(30)     NOT NULL CHECK (action_type IN (
        'create_entry',
        'update_entry',
        'delete_entry',
        'expire_entry',
        'bulk_create_entries',
        'create_global_block',
        'delete_global_block'
    )),
    entry_type              VARCHAR(20),
    entry_value             VARCHAR(45),
    label                   VARCHAR(255),
    previous_label          VARCHAR(255),
    previous_expiry         TIMESTAMPTZ,
    new_expiry              TIMESTAMPTZ,
    initiated_by            TEXT            NOT NULL,  -- consumer_id or admin_id
    initiator_type          VARCHAR(20)     NOT NULL CHECK (initiator_type IN ('consumer', 'admin')),
    reason                  TEXT,
    bulk_operation_id       UUID,                      -- groups related bulk operations
    number_of_entries       INTEGER,                   -- for bulk operations
    success_count           INTEGER,                   -- for bulk operations
    failure_count           INTEGER,                   -- for bulk operations
    created_at              TIMESTAMPTZ     NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT chk_entry_or_block CHECK (
        (entry_id IS NOT NULL AND global_block_id IS NULL AND consumer_id IS NOT NULL) OR
        (entry_id IS NULL AND global_block_id IS NOT NULL AND consumer_id IS NULL)
    )
);

-- Indexes for audit trail queries
CREATE INDEX idx_audit_consumer_created
    ON allowlist_audit_trail(consumer_id, created_at DESC);

CREATE INDEX idx_audit_action_created
    ON allowlist_audit_trail(action_type, created_at DESC);

CREATE INDEX idx_audit_initiated_created
    ON allowlist_audit_trail(initiated_by, created_at DESC);

CREATE INDEX idx_audit_bulk_operation
    ON allowlist_audit_trail(bulk_operation_id)
    WHERE bulk_operation_id IS NOT NULL;

CREATE INDEX idx_audit_date_range
    ON allowlist_audit_trail(created_at DESC);


-- ─────────────────────────────────────────────────────────────────────────────
-- 4. allowlist_cache_invalidation - Track cache invalidation events
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE allowlist_cache_invalidation (
    id                  BIGSERIAL PRIMARY KEY,
    consumer_id         TEXT            NOT NULL,
    reason              VARCHAR(100)    NOT NULL,
    triggered_at        TIMESTAMPTZ     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    cache_cleared_at    TIMESTAMPTZ
);

CREATE INDEX idx_cache_invalidation_consumer_time
    ON allowlist_cache_invalidation(consumer_id, triggered_at DESC);

CREATE INDEX idx_cache_invalidation_pending
    ON allowlist_cache_invalidation(cache_cleared_at)
    WHERE cache_cleared_at IS NULL;


-- ─────────────────────────────────────────────────────────────────────────────
-- 5. HELPER FUNCTIONS
-- ─────────────────────────────────────────────────────────────────────────────

-- Get all active allowlist entries for a consumer (for enforcement)
CREATE OR REPLACE FUNCTION get_consumer_active_allowlist(p_consumer_id TEXT)
RETURNS TABLE (
    id BIGINT,
    entry_type VARCHAR,
    entry_value VARCHAR,
    label VARCHAR,
    created_at TIMESTAMPTZ,
    expiry_at TIMESTAMPTZ
) AS $$
    SELECT id, entry_type, entry_value, label, created_at, expiry_at
    FROM ip_allowlist
    WHERE consumer_id = p_consumer_id
      AND status = 'active'
      AND (expiry_at IS NULL OR expiry_at > CURRENT_TIMESTAMP)
    ORDER BY created_at DESC;
$$ LANGUAGE SQL STABLE;

-- Get all active global blocks
CREATE OR REPLACE FUNCTION get_all_active_global_blocks()
RETURNS TABLE (
    id BIGINT,
    entry_type VARCHAR,
    entry_value VARCHAR,
    reason TEXT
) AS $$
    SELECT id, entry_type, entry_value, reason
    FROM global_ip_blocks
    WHERE status = 'active'
      AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)
    ORDER BY created_at DESC;
$$ LANGUAGE SQL STABLE;

-- Count active allowlist entries for a consumer
CREATE OR REPLACE FUNCTION count_consumer_active_allowlist(p_consumer_id TEXT)
RETURNS INTEGER AS $$
    SELECT COUNT(*)::INTEGER
    FROM ip_allowlist
    WHERE consumer_id = p_consumer_id
      AND status = 'active'
      AND (expiry_at IS NULL OR expiry_at > CURRENT_TIMESTAMP);
$$ LANGUAGE SQL STABLE;
