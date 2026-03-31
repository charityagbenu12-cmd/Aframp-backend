-- ============================================================================
-- COMPLIANCE REGISTRY — Issue #2.02
-- Tracks licenses, regulatory constraints, and corridor governance.
-- ============================================================================

-- ---------------------------------------------------------------------------
-- ENUMS
-- ---------------------------------------------------------------------------

CREATE TYPE license_status AS ENUM (
    'active',
    'expired',
    'suspended',
    'pending_renewal',
    'revoked'
);

CREATE TYPE corridor_status AS ENUM (
    'active',
    'suspended',
    'blocked_license_expired',
    'blocked_license_suspended',
    'blocked_regulatory'
);

-- ---------------------------------------------------------------------------
-- 1. PAYMENT_CORRIDORS
--    Explicit corridor table — source_country → destination_country pair.
-- ---------------------------------------------------------------------------
CREATE TABLE payment_corridors (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_country      CHAR(2) NOT NULL,   -- ISO 3166-1 alpha-2
    destination_country CHAR(2) NOT NULL,   -- ISO 3166-1 alpha-2
    source_currency     CHAR(3) NOT NULL,   -- ISO 4217
    destination_currency CHAR(3) NOT NULL,
    status              corridor_status NOT NULL DEFAULT 'active',
    status_reason       TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_by          UUID,

    CONSTRAINT uq_corridor UNIQUE (source_country, destination_country, source_currency, destination_currency)
);

CREATE INDEX idx_corridors_status ON payment_corridors(status);
CREATE INDEX idx_corridors_countries ON payment_corridors(source_country, destination_country);

-- ---------------------------------------------------------------------------
-- 2. CORRIDOR_LICENSES
--    One corridor can have multiple licenses (IMTO, PSP, etc.).
--    A corridor is only operable when at least one required license is active.
-- ---------------------------------------------------------------------------
CREATE TABLE corridor_licenses (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    corridor_id         UUID NOT NULL REFERENCES payment_corridors(id) ON DELETE CASCADE,
    license_type        VARCHAR(50) NOT NULL,   -- e.g. 'IMTO', 'PSP', 'EMI', 'MSB'
    license_number      VARCHAR(100) NOT NULL,
    issuing_authority   VARCHAR(200) NOT NULL,  -- e.g. 'Central Bank of Nigeria'
    issuing_country     CHAR(2) NOT NULL,
    issued_date         DATE NOT NULL,
    expiry_date         DATE NOT NULL,
    renewal_deadline    DATE,                   -- optional earlier deadline
    status              license_status NOT NULL DEFAULT 'active',
    document_url        TEXT,                   -- link to stored license document
    notes               TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by          UUID,
    updated_by          UUID,

    CONSTRAINT chk_license_dates CHECK (expiry_date > issued_date)
);

CREATE INDEX idx_licenses_corridor ON corridor_licenses(corridor_id, status);
CREATE INDEX idx_licenses_expiry ON corridor_licenses(expiry_date, status);
CREATE INDEX idx_licenses_status ON corridor_licenses(status, expiry_date);

-- ---------------------------------------------------------------------------
-- 3. REGULATORY_RULESETS
--    Hard-coded regional constraints (daily limits, per-tx caps, etc.).
--    Admins can update values at runtime without code deployment.
-- ---------------------------------------------------------------------------
CREATE TABLE regulatory_rulesets (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    corridor_id             UUID NOT NULL REFERENCES payment_corridors(id) ON DELETE CASCADE,
    rule_name               VARCHAR(100) NOT NULL,
    rule_description        TEXT,
    -- Monetary limits (NULL = no limit)
    max_single_transaction  DECIMAL(20,4),
    max_daily_volume        DECIMAL(20,4),
    max_monthly_volume      DECIMAL(20,4),
    currency                CHAR(3) NOT NULL,
    -- Issuing authority that mandates this rule
    mandated_by             VARCHAR(200) NOT NULL,
    is_active               BOOLEAN NOT NULL DEFAULT true,
    effective_from          TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    effective_until         TIMESTAMPTZ,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_by              UUID,

    CONSTRAINT chk_ruleset_amounts CHECK (
        (max_single_transaction IS NULL OR max_single_transaction > 0) AND
        (max_daily_volume IS NULL OR max_daily_volume > 0) AND
        (max_monthly_volume IS NULL OR max_monthly_volume > 0)
    )
);

CREATE INDEX idx_rulesets_corridor_active ON regulatory_rulesets(corridor_id, is_active);
CREATE INDEX idx_rulesets_active ON regulatory_rulesets(is_active, effective_from);

-- ---------------------------------------------------------------------------
-- 4. COMPLIANCE_REGISTRY_AUDIT_LOG
--    Every change to licenses or rulesets is captured here (Audit Trail #98).
-- ---------------------------------------------------------------------------
CREATE TABLE compliance_registry_audit_log (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    entity_type     VARCHAR(50) NOT NULL,   -- 'corridor_license' | 'regulatory_ruleset' | 'payment_corridor'
    entity_id       UUID NOT NULL,
    action          VARCHAR(50) NOT NULL,   -- 'created' | 'updated' | 'status_changed' | 'deleted'
    changed_by      UUID,
    changed_by_role VARCHAR(100),
    previous_value  JSONB,
    new_value       JSONB,
    reason          TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_compliance_audit_entity ON compliance_registry_audit_log(entity_type, entity_id, created_at DESC);
CREATE INDEX idx_compliance_audit_time ON compliance_registry_audit_log(created_at DESC);

-- ---------------------------------------------------------------------------
-- 5. LICENSE_EXPIRY_NOTIFICATIONS
--    Tracks which expiry alerts have already been dispatched (90/60/30 days).
-- ---------------------------------------------------------------------------
CREATE TABLE license_expiry_notifications (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    license_id      UUID NOT NULL REFERENCES corridor_licenses(id) ON DELETE CASCADE,
    days_before     INTEGER NOT NULL CHECK (days_before IN (90, 60, 30)),
    sent_at         TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT uq_expiry_notification UNIQUE (license_id, days_before)
);

CREATE INDEX idx_expiry_notif_license ON license_expiry_notifications(license_id);

-- ---------------------------------------------------------------------------
-- 6. TRANSACTION_COMPLIANCE_TAGS
--    Every cross-border transaction is tagged with the license/ruleset it
--    was processed under (acceptance criterion #3).
-- ---------------------------------------------------------------------------
CREATE TABLE transaction_compliance_tags (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    transaction_id  UUID NOT NULL,
    corridor_id     UUID NOT NULL REFERENCES payment_corridors(id),
    license_id      UUID REFERENCES corridor_licenses(id),
    ruleset_id      UUID REFERENCES regulatory_rulesets(id),
    tagged_at       TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_compliance_tags_tx ON transaction_compliance_tags(transaction_id);
CREATE INDEX idx_compliance_tags_corridor ON transaction_compliance_tags(corridor_id, tagged_at DESC);
CREATE INDEX idx_compliance_tags_license ON transaction_compliance_tags(license_id);
