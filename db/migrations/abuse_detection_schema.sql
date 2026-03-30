-- ============================================================================
-- ABUSE DETECTION AND AUTOMATED RESPONSE SYSTEM
-- ============================================================================

-- Enum for abuse case status
CREATE TYPE abuse_case_status AS ENUM ('open', 'escalated', 'dismissed', 'resolved');

-- ============================================================================
-- 1. ABUSE_CASES TABLE
-- ============================================================================
CREATE TABLE abuse_cases (
    id                      UUID PRIMARY KEY,
    consumer_ids            UUID[] NOT NULL,
    detection_signals       JSONB NOT NULL,
    composite_confidence    DECIMAL(5,4) NOT NULL CHECK (composite_confidence >= 0 AND composite_confidence <= 1),
    response_tier           VARCHAR(20) NOT NULL CHECK (response_tier IN ('monitor', 'soft', 'hard', 'critical')),
    status                  abuse_case_status NOT NULL DEFAULT 'open',
    created_at              TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    resolved_at             TIMESTAMPTZ,
    resolution_notes        TEXT,
    escalated_by            UUID,
    resolved_by             UUID,
    false_positive          BOOLEAN NOT NULL DEFAULT FALSE,
    whitelisted_signals     TEXT[] NOT NULL DEFAULT '{}',

    CONSTRAINT chk_resolved_fields CHECK (
        (status IN ('dismissed', 'resolved') AND resolved_at IS NOT NULL AND resolved_by IS NOT NULL)
        OR (status NOT IN ('dismissed', 'resolved'))
    )
);

CREATE INDEX idx_abuse_cases_status ON abuse_cases(status, created_at DESC);
CREATE INDEX idx_abuse_cases_consumers ON abuse_cases USING GIN(consumer_ids);
CREATE INDEX idx_abuse_cases_tier ON abuse_cases(response_tier, created_at DESC);
CREATE INDEX idx_abuse_cases_created ON abuse_cases(created_at DESC);

-- ============================================================================
-- 2. ABUSE_RESPONSE_ACTIONS TABLE
-- ============================================================================
CREATE TABLE abuse_response_actions (
    id                      UUID PRIMARY KEY,
    tier                    VARCHAR(20) NOT NULL CHECK (tier IN ('monitor', 'soft', 'hard', 'critical')),
    consumer_ids            UUID[] NOT NULL,
    applied_at              TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at              TIMESTAMPTZ,
    reason                  TEXT NOT NULL,
    evidence_case_id        UUID NOT NULL REFERENCES abuse_cases(id),
    actions_taken           TEXT[] NOT NULL,
    notification_sent       BOOLEAN NOT NULL DEFAULT FALSE,

    CONSTRAINT chk_expiry_for_temporary CHECK (
        (tier IN ('soft', 'hard') AND expires_at IS NOT NULL)
        OR (tier IN ('monitor', 'critical'))
    )
);

CREATE INDEX idx_abuse_responses_consumers ON abuse_response_actions USING GIN(consumer_ids);
CREATE INDEX idx_abuse_responses_active ON abuse_response_actions(applied_at DESC)
    WHERE expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP;
CREATE INDEX idx_abuse_responses_case ON abuse_response_actions(evidence_case_id);

-- ============================================================================
-- 3. ABUSE_SIGNAL_WHITELIST TABLE
-- ============================================================================
CREATE TABLE abuse_signal_whitelist (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    consumer_id             UUID NOT NULL,
    signal_type             VARCHAR(100) NOT NULL,
    whitelisted_at          TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    whitelisted_by          UUID NOT NULL,
    reason                  TEXT NOT NULL,
    expires_at              TIMESTAMPTZ,

    CONSTRAINT uq_consumer_signal UNIQUE (consumer_id, signal_type)
);

CREATE INDEX idx_abuse_whitelist_consumer ON abuse_signal_whitelist(consumer_id);
CREATE INDEX idx_abuse_whitelist_active ON abuse_signal_whitelist(consumer_id, signal_type)
    WHERE expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP;

-- ============================================================================
-- 4. ABUSE_DETECTION_AUDIT_LOG TABLE
-- ============================================================================
CREATE TABLE abuse_detection_audit_log (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type              VARCHAR(50) NOT NULL,
    consumer_id             UUID,
    ip_address              INET,
    signal_type             VARCHAR(100),
    confidence_score        DECIMAL(5,4),
    response_tier           VARCHAR(20),
    case_id                 UUID REFERENCES abuse_cases(id),
    details                 JSONB,
    detected_at             TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_abuse_audit_consumer ON abuse_detection_audit_log(consumer_id, detected_at DESC);
CREATE INDEX idx_abuse_audit_ip ON abuse_detection_audit_log(ip_address, detected_at DESC);
CREATE INDEX idx_abuse_audit_signal ON abuse_detection_audit_log(signal_type, detected_at DESC);
CREATE INDEX idx_abuse_audit_case ON abuse_detection_audit_log(case_id);
CREATE INDEX idx_abuse_audit_time ON abuse_detection_audit_log(detected_at DESC);

-- ============================================================================
-- 5. RATE_LIMIT_ADJUSTMENTS TABLE
-- ============================================================================
CREATE TABLE rate_limit_adjustments (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    consumer_id             UUID NOT NULL,
    original_limit          BIGINT NOT NULL,
    adjusted_limit          BIGINT NOT NULL,
    reduction_percent       DECIMAL(5,2) NOT NULL,
    applied_at              TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at              TIMESTAMPTZ NOT NULL,
    case_id                 UUID NOT NULL REFERENCES abuse_cases(id),

    CONSTRAINT chk_adjusted_limit CHECK (adjusted_limit > 0 AND adjusted_limit <= original_limit)
);

CREATE INDEX idx_rate_adjustments_consumer ON rate_limit_adjustments(consumer_id);
CREATE INDEX idx_rate_adjustments_active ON rate_limit_adjustments(consumer_id, expires_at)
    WHERE expires_at > CURRENT_TIMESTAMP;

-- ============================================================================
-- 6. CREDENTIAL_SUSPENSIONS TABLE
-- ============================================================================
CREATE TABLE credential_suspensions (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    consumer_id             UUID NOT NULL,
    suspended_keys          UUID[] NOT NULL,
    suspended_tokens        TEXT[] NOT NULL,
    suspension_type         VARCHAR(20) NOT NULL CHECK (suspension_type IN ('hard', 'critical')),
    reason                  TEXT NOT NULL,
    suspended_at            TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at              TIMESTAMPTZ,
    case_id                 UUID NOT NULL REFERENCES abuse_cases(id),

    CONSTRAINT chk_critical_permanent CHECK (
        (suspension_type = 'critical' AND expires_at IS NULL)
        OR (suspension_type = 'hard' AND expires_at IS NOT NULL)
    )
);

CREATE INDEX idx_credential_suspensions_consumer ON credential_suspensions(consumer_id);
CREATE INDEX idx_credential_suspensions_active ON credential_suspensions(consumer_id)
    WHERE expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP;
CREATE INDEX idx_credential_suspensions_keys ON credential_suspensions USING GIN(suspended_keys);

-- ============================================================================
-- HELPER FUNCTIONS
-- ============================================================================

-- Function to check if consumer has active abuse response
CREATE OR REPLACE FUNCTION has_active_abuse_response(p_consumer_id UUID)
RETURNS TABLE (
    has_response BOOLEAN,
    highest_tier VARCHAR(20),
    case_id UUID
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        TRUE as has_response,
        tier as highest_tier,
        evidence_case_id as case_id
    FROM abuse_response_actions
    WHERE p_consumer_id = ANY(consumer_ids)
      AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)
    ORDER BY
        CASE tier
            WHEN 'critical' THEN 4
            WHEN 'hard' THEN 3
            WHEN 'soft' THEN 2
            WHEN 'monitor' THEN 1
        END DESC
    LIMIT 1;
END;
$$ LANGUAGE plpgsql STABLE;

-- Function to get active rate limit adjustment
CREATE OR REPLACE FUNCTION get_active_rate_limit(p_consumer_id UUID)
RETURNS TABLE (
    adjusted_limit BIGINT,
    expires_at TIMESTAMPTZ
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        rla.adjusted_limit,
        rla.expires_at
    FROM rate_limit_adjustments rla
    WHERE rla.consumer_id = p_consumer_id
      AND rla.expires_at > CURRENT_TIMESTAMP
    ORDER BY rla.applied_at DESC
    LIMIT 1;
END;
$$ LANGUAGE plpgsql STABLE;

-- Function to check if signal is whitelisted for consumer
CREATE OR REPLACE FUNCTION is_signal_whitelisted(
    p_consumer_id UUID,
    p_signal_type VARCHAR(100)
)
RETURNS BOOLEAN AS $$
BEGIN
    RETURN EXISTS (
        SELECT 1
        FROM abuse_signal_whitelist
        WHERE consumer_id = p_consumer_id
          AND signal_type = p_signal_type
          AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)
    );
END;
$$ LANGUAGE plpgsql STABLE;

-- Function to clean up expired response actions
CREATE OR REPLACE FUNCTION cleanup_expired_abuse_responses()
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM abuse_response_actions
    WHERE expires_at IS NOT NULL
      AND expires_at < CURRENT_TIMESTAMP - INTERVAL '7 days';

    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- TRIGGERS
-- ============================================================================

-- Trigger to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_abuse_case_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_abuse_cases_updated
    BEFORE UPDATE ON abuse_cases
    FOR EACH ROW
    EXECUTE FUNCTION update_abuse_case_timestamp();

-- ============================================================================
-- VIEWS
-- ============================================================================

-- View for abuse case summary
CREATE OR REPLACE VIEW abuse_case_summary AS
SELECT
    ac.id,
    ac.consumer_ids,
    jsonb_array_length(ac.detection_signals) as signal_count,
    ac.composite_confidence,
    ac.response_tier,
    ac.status,
    ac.created_at,
    ac.updated_at,
    ac.false_positive,
    COUNT(ara.id) as response_action_count
FROM abuse_cases ac
LEFT JOIN abuse_response_actions ara ON ara.evidence_case_id = ac.id
GROUP BY ac.id;

-- View for active abuse responses
CREATE OR REPLACE VIEW active_abuse_responses AS
SELECT
    ara.*,
    ac.composite_confidence,
    ac.status as case_status
FROM abuse_response_actions ara
JOIN abuse_cases ac ON ac.id = ara.evidence_case_id
WHERE ara.expires_at IS NULL OR ara.expires_at > CURRENT_TIMESTAMP;

-- ============================================================================
-- SAMPLE QUERIES FOR MONITORING
-- ============================================================================

-- Get abuse detection statistics for last 24 hours
-- SELECT
--     COUNT(*) FILTER (WHERE status = 'open') as open_cases,
--     COUNT(*) FILTER (WHERE status = 'resolved') as resolved_cases,
--     COUNT(*) FILTER (WHERE false_positive = true) as false_positives,
--     AVG(composite_confidence) as avg_confidence,
--     COUNT(*) FILTER (WHERE response_tier = 'critical') as critical_responses
-- FROM abuse_cases
-- WHERE created_at > CURRENT_TIMESTAMP - INTERVAL '24 hours';

-- Get top consumers by abuse case count
-- SELECT
--     unnest(consumer_ids) as consumer_id,
--     COUNT(*) as case_count,
--     AVG(composite_confidence) as avg_confidence,
--     MAX(response_tier) as highest_tier
-- FROM abuse_cases
-- WHERE created_at > CURRENT_TIMESTAMP - INTERVAL '7 days'
-- GROUP BY consumer_id
-- ORDER BY case_count DESC
-- LIMIT 10;

-- Get signal type distribution
-- SELECT
--     signal->>'type' as signal_type,
--     COUNT(*) as occurrence_count
-- FROM abuse_cases,
--      jsonb_array_elements(detection_signals) as signal
-- WHERE created_at > CURRENT_TIMESTAMP - INTERVAL '24 hours'
-- GROUP BY signal_type
-- ORDER BY occurrence_count DESC;
