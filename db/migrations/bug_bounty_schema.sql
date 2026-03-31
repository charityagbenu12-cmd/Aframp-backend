-- ============================================================================
-- BUG BOUNTY PROGRAMME SCHEMA
-- ============================================================================

-- ============================================================================
-- 1. ENUM TYPES
-- ============================================================================

DO $$ BEGIN
    CREATE TYPE bb_report_status AS ENUM (
        'new',
        'acknowledged',
        'triaged',
        'in_remediation',
        'resolved',
        'duplicate',
        'out_of_scope',
        'rejected'
    );
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    CREATE TYPE bb_severity AS ENUM (
        'critical',
        'high',
        'medium',
        'low',
        'informational'
    );
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    CREATE TYPE bb_programme_phase AS ENUM (
        'private',
        'public'
    );
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

-- ============================================================================
-- 2. BUG_BOUNTY_REPORTS TABLE
-- ============================================================================
CREATE TABLE IF NOT EXISTS bug_bounty_reports (
    id                              UUID PRIMARY KEY,
    researcher_id                   TEXT NOT NULL,
    severity                        bb_severity NOT NULL,
    affected_component              TEXT NOT NULL,
    vulnerability_type              TEXT NOT NULL,
    title                           TEXT NOT NULL,
    description                     TEXT NOT NULL,
    proof_of_concept                TEXT,
    submission_content              JSONB NOT NULL,
    status                          bb_report_status NOT NULL DEFAULT 'new',
    duplicate_of                    UUID REFERENCES bug_bounty_reports(id),
    acknowledgement_sla_deadline    TIMESTAMPTZ NOT NULL,
    triage_sla_deadline             TIMESTAMPTZ NOT NULL,
    acknowledged_at                 TIMESTAMPTZ,
    triaged_at                      TIMESTAMPTZ,
    resolved_at                     TIMESTAMPTZ,
    coordinated_disclosure_date     TIMESTAMPTZ,
    remediation_ref                 TEXT,
    source                          TEXT NOT NULL DEFAULT 'managed_platform',
    created_at                      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at                      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_bb_reports_researcher_id
    ON bug_bounty_reports(researcher_id);

CREATE INDEX IF NOT EXISTS idx_bb_reports_status
    ON bug_bounty_reports(status, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_bb_reports_severity
    ON bug_bounty_reports(severity, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_bb_reports_duplicate_of
    ON bug_bounty_reports(duplicate_of)
    WHERE duplicate_of IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_bb_reports_sla_ack
    ON bug_bounty_reports(acknowledgement_sla_deadline)
    WHERE acknowledged_at IS NULL AND status NOT IN ('duplicate', 'out_of_scope', 'rejected');

CREATE INDEX IF NOT EXISTS idx_bb_reports_sla_triage
    ON bug_bounty_reports(triage_sla_deadline)
    WHERE triaged_at IS NULL AND severity IN ('critical', 'high') AND status NOT IN ('duplicate', 'out_of_scope', 'rejected');

-- ============================================================================
-- 3. COMMUNICATION_LOG TABLE
-- ============================================================================
CREATE TABLE IF NOT EXISTS communication_log (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    report_id           UUID NOT NULL REFERENCES bug_bounty_reports(id),
    direction           TEXT NOT NULL DEFAULT 'outbound',
    notification_type   TEXT NOT NULL,
    content             JSONB NOT NULL,
    sent_at             TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_comm_log_report_id
    ON communication_log(report_id, sent_at ASC);

-- ============================================================================
-- 4. REWARD_RECORDS TABLE
-- ============================================================================
CREATE TABLE IF NOT EXISTS reward_records (
    id                          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    report_id                   UUID NOT NULL REFERENCES bug_bounty_reports(id),
    researcher_id               TEXT NOT NULL,
    amount_usd                  NUMERIC(12,2) NOT NULL,
    justification               TEXT NOT NULL,
    escalation_justification    TEXT,
    payment_initiated_at        TIMESTAMPTZ NOT NULL,
    created_by                  UUID NOT NULL,
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_reward_records_report_id
    ON reward_records(report_id);

CREATE INDEX IF NOT EXISTS idx_reward_records_researcher_id
    ON reward_records(researcher_id);

CREATE INDEX IF NOT EXISTS idx_reward_records_month
    ON reward_records(date_trunc('month', created_at));

-- ============================================================================
-- 5. RESEARCHER_INVITATIONS TABLE
-- ============================================================================
CREATE TABLE IF NOT EXISTS researcher_invitations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    researcher_id   TEXT NOT NULL UNIQUE,
    status          TEXT NOT NULL DEFAULT 'active',
    created_by      UUID NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at      TIMESTAMPTZ,
    revoked_by      UUID
);

CREATE INDEX IF NOT EXISTS idx_researcher_invitations_researcher_id
    ON researcher_invitations(researcher_id);

CREATE INDEX IF NOT EXISTS idx_researcher_invitations_active
    ON researcher_invitations(researcher_id)
    WHERE status = 'active';

-- ============================================================================
-- 6. PROGRAMME_STATE SINGLETON TABLE
-- ============================================================================
CREATE TABLE IF NOT EXISTS programme_state (
    id                          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    phase                       bb_programme_phase NOT NULL DEFAULT 'private',
    launched_at                 TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    transitioned_to_public_at   TIMESTAMPTZ,
    transitioned_by             UUID
);

-- Seed the singleton row if it doesn't already exist
INSERT INTO programme_state (phase)
SELECT 'private'
WHERE NOT EXISTS (SELECT 1 FROM programme_state);

-- ============================================================================
-- TRIGGERS
-- ============================================================================

-- Auto-update updated_at on bug_bounty_reports
CREATE OR REPLACE FUNCTION update_bb_report_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_bb_reports_updated ON bug_bounty_reports;
CREATE TRIGGER trg_bb_reports_updated
    BEFORE UPDATE ON bug_bounty_reports
    FOR EACH ROW
    EXECUTE FUNCTION update_bb_report_timestamp();
