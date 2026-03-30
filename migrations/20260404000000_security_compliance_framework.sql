-- Security Compliance Framework Schema
-- Covers: vulnerability management, compliance posture scoring, allowlists,
--         SLA tracking, and compliance report persistence.

-- ---------------------------------------------------------------------------
-- Vulnerability registry
-- ---------------------------------------------------------------------------

CREATE TYPE vuln_severity AS ENUM ('critical', 'high', 'medium', 'low', 'informational');
CREATE TYPE vuln_status    AS ENUM ('open', 'acknowledged', 'resolved', 'risk_accepted');
CREATE TYPE vuln_source    AS ENUM (
    'cargo_audit',
    'sast',
    'container_scan',
    'secrets_detection',
    'owasp_api',
    'infra_config',
    'manual'
);

CREATE TABLE security_vulnerabilities (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title               TEXT NOT NULL,
    description         TEXT NOT NULL,
    severity            vuln_severity NOT NULL,
    status              vuln_status NOT NULL DEFAULT 'open',
    source              vuln_source NOT NULL,
    affected_component  TEXT NOT NULL,
    cve_reference       TEXT,
    affected_versions   TEXT,
    remediation_guidance TEXT,
    -- SLA
    discovered_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    sla_deadline        TIMESTAMPTZ NOT NULL,
    -- Acknowledgement
    acknowledged_at     TIMESTAMPTZ,
    acknowledged_by     TEXT,
    remediation_plan    TEXT,
    -- Resolution
    resolved_at         TIMESTAMPTZ,
    resolved_by         TEXT,
    remediation_notes   TEXT,
    resolving_commit    TEXT,
    -- Risk acceptance
    risk_accepted_at    TIMESTAMPTZ,
    risk_accepted_by    TEXT,
    risk_justification  TEXT,
    risk_expiry_date    TIMESTAMPTZ,
    -- Metadata
    raw_finding         JSONB,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_vulns_status_severity ON security_vulnerabilities (status, severity);
CREATE INDEX idx_vulns_source          ON security_vulnerabilities (source);
CREATE INDEX idx_vulns_sla_deadline    ON security_vulnerabilities (sla_deadline) WHERE status = 'open';
CREATE INDEX idx_vulns_discovered_at   ON security_vulnerabilities (discovered_at DESC);

-- ---------------------------------------------------------------------------
-- Vulnerability status history (immutable audit trail)
-- ---------------------------------------------------------------------------

CREATE TABLE security_vulnerability_history (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    vuln_id     UUID NOT NULL REFERENCES security_vulnerabilities(id) ON DELETE CASCADE,
    old_status  vuln_status,
    new_status  vuln_status NOT NULL,
    changed_by  TEXT NOT NULL,
    notes       TEXT,
    changed_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_vuln_history_vuln_id ON security_vulnerability_history (vuln_id, changed_at DESC);

-- ---------------------------------------------------------------------------
-- Vulnerability allowlist (acknowledged false positives / accepted risks)
-- ---------------------------------------------------------------------------

CREATE TABLE security_vuln_allowlist (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    identifier      TEXT NOT NULL UNIQUE,   -- e.g. RUSTSEC-2024-0001 or CVE-2024-12345
    source          vuln_source NOT NULL,
    justification   TEXT NOT NULL,
    added_by        TEXT NOT NULL,
    expiry_date     TIMESTAMPTZ NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_allowlist_identifier ON security_vuln_allowlist (identifier);
CREATE INDEX idx_allowlist_expiry     ON security_vuln_allowlist (expiry_date);

-- ---------------------------------------------------------------------------
-- Compliance posture snapshots (daily)
-- ---------------------------------------------------------------------------

CREATE TABLE security_posture_snapshots (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    snapshot_date           DATE NOT NULL UNIQUE,
    posture_score           NUMERIC(5,2) NOT NULL,  -- 0.00 – 100.00
    open_critical           INT NOT NULL DEFAULT 0,
    open_high               INT NOT NULL DEFAULT 0,
    open_medium             INT NOT NULL DEFAULT 0,
    open_low                INT NOT NULL DEFAULT 0,
    open_informational      INT NOT NULL DEFAULT 0,
    sla_breached_count      INT NOT NULL DEFAULT 0,
    domain_breakdown        JSONB NOT NULL DEFAULT '{}',
    computed_at             TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_posture_date ON security_posture_snapshots (snapshot_date DESC);

-- ---------------------------------------------------------------------------
-- Compliance reports (monthly)
-- ---------------------------------------------------------------------------

CREATE TABLE security_compliance_reports (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    report_period_start DATE NOT NULL,
    report_period_end   DATE NOT NULL,
    new_vulns_count     INT NOT NULL DEFAULT 0,
    remediated_count    INT NOT NULL DEFAULT 0,
    sla_breaches_count  INT NOT NULL DEFAULT 0,
    posture_score_start NUMERIC(5,2),
    posture_score_end   NUMERIC(5,2),
    report_data         JSONB NOT NULL DEFAULT '{}',
    generated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    generated_by        TEXT NOT NULL DEFAULT 'system'
);

CREATE INDEX idx_compliance_reports_period ON security_compliance_reports (report_period_start DESC);

-- ---------------------------------------------------------------------------
-- Scan run log (tracks every CI/scheduled scan execution)
-- ---------------------------------------------------------------------------

CREATE TYPE scan_type AS ENUM (
    'dependency',
    'sast',
    'container',
    'secrets',
    'owasp_api',
    'infra_config'
);

CREATE TYPE scan_result AS ENUM ('passed', 'failed', 'error');

CREATE TABLE security_scan_runs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_type       scan_type NOT NULL,
    result          scan_result NOT NULL,
    findings_count  INT NOT NULL DEFAULT 0,
    new_critical    INT NOT NULL DEFAULT 0,
    new_high        INT NOT NULL DEFAULT 0,
    triggered_by    TEXT NOT NULL,   -- 'ci_pr', 'ci_merge', 'scheduled', 'manual'
    artifact_path   TEXT,
    raw_output      JSONB,
    started_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at    TIMESTAMPTZ
);

CREATE INDEX idx_scan_runs_type_started ON security_scan_runs (scan_type, started_at DESC);
