//! Database repository for the security compliance framework.

use chrono::{DateTime, NaiveDate, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::security_compliance::models::{
    AllowlistEntry, CompliancePosture, ComplianceReport, ScanResult, ScanRun, ScanType,
    VulnSeverity, VulnSource, VulnStatus, Vulnerability, VulnHistoryEntry,
};

#[derive(Clone)]
pub struct SecurityComplianceRepository {
    pool: PgPool,
}

impl SecurityComplianceRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    // ── Vulnerability CRUD ────────────────────────────────────────────────────

    pub async fn insert_vulnerability(
        &self,
        vuln: &Vulnerability,
    ) -> Result<(), sqlx::Error> {
        sqlx::query!(
            r#"
            INSERT INTO security_vulnerabilities (
                id, title, description, severity, status, source,
                affected_component, cve_reference, affected_versions,
                remediation_guidance, discovered_at, sla_deadline,
                raw_finding, created_at, updated_at
            ) VALUES (
                $1, $2, $3, $4::vuln_severity, $5::vuln_status, $6::vuln_source,
                $7, $8, $9, $10, $11, $12, $13, $14, $15
            )
            "#,
            vuln.id,
            vuln.title,
            vuln.description,
            vuln.severity as VulnSeverity,
            vuln.status as VulnStatus,
            vuln.source as VulnSource,
            vuln.affected_component,
            vuln.cve_reference,
            vuln.affected_versions,
            vuln.remediation_guidance,
            vuln.discovered_at,
            vuln.sla_deadline,
            vuln.raw_finding,
            vuln.created_at,
            vuln.updated_at,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_vulnerability(&self, id: Uuid) -> Result<Option<VulnRow>, sqlx::Error> {
        let row = sqlx::query_as!(
            VulnRow,
            r#"
            SELECT
                id, title, description,
                severity AS "severity: VulnSeverity",
                status   AS "status: VulnStatus",
                source   AS "source: VulnSource",
                affected_component, cve_reference, affected_versions,
                remediation_guidance, discovered_at, sla_deadline,
                acknowledged_at, acknowledged_by, remediation_plan,
                resolved_at, resolved_by, remediation_notes, resolving_commit,
                risk_accepted_at, risk_accepted_by, risk_justification, risk_expiry_date,
                raw_finding, created_at, updated_at
            FROM security_vulnerabilities
            WHERE id = $1
            "#,
            id,
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    pub async fn list_vulnerabilities(
        &self,
        status_filter: Option<VulnStatus>,
        severity_filter: Option<VulnSeverity>,
        source_filter: Option<VulnSource>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<VulnRow>, sqlx::Error> {
        // Dynamic filtering via nullable params — sqlx doesn't support fully
        // dynamic WHERE clauses with query!, so we use query_as with a
        // hand-written query string.
        let rows = sqlx::query_as!(
            VulnRow,
            r#"
            SELECT
                id, title, description,
                severity AS "severity: VulnSeverity",
                status   AS "status: VulnStatus",
                source   AS "source: VulnSource",
                affected_component, cve_reference, affected_versions,
                remediation_guidance, discovered_at, sla_deadline,
                acknowledged_at, acknowledged_by, remediation_plan,
                resolved_at, resolved_by, remediation_notes, resolving_commit,
                risk_accepted_at, risk_accepted_by, risk_justification, risk_expiry_date,
                raw_finding, created_at, updated_at
            FROM security_vulnerabilities
            WHERE ($1::vuln_status IS NULL OR status = $1)
              AND ($2::vuln_severity IS NULL OR severity = $2)
              AND ($3::vuln_source IS NULL OR source = $3)
            ORDER BY
                CASE severity
                    WHEN 'critical' THEN 1
                    WHEN 'high'     THEN 2
                    WHEN 'medium'   THEN 3
                    WHEN 'low'      THEN 4
                    ELSE 5
                END,
                discovered_at DESC
            LIMIT $4 OFFSET $5
            "#,
            status_filter as Option<VulnStatus>,
            severity_filter as Option<VulnSeverity>,
            source_filter as Option<VulnSource>,
            limit,
            offset,
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    pub async fn count_vulnerabilities(
        &self,
        status_filter: Option<VulnStatus>,
        severity_filter: Option<VulnSeverity>,
        source_filter: Option<VulnSource>,
    ) -> Result<i64, sqlx::Error> {
        let count = sqlx::query_scalar!(
            r#"
            SELECT COUNT(*) FROM security_vulnerabilities
            WHERE ($1::vuln_status IS NULL OR status = $1)
              AND ($2::vuln_severity IS NULL OR severity = $2)
              AND ($3::vuln_source IS NULL OR source = $3)
            "#,
            status_filter as Option<VulnStatus>,
            severity_filter as Option<VulnSeverity>,
            source_filter as Option<VulnSource>,
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(count.unwrap_or(0))
    }

    /// Acknowledge a vulnerability.
    pub async fn acknowledge_vulnerability(
        &self,
        id: Uuid,
        acknowledged_by: &str,
        remediation_plan: &str,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query!(
            r#"
            UPDATE security_vulnerabilities
            SET status = 'acknowledged',
                acknowledged_at = NOW(),
                acknowledged_by = $2,
                remediation_plan = $3,
                updated_at = NOW()
            WHERE id = $1 AND status = 'open'
            "#,
            id,
            acknowledged_by,
            remediation_plan,
        )
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Resolve a vulnerability.
    pub async fn resolve_vulnerability(
        &self,
        id: Uuid,
        resolved_by: &str,
        remediation_notes: &str,
        resolving_commit: Option<&str>,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query!(
            r#"
            UPDATE security_vulnerabilities
            SET status = 'resolved',
                resolved_at = NOW(),
                resolved_by = $2,
                remediation_notes = $3,
                resolving_commit = $4,
                updated_at = NOW()
            WHERE id = $1 AND status IN ('open', 'acknowledged')
            "#,
            id,
            resolved_by,
            remediation_notes,
            resolving_commit,
        )
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Accept risk for a vulnerability.
    pub async fn accept_risk(
        &self,
        id: Uuid,
        accepted_by: &str,
        justification: &str,
        expiry_date: DateTime<Utc>,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query!(
            r#"
            UPDATE security_vulnerabilities
            SET status = 'risk_accepted',
                risk_accepted_at = NOW(),
                risk_accepted_by = $2,
                risk_justification = $3,
                risk_expiry_date = $4,
                updated_at = NOW()
            WHERE id = $1 AND status IN ('open', 'acknowledged')
            "#,
            id,
            accepted_by,
            justification,
            expiry_date,
        )
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Append a history entry.
    pub async fn append_history(
        &self,
        entry: &VulnHistoryEntry,
    ) -> Result<(), sqlx::Error> {
        sqlx::query!(
            r#"
            INSERT INTO security_vulnerability_history
                (id, vuln_id, old_status, new_status, changed_by, notes, changed_at)
            VALUES ($1, $2, $3::vuln_status, $4::vuln_status, $5, $6, $7)
            "#,
            entry.id,
            entry.vuln_id,
            entry.old_status as Option<VulnStatus>,
            entry.new_status as VulnStatus,
            entry.changed_by,
            entry.notes,
            entry.changed_at,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Fetch all open vulnerabilities (for posture scoring).
    pub async fn list_open_vulnerabilities(&self) -> Result<Vec<VulnRow>, sqlx::Error> {
        let rows = sqlx::query_as!(
            VulnRow,
            r#"
            SELECT
                id, title, description,
                severity AS "severity: VulnSeverity",
                status   AS "status: VulnStatus",
                source   AS "source: VulnSource",
                affected_component, cve_reference, affected_versions,
                remediation_guidance, discovered_at, sla_deadline,
                acknowledged_at, acknowledged_by, remediation_plan,
                resolved_at, resolved_by, remediation_notes, resolving_commit,
                risk_accepted_at, risk_accepted_by, risk_justification, risk_expiry_date,
                raw_finding, created_at, updated_at
            FROM security_vulnerabilities
            WHERE status IN ('open', 'acknowledged')
            ORDER BY severity DESC, sla_deadline ASC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    /// Fetch vulnerabilities approaching SLA deadline within `hours` hours.
    pub async fn list_approaching_sla_deadline(
        &self,
        hours: i64,
    ) -> Result<Vec<VulnRow>, sqlx::Error> {
        let rows = sqlx::query_as!(
            VulnRow,
            r#"
            SELECT
                id, title, description,
                severity AS "severity: VulnSeverity",
                status   AS "status: VulnStatus",
                source   AS "source: VulnSource",
                affected_component, cve_reference, affected_versions,
                remediation_guidance, discovered_at, sla_deadline,
                acknowledged_at, acknowledged_by, remediation_plan,
                resolved_at, resolved_by, remediation_notes, resolving_commit,
                risk_accepted_at, risk_accepted_by, risk_justification, risk_expiry_date,
                raw_finding, created_at, updated_at
            FROM security_vulnerabilities
            WHERE status IN ('open', 'acknowledged')
              AND sla_deadline BETWEEN NOW() AND NOW() + ($1 || ' hours')::INTERVAL
            ORDER BY sla_deadline ASC
            "#,
            hours.to_string(),
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    // ── Allowlist ─────────────────────────────────────────────────────────────

    pub async fn insert_allowlist_entry(
        &self,
        entry: &AllowlistEntry,
    ) -> Result<(), sqlx::Error> {
        sqlx::query!(
            r#"
            INSERT INTO security_vuln_allowlist
                (id, identifier, source, justification, added_by, expiry_date, created_at)
            VALUES ($1, $2, $3::vuln_source, $4, $5, $6, $7)
            ON CONFLICT (identifier) DO UPDATE
                SET justification = EXCLUDED.justification,
                    expiry_date   = EXCLUDED.expiry_date,
                    added_by      = EXCLUDED.added_by
            "#,
            entry.id,
            entry.identifier,
            entry.source as VulnSource,
            entry.justification,
            entry.added_by,
            entry.expiry_date,
            entry.created_at,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn is_allowlisted(&self, identifier: &str) -> Result<bool, sqlx::Error> {
        let count = sqlx::query_scalar!(
            r#"
            SELECT COUNT(*) FROM security_vuln_allowlist
            WHERE identifier = $1 AND expiry_date > NOW()
            "#,
            identifier,
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(count.unwrap_or(0) > 0)
    }

    pub async fn list_allowlist(&self) -> Result<Vec<AllowlistRow>, sqlx::Error> {
        let rows = sqlx::query_as!(
            AllowlistRow,
            r#"
            SELECT id, identifier, source AS "source: VulnSource",
                   justification, added_by, expiry_date, created_at
            FROM security_vuln_allowlist
            ORDER BY created_at DESC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    // ── Posture snapshots ─────────────────────────────────────────────────────

    pub async fn upsert_posture_snapshot(
        &self,
        snapshot: &CompliancePosture,
    ) -> Result<(), sqlx::Error> {
        sqlx::query!(
            r#"
            INSERT INTO security_posture_snapshots (
                id, snapshot_date, posture_score,
                open_critical, open_high, open_medium, open_low, open_informational,
                sla_breached_count, domain_breakdown, computed_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            ON CONFLICT (snapshot_date) DO UPDATE
                SET posture_score       = EXCLUDED.posture_score,
                    open_critical       = EXCLUDED.open_critical,
                    open_high           = EXCLUDED.open_high,
                    open_medium         = EXCLUDED.open_medium,
                    open_low            = EXCLUDED.open_low,
                    open_informational  = EXCLUDED.open_informational,
                    sla_breached_count  = EXCLUDED.sla_breached_count,
                    domain_breakdown    = EXCLUDED.domain_breakdown,
                    computed_at         = EXCLUDED.computed_at
            "#,
            snapshot.id,
            snapshot.snapshot_date,
            snapshot.posture_score,
            snapshot.open_critical,
            snapshot.open_high,
            snapshot.open_medium,
            snapshot.open_low,
            snapshot.open_informational,
            snapshot.sla_breached_count,
            snapshot.domain_breakdown,
            snapshot.computed_at,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn latest_posture_snapshot(
        &self,
    ) -> Result<Option<PostureRow>, sqlx::Error> {
        let row = sqlx::query_as!(
            PostureRow,
            r#"
            SELECT id, snapshot_date, posture_score,
                   open_critical, open_high, open_medium, open_low, open_informational,
                   sla_breached_count, domain_breakdown, computed_at
            FROM security_posture_snapshots
            ORDER BY snapshot_date DESC
            LIMIT 1
            "#,
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    pub async fn posture_snapshot_for_date(
        &self,
        date: NaiveDate,
    ) -> Result<Option<PostureRow>, sqlx::Error> {
        let row = sqlx::query_as!(
            PostureRow,
            r#"
            SELECT id, snapshot_date, posture_score,
                   open_critical, open_high, open_medium, open_low, open_informational,
                   sla_breached_count, domain_breakdown, computed_at
            FROM security_posture_snapshots
            WHERE snapshot_date = $1
            "#,
            date,
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    // ── Compliance reports ────────────────────────────────────────────────────

    pub async fn insert_compliance_report(
        &self,
        report: &ComplianceReport,
    ) -> Result<(), sqlx::Error> {
        sqlx::query!(
            r#"
            INSERT INTO security_compliance_reports (
                id, report_period_start, report_period_end,
                new_vulns_count, remediated_count, sla_breaches_count,
                posture_score_start, posture_score_end,
                report_data, generated_at, generated_by
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            "#,
            report.id,
            report.report_period_start,
            report.report_period_end,
            report.new_vulns_count,
            report.remediated_count,
            report.sla_breaches_count,
            report.posture_score_start,
            report.posture_score_end,
            report.report_data,
            report.generated_at,
            report.generated_by,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn list_compliance_reports(
        &self,
        limit: i64,
    ) -> Result<Vec<ReportRow>, sqlx::Error> {
        let rows = sqlx::query_as!(
            ReportRow,
            r#"
            SELECT id, report_period_start, report_period_end,
                   new_vulns_count, remediated_count, sla_breaches_count,
                   posture_score_start, posture_score_end,
                   report_data, generated_at, generated_by
            FROM security_compliance_reports
            ORDER BY report_period_start DESC
            LIMIT $1
            "#,
            limit,
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    /// Count new vulnerabilities discovered in a date range.
    pub async fn count_new_in_period(
        &self,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> Result<i64, sqlx::Error> {
        let count = sqlx::query_scalar!(
            "SELECT COUNT(*) FROM security_vulnerabilities WHERE discovered_at BETWEEN $1 AND $2",
            start,
            end,
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(count.unwrap_or(0))
    }

    /// Count vulnerabilities resolved in a date range.
    pub async fn count_resolved_in_period(
        &self,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> Result<i64, sqlx::Error> {
        let count = sqlx::query_scalar!(
            "SELECT COUNT(*) FROM security_vulnerabilities WHERE resolved_at BETWEEN $1 AND $2",
            start,
            end,
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(count.unwrap_or(0))
    }

    /// Count SLA breaches that occurred in a date range.
    pub async fn count_sla_breaches_in_period(
        &self,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> Result<i64, sqlx::Error> {
        let count = sqlx::query_scalar!(
            r#"
            SELECT COUNT(*) FROM security_vulnerabilities
            WHERE sla_deadline BETWEEN $1 AND $2
              AND status IN ('open', 'acknowledged')
            "#,
            start,
            end,
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(count.unwrap_or(0))
    }

    // ── Scan runs ─────────────────────────────────────────────────────────────

    pub async fn insert_scan_run(&self, run: &ScanRun) -> Result<(), sqlx::Error> {
        sqlx::query!(
            r#"
            INSERT INTO security_scan_runs (
                id, scan_type, result, findings_count, new_critical, new_high,
                triggered_by, artifact_path, raw_output, started_at, completed_at
            ) VALUES (
                $1, $2::scan_type, $3::scan_result, $4, $5, $6, $7, $8, $9, $10, $11
            )
            "#,
            run.id,
            run.scan_type as ScanType,
            run.result as ScanResult,
            run.findings_count,
            run.new_critical,
            run.new_high,
            run.triggered_by,
            run.artifact_path,
            run.raw_output,
            run.started_at,
            run.completed_at,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// sqlx FromRow structs (flat DB projections)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct VulnRow {
    pub id: Uuid,
    pub title: String,
    pub description: String,
    pub severity: VulnSeverity,
    pub status: VulnStatus,
    pub source: VulnSource,
    pub affected_component: String,
    pub cve_reference: Option<String>,
    pub affected_versions: Option<String>,
    pub remediation_guidance: Option<String>,
    pub discovered_at: DateTime<Utc>,
    pub sla_deadline: DateTime<Utc>,
    pub acknowledged_at: Option<DateTime<Utc>>,
    pub acknowledged_by: Option<String>,
    pub remediation_plan: Option<String>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub resolved_by: Option<String>,
    pub remediation_notes: Option<String>,
    pub resolving_commit: Option<String>,
    pub risk_accepted_at: Option<DateTime<Utc>>,
    pub risk_accepted_by: Option<String>,
    pub risk_justification: Option<String>,
    pub risk_expiry_date: Option<DateTime<Utc>>,
    pub raw_finding: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<VulnRow> for Vulnerability {
    fn from(r: VulnRow) -> Self {
        Vulnerability {
            id: r.id,
            title: r.title,
            description: r.description,
            severity: r.severity,
            status: r.status,
            source: r.source,
            affected_component: r.affected_component,
            cve_reference: r.cve_reference,
            affected_versions: r.affected_versions,
            remediation_guidance: r.remediation_guidance,
            discovered_at: r.discovered_at,
            sla_deadline: r.sla_deadline,
            acknowledged_at: r.acknowledged_at,
            acknowledged_by: r.acknowledged_by,
            remediation_plan: r.remediation_plan,
            resolved_at: r.resolved_at,
            resolved_by: r.resolved_by,
            remediation_notes: r.remediation_notes,
            resolving_commit: r.resolving_commit,
            risk_accepted_at: r.risk_accepted_at,
            risk_accepted_by: r.risk_accepted_by,
            risk_justification: r.risk_justification,
            risk_expiry_date: r.risk_expiry_date,
            raw_finding: r.raw_finding,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }
}

#[derive(Debug, sqlx::FromRow, serde::Serialize)]
pub struct AllowlistRow {
    pub id: Uuid,
    pub identifier: String,
    pub source: VulnSource,
    pub justification: String,
    pub added_by: String,
    pub expiry_date: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, sqlx::FromRow, serde::Serialize)]
pub struct PostureRow {
    pub id: Uuid,
    pub snapshot_date: NaiveDate,
    pub posture_score: sqlx::types::BigDecimal,
    pub open_critical: i32,
    pub open_high: i32,
    pub open_medium: i32,
    pub open_low: i32,
    pub open_informational: i32,
    pub sla_breached_count: i32,
    pub domain_breakdown: serde_json::Value,
    pub computed_at: DateTime<Utc>,
}

#[derive(Debug, sqlx::FromRow, serde::Serialize)]
pub struct ReportRow {
    pub id: Uuid,
    pub report_period_start: NaiveDate,
    pub report_period_end: NaiveDate,
    pub new_vulns_count: i32,
    pub remediated_count: i32,
    pub sla_breaches_count: i32,
    pub posture_score_start: Option<sqlx::types::BigDecimal>,
    pub posture_score_end: Option<sqlx::types::BigDecimal>,
    pub report_data: serde_json::Value,
    pub generated_at: DateTime<Utc>,
    pub generated_by: String,
}
