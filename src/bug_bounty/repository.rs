use async_trait::async_trait;
use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use sqlx::PgPool;
use std::collections::HashMap;
use uuid::Uuid;

use crate::bug_bounty::models::{
    BugBountyError, BugBountyReport, CommunicationLogEntry, ProgrammePhase, ProgrammeState,
    ReportStatus, ResearcherInvitation, RewardRecord, Severity,
};
use crate::bug_bounty::notifications::NotificationRepository;

/// Repository for all bug bounty database operations.
#[derive(Debug, Clone)]
pub struct BugBountyRepository {
    pub pool: PgPool,
}

impl BugBountyRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    // -------------------------------------------------------------------------
    // bug_bounty_reports
    // -------------------------------------------------------------------------

    pub async fn insert_report(&self, report: &BugBountyReport) -> Result<(), BugBountyError> {
        sqlx::query(
            r#"
            INSERT INTO bug_bounty_reports (
                id, researcher_id, severity, affected_component, vulnerability_type,
                title, description, proof_of_concept, submission_content, status,
                duplicate_of, acknowledgement_sla_deadline, triage_sla_deadline,
                acknowledged_at, triaged_at, resolved_at, coordinated_disclosure_date,
                remediation_ref, source, created_at, updated_at
            ) VALUES (
                $1, $2, $3::bb_severity, $4, $5,
                $6, $7, $8, $9, $10::bb_report_status,
                $11, $12, $13,
                $14, $15, $16, $17,
                $18, $19, $20, $21
            )
            "#,
        )
        .bind(report.id)
        .bind(&report.researcher_id)
        .bind(severity_to_str(&report.severity))
        .bind(&report.affected_component)
        .bind(&report.vulnerability_type)
        .bind(&report.title)
        .bind(&report.description)
        .bind(&report.proof_of_concept)
        .bind(&report.submission_content)
        .bind(status_to_str(&report.status))
        .bind(report.duplicate_of)
        .bind(report.acknowledgement_sla_deadline)
        .bind(report.triage_sla_deadline)
        .bind(report.acknowledged_at)
        .bind(report.triaged_at)
        .bind(report.resolved_at)
        .bind(report.coordinated_disclosure_date)
        .bind(&report.remediation_ref)
        .bind(&report.source)
        .bind(report.created_at)
        .bind(report.updated_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn find_report_by_id(
        &self,
        id: Uuid,
    ) -> Result<Option<BugBountyReport>, BugBountyError> {
        let row: Option<BugBountyReportRow> = sqlx::query_as(
            r#"
            SELECT
                id, researcher_id,
                severity::TEXT AS severity,
                affected_component, vulnerability_type,
                title, description, proof_of_concept, submission_content,
                status::TEXT AS status,
                duplicate_of, acknowledgement_sla_deadline, triage_sla_deadline,
                acknowledged_at, triaged_at, resolved_at, coordinated_disclosure_date,
                remediation_ref, source, created_at, updated_at
            FROM bug_bounty_reports
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(BugBountyReport::from))
    }

    /// Returns `(reports, total_count)`.
    #[allow(clippy::integer_arithmetic)]
    pub async fn list_reports_paginated(
        &self,
        page: u32,
        per_page: u32,
    ) -> Result<(Vec<BugBountyReport>, i64), BugBountyError> {
        let offset = i64::from(page.saturating_sub(1)) * i64::from(per_page);
        let limit = i64::from(per_page);

        let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM bug_bounty_reports")
            .fetch_one(&self.pool)
            .await?;

        let rows: Vec<BugBountyReportRow> = sqlx::query_as(
            r#"
            SELECT
                id, researcher_id,
                severity::TEXT AS severity,
                affected_component, vulnerability_type,
                title, description, proof_of_concept, submission_content,
                status::TEXT AS status,
                duplicate_of, acknowledgement_sla_deadline, triage_sla_deadline,
                acknowledged_at, triaged_at, resolved_at, coordinated_disclosure_date,
                remediation_ref, source, created_at, updated_at
            FROM bug_bounty_reports
            ORDER BY created_at DESC
            LIMIT $1 OFFSET $2
            "#,
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        Ok((rows.into_iter().map(BugBountyReport::from).collect(), total))
    }

    pub async fn update_report(
        &self,
        id: Uuid,
        status: Option<&ReportStatus>,
        severity: Option<&Severity>,
        acknowledged_at: Option<DateTime<Utc>>,
        triaged_at: Option<DateTime<Utc>>,
        resolved_at: Option<DateTime<Utc>>,
        coordinated_disclosure_date: Option<DateTime<Utc>>,
        remediation_ref: Option<&str>,
        duplicate_of: Option<Uuid>,
        updated_at: DateTime<Utc>,
    ) -> Result<BugBountyReport, BugBountyError> {
        let row: Option<BugBountyReportRow> = sqlx::query_as(
            r#"
            UPDATE bug_bounty_reports SET
                status                      = COALESCE($2::bb_report_status, status),
                severity                    = COALESCE($3::bb_severity, severity),
                acknowledged_at             = COALESCE($4, acknowledged_at),
                triaged_at                  = COALESCE($5, triaged_at),
                resolved_at                 = COALESCE($6, resolved_at),
                coordinated_disclosure_date = COALESCE($7, coordinated_disclosure_date),
                remediation_ref             = COALESCE($8, remediation_ref),
                duplicate_of                = COALESCE($9, duplicate_of),
                updated_at                  = $10
            WHERE id = $1
            RETURNING
                id, researcher_id,
                severity::TEXT AS severity,
                affected_component, vulnerability_type,
                title, description, proof_of_concept, submission_content,
                status::TEXT AS status,
                duplicate_of, acknowledgement_sla_deadline, triage_sla_deadline,
                acknowledged_at, triaged_at, resolved_at, coordinated_disclosure_date,
                remediation_ref, source, created_at, updated_at
            "#,
        )
        .bind(id)
        .bind(status.map(status_to_str))
        .bind(severity.map(severity_to_str))
        .bind(acknowledged_at)
        .bind(triaged_at)
        .bind(resolved_at)
        .bind(coordinated_disclosure_date)
        .bind(remediation_ref)
        .bind(duplicate_of)
        .bind(updated_at)
        .fetch_optional(&self.pool)
        .await?;

        row.map(BugBountyReport::from)
            .ok_or(BugBountyError::ReportNotFound)
    }

    /// Returns reports whose status is NOT one of: duplicate, out_of_scope, rejected, resolved.
    pub async fn find_open_reports(&self) -> Result<Vec<BugBountyReport>, BugBountyError> {
        let rows: Vec<BugBountyReportRow> = sqlx::query_as(
            r#"
            SELECT
                id, researcher_id,
                severity::TEXT AS severity,
                affected_component, vulnerability_type,
                title, description, proof_of_concept, submission_content,
                status::TEXT AS status,
                duplicate_of, acknowledgement_sla_deadline, triage_sla_deadline,
                acknowledged_at, triaged_at, resolved_at, coordinated_disclosure_date,
                remediation_ref, source, created_at, updated_at
            FROM bug_bounty_reports
            WHERE status NOT IN (
                'duplicate'::bb_report_status,
                'out_of_scope'::bb_report_status,
                'rejected'::bb_report_status,
                'resolved'::bb_report_status
            )
            ORDER BY created_at DESC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(BugBountyReport::from).collect())
    }

    // -------------------------------------------------------------------------
    // communication_log
    // -------------------------------------------------------------------------

    pub async fn insert_communication_log_entry(
        &self,
        entry: &CommunicationLogEntry,
    ) -> Result<(), BugBountyError> {
        sqlx::query(
            r#"
            INSERT INTO communication_log (id, report_id, direction, notification_type, content, sent_at)
            VALUES ($1, $2, $3, $4, $5, $6)
            "#,
        )
        .bind(entry.id)
        .bind(entry.report_id)
        .bind(&entry.direction)
        .bind(&entry.notification_type)
        .bind(&entry.content)
        .bind(entry.sent_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn list_communication_log_for_report(
        &self,
        report_id: Uuid,
    ) -> Result<Vec<CommunicationLogEntry>, BugBountyError> {
        let entries: Vec<CommunicationLogEntry> = sqlx::query_as(
            r#"
            SELECT id, report_id, direction, notification_type, content, sent_at
            FROM communication_log
            WHERE report_id = $1
            ORDER BY sent_at ASC
            "#,
        )
        .bind(report_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(entries)
    }

    // -------------------------------------------------------------------------
    // reward_records
    // -------------------------------------------------------------------------

    pub async fn insert_reward_record(&self, record: &RewardRecord) -> Result<(), BugBountyError> {
        sqlx::query(
            r#"
            INSERT INTO reward_records (
                id, report_id, researcher_id, amount_usd, justification,
                escalation_justification, payment_initiated_at, created_by, created_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            "#,
        )
        .bind(record.id)
        .bind(record.report_id)
        .bind(&record.researcher_id)
        .bind(record.amount_usd)
        .bind(&record.justification)
        .bind(&record.escalation_justification)
        .bind(record.payment_initiated_at)
        .bind(record.created_by)
        .bind(record.created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn find_rewards_by_report(
        &self,
        report_id: Uuid,
    ) -> Result<Vec<RewardRecord>, BugBountyError> {
        let records: Vec<RewardRecord> = sqlx::query_as(
            r#"
            SELECT id, report_id, researcher_id, amount_usd, justification,
                   escalation_justification, payment_initiated_at, created_by, created_at
            FROM reward_records
            WHERE report_id = $1
            ORDER BY created_at ASC
            "#,
        )
        .bind(report_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(records)
    }

    /// Returns a map of researcher_id → total rewards paid.
    pub async fn sum_rewards_by_researcher(
        &self,
    ) -> Result<HashMap<String, Decimal>, BugBountyError> {
        let rows: Vec<(String, Decimal)> = sqlx::query_as(
            r#"
            SELECT researcher_id, SUM(amount_usd) AS total
            FROM reward_records
            GROUP BY researcher_id
            "#,
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().collect())
    }

    /// Returns a map of vulnerability_type → total rewards paid.
    pub async fn sum_rewards_by_vuln_type(
        &self,
    ) -> Result<HashMap<String, Decimal>, BugBountyError> {
        let rows: Vec<(String, Decimal)> = sqlx::query_as(
            r#"
            SELECT r.vulnerability_type, SUM(rr.amount_usd) AS total
            FROM reward_records rr
            JOIN bug_bounty_reports r ON r.id = rr.report_id
            GROUP BY r.vulnerability_type
            "#,
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().collect())
    }

    /// Returns a map of "YYYY-MM" → total rewards paid in that calendar month.
    pub async fn sum_rewards_by_month(&self) -> Result<HashMap<String, Decimal>, BugBountyError> {
        let rows: Vec<(String, Decimal)> = sqlx::query_as(
            r#"
            SELECT TO_CHAR(DATE_TRUNC('month', created_at), 'YYYY-MM') AS month,
                   SUM(amount_usd) AS total
            FROM reward_records
            GROUP BY DATE_TRUNC('month', created_at)
            ORDER BY DATE_TRUNC('month', created_at)
            "#,
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().collect())
    }

    // -------------------------------------------------------------------------
    // researcher_invitations
    // -------------------------------------------------------------------------

    pub async fn insert_invitation(
        &self,
        invitation: &ResearcherInvitation,
    ) -> Result<(), BugBountyError> {
        sqlx::query(
            r#"
            INSERT INTO researcher_invitations (
                id, researcher_id, status, created_by, created_at, revoked_at, revoked_by
            ) VALUES ($1, $2, $3, $4, $5, $6, $7)
            "#,
        )
        .bind(invitation.id)
        .bind(&invitation.researcher_id)
        .bind(&invitation.status)
        .bind(invitation.created_by)
        .bind(invitation.created_at)
        .bind(invitation.revoked_at)
        .bind(invitation.revoked_by)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn list_active_invitations(
        &self,
    ) -> Result<Vec<ResearcherInvitation>, BugBountyError> {
        let invitations: Vec<ResearcherInvitation> = sqlx::query_as(
            r#"
            SELECT id, researcher_id, status, created_by, created_at, revoked_at, revoked_by
            FROM researcher_invitations
            WHERE status = 'active'
            ORDER BY created_at DESC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(invitations)
    }

    pub async fn find_invitation_by_researcher(
        &self,
        researcher_id: &str,
    ) -> Result<Option<ResearcherInvitation>, BugBountyError> {
        let invitation: Option<ResearcherInvitation> = sqlx::query_as(
            r#"
            SELECT id, researcher_id, status, created_by, created_at, revoked_at, revoked_by
            FROM researcher_invitations
            WHERE researcher_id = $1
            "#,
        )
        .bind(researcher_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(invitation)
    }

    // -------------------------------------------------------------------------
    // programme_state
    // -------------------------------------------------------------------------

    pub async fn get_programme_state(&self) -> Result<ProgrammeState, BugBountyError> {
        let row: Option<ProgrammeStateRow> = sqlx::query_as(
            r#"
            SELECT id, phase::TEXT AS phase, launched_at,
                   transitioned_to_public_at, transitioned_by
            FROM programme_state
            LIMIT 1
            "#,
        )
        .fetch_optional(&self.pool)
        .await?;

        row.map(ProgrammeState::from)
            .ok_or_else(|| BugBountyError::DatabaseError(sqlx::Error::RowNotFound))
    }

    pub async fn update_programme_phase(
        &self,
        phase: &ProgrammePhase,
        transitioned_to_public_at: Option<DateTime<Utc>>,
        transitioned_by: Option<Uuid>,
    ) -> Result<ProgrammeState, BugBountyError> {
        let row: Option<ProgrammeStateRow> = sqlx::query_as(
            r#"
            UPDATE programme_state SET
                phase                     = $1::bb_programme_phase,
                transitioned_to_public_at = COALESCE($2, transitioned_to_public_at),
                transitioned_by           = COALESCE($3, transitioned_by)
            RETURNING id, phase::TEXT AS phase, launched_at,
                      transitioned_to_public_at, transitioned_by
            "#,
        )
        .bind(phase_to_str(phase))
        .bind(transitioned_to_public_at)
        .bind(transitioned_by)
        .fetch_optional(&self.pool)
        .await?;

        row.map(ProgrammeState::from)
            .ok_or_else(|| BugBountyError::DatabaseError(sqlx::Error::RowNotFound))
    }
}

// ---------------------------------------------------------------------------
// NotificationRepository impl
// ---------------------------------------------------------------------------

#[async_trait]
impl NotificationRepository for BugBountyRepository {
    async fn insert_communication_log_entry(
        &self,
        entry: &CommunicationLogEntry,
    ) -> Result<(), BugBountyError> {
        self.insert_communication_log_entry(entry).await
    }
}

// ---------------------------------------------------------------------------
// Flat DB row types for runtime query mapping
// ---------------------------------------------------------------------------

/// Flat row returned by runtime queries against `bug_bounty_reports`.
/// Enum columns are cast to TEXT and parsed manually.
#[derive(sqlx::FromRow)]
struct BugBountyReportRow {
    pub id: Uuid,
    pub researcher_id: String,
    pub severity: String,
    pub affected_component: String,
    pub vulnerability_type: String,
    pub title: String,
    pub description: String,
    pub proof_of_concept: Option<String>,
    pub submission_content: serde_json::Value,
    pub status: String,
    pub duplicate_of: Option<Uuid>,
    pub acknowledgement_sla_deadline: DateTime<Utc>,
    pub triage_sla_deadline: DateTime<Utc>,
    pub acknowledged_at: Option<DateTime<Utc>>,
    pub triaged_at: Option<DateTime<Utc>>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub coordinated_disclosure_date: Option<DateTime<Utc>>,
    pub remediation_ref: Option<String>,
    pub source: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<BugBountyReportRow> for BugBountyReport {
    fn from(r: BugBountyReportRow) -> Self {
        BugBountyReport {
            id: r.id,
            researcher_id: r.researcher_id,
            severity: parse_severity(&r.severity),
            affected_component: r.affected_component,
            vulnerability_type: r.vulnerability_type,
            title: r.title,
            description: r.description,
            proof_of_concept: r.proof_of_concept,
            submission_content: r.submission_content,
            status: parse_status(&r.status),
            duplicate_of: r.duplicate_of,
            acknowledgement_sla_deadline: r.acknowledgement_sla_deadline,
            triage_sla_deadline: r.triage_sla_deadline,
            acknowledged_at: r.acknowledged_at,
            triaged_at: r.triaged_at,
            resolved_at: r.resolved_at,
            coordinated_disclosure_date: r.coordinated_disclosure_date,
            remediation_ref: r.remediation_ref,
            source: r.source,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }
}

/// Flat row for `programme_state` (phase cast to TEXT).
#[derive(sqlx::FromRow)]
struct ProgrammeStateRow {
    pub id: Uuid,
    pub phase: String,
    pub launched_at: DateTime<Utc>,
    pub transitioned_to_public_at: Option<DateTime<Utc>>,
    pub transitioned_by: Option<Uuid>,
}

impl From<ProgrammeStateRow> for ProgrammeState {
    fn from(r: ProgrammeStateRow) -> Self {
        ProgrammeState {
            id: r.id,
            phase: parse_phase(&r.phase),
            launched_at: r.launched_at,
            transitioned_to_public_at: r.transitioned_to_public_at,
            transitioned_by: r.transitioned_by,
        }
    }
}

// ---------------------------------------------------------------------------
// Enum ↔ &str helpers
// ---------------------------------------------------------------------------

fn severity_to_str(s: &Severity) -> &'static str {
    match s {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Informational => "informational",
    }
}

fn parse_severity(s: &str) -> Severity {
    match s {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Informational,
    }
}

fn status_to_str(s: &ReportStatus) -> &'static str {
    match s {
        ReportStatus::New => "new",
        ReportStatus::Acknowledged => "acknowledged",
        ReportStatus::Triaged => "triaged",
        ReportStatus::InRemediation => "in_remediation",
        ReportStatus::Resolved => "resolved",
        ReportStatus::Duplicate => "duplicate",
        ReportStatus::OutOfScope => "out_of_scope",
        ReportStatus::Rejected => "rejected",
    }
}

fn parse_status(s: &str) -> ReportStatus {
    match s {
        "acknowledged" => ReportStatus::Acknowledged,
        "triaged" => ReportStatus::Triaged,
        "in_remediation" => ReportStatus::InRemediation,
        "resolved" => ReportStatus::Resolved,
        "duplicate" => ReportStatus::Duplicate,
        "out_of_scope" => ReportStatus::OutOfScope,
        "rejected" => ReportStatus::Rejected,
        _ => ReportStatus::New,
    }
}

fn phase_to_str(p: &ProgrammePhase) -> &'static str {
    match p {
        ProgrammePhase::Private => "private",
        ProgrammePhase::Public => "public",
    }
}

fn parse_phase(s: &str) -> ProgrammePhase {
    match s {
        "public" => ProgrammePhase::Public,
        _ => ProgrammePhase::Private,
    }
}
