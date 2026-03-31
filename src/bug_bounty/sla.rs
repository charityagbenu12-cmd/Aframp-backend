use chrono::{DateTime, Duration, Utc};

use crate::bug_bounty::models::{BugBountyConfig, BugBountyReport, ReportStatus, Severity};

/// Compute `(acknowledgement_sla_deadline, triage_sla_deadline)` for a report
/// submitted at `submitted_at`.
pub fn compute_deadlines(
    submitted_at: DateTime<Utc>,
    config: &BugBountyConfig,
) -> (DateTime<Utc>, DateTime<Utc>) {
    let ack_deadline = submitted_at + Duration::hours(config.acknowledgement_sla_hours);
    let triage_deadline = submitted_at + Duration::hours(config.triage_sla_hours);
    (ack_deadline, triage_deadline)
}

/// Returns true when the acknowledgement SLA has been breached:
/// the report has not been acknowledged and the deadline has passed.
pub fn is_ack_breached(report: &BugBountyReport, now: DateTime<Utc>) -> bool {
    report.acknowledged_at.is_none() && now > report.acknowledgement_sla_deadline
}

/// Returns true when the triage SLA has been breached for `critical` or `high`
/// severity reports that have not yet been triaged.
pub fn is_triage_breached(report: &BugBountyReport, now: DateTime<Utc>) -> bool {
    let is_high_priority = matches!(report.severity, Severity::Critical | Severity::High);
    let not_triaged = report.triaged_at.is_none()
        && !matches!(
            report.status,
            ReportStatus::Triaged
                | ReportStatus::InRemediation
                | ReportStatus::Resolved
                | ReportStatus::Duplicate
                | ReportStatus::OutOfScope
                | ReportStatus::Rejected
        );
    is_high_priority && not_triaged && now > report.triage_sla_deadline
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use uuid::Uuid;

    fn default_config() -> BugBountyConfig {
        BugBountyConfig::default()
    }

    /// Build a minimal `BugBountyReport` for testing.
    fn make_report(
        severity: Severity,
        status: ReportStatus,
        acknowledged_at: Option<DateTime<Utc>>,
        triaged_at: Option<DateTime<Utc>>,
        submitted_at: DateTime<Utc>,
        config: &BugBountyConfig,
    ) -> BugBountyReport {
        let (ack_deadline, triage_deadline) = compute_deadlines(submitted_at, config);
        BugBountyReport {
            id: Uuid::new_v4(),
            researcher_id: "researcher-1".to_string(),
            severity,
            affected_component: "api/auth".to_string(),
            vulnerability_type: "sql-injection".to_string(),
            title: "Test Report".to_string(),
            description: "Test description".to_string(),
            proof_of_concept: None,
            submission_content: json!({}),
            status,
            duplicate_of: None,
            acknowledgement_sla_deadline: ack_deadline,
            triage_sla_deadline: triage_deadline,
            acknowledged_at,
            triaged_at,
            resolved_at: None,
            coordinated_disclosure_date: None,
            remediation_ref: None,
            source: "managed_platform".to_string(),
            created_at: submitted_at,
            updated_at: submitted_at,
        }
    }

    // -----------------------------------------------------------------------
    // compute_deadlines
    // -----------------------------------------------------------------------

    #[test]
    fn compute_deadlines_returns_24h_ack_and_72h_triage() {
        let config = default_config();
        let submitted_at = Utc::now();
        let (ack, triage) = compute_deadlines(submitted_at, &config);
        assert_eq!(ack, submitted_at + Duration::hours(24));
        assert_eq!(triage, submitted_at + Duration::hours(72));
    }

    // -----------------------------------------------------------------------
    // is_ack_breached
    // -----------------------------------------------------------------------

    #[test]
    fn unacknowledged_report_past_ack_deadline_is_breached() {
        let config = default_config();
        // submitted 25 hours ago → deadline was 1 hour ago
        let submitted_at = Utc::now() - Duration::hours(25);
        let report = make_report(
            Severity::Medium,
            ReportStatus::New,
            None,
            None,
            submitted_at,
            &config,
        );
        assert!(is_ack_breached(&report, Utc::now()));
    }

    #[test]
    fn acknowledged_report_past_ack_deadline_is_not_breached() {
        let config = default_config();
        let submitted_at = Utc::now() - Duration::hours(25);
        let acked_at = submitted_at + Duration::hours(1);
        let report = make_report(
            Severity::Medium,
            ReportStatus::Acknowledged,
            Some(acked_at),
            None,
            submitted_at,
            &config,
        );
        assert!(!is_ack_breached(&report, Utc::now()));
    }

    #[test]
    fn report_not_yet_past_ack_deadline_is_not_breached() {
        let config = default_config();
        // submitted 1 hour ago → deadline is 23 hours from now
        let submitted_at = Utc::now() - Duration::hours(1);
        let report = make_report(
            Severity::Medium,
            ReportStatus::New,
            None,
            None,
            submitted_at,
            &config,
        );
        assert!(!is_ack_breached(&report, Utc::now()));
    }

    // -----------------------------------------------------------------------
    // is_triage_breached
    // -----------------------------------------------------------------------

    #[test]
    fn critical_report_past_triage_deadline_not_triaged_is_breached() {
        let config = default_config();
        let submitted_at = Utc::now() - Duration::hours(73);
        let report = make_report(
            Severity::Critical,
            ReportStatus::New,
            None,
            None,
            submitted_at,
            &config,
        );
        assert!(is_triage_breached(&report, Utc::now()));
    }

    #[test]
    fn high_report_past_triage_deadline_not_triaged_is_breached() {
        let config = default_config();
        let submitted_at = Utc::now() - Duration::hours(73);
        let report = make_report(
            Severity::High,
            ReportStatus::New,
            None,
            None,
            submitted_at,
            &config,
        );
        assert!(is_triage_breached(&report, Utc::now()));
    }

    #[test]
    fn medium_report_past_triage_deadline_is_not_breached() {
        let config = default_config();
        let submitted_at = Utc::now() - Duration::hours(73);
        let report = make_report(
            Severity::Medium,
            ReportStatus::New,
            None,
            None,
            submitted_at,
            &config,
        );
        assert!(!is_triage_breached(&report, Utc::now()));
    }

    #[test]
    fn critical_report_past_triage_deadline_already_triaged_is_not_breached() {
        let config = default_config();
        let submitted_at = Utc::now() - Duration::hours(73);
        let triaged_at = submitted_at + Duration::hours(1);
        let report = make_report(
            Severity::Critical,
            ReportStatus::Triaged,
            None,
            Some(triaged_at),
            submitted_at,
            &config,
        );
        assert!(!is_triage_breached(&report, Utc::now()));
    }

    #[test]
    fn critical_report_past_triage_deadline_status_resolved_is_not_breached() {
        let config = default_config();
        let submitted_at = Utc::now() - Duration::hours(73);
        let report = make_report(
            Severity::Critical,
            ReportStatus::Resolved,
            None,
            None,
            submitted_at,
            &config,
        );
        assert!(!is_triage_breached(&report, Utc::now()));
    }
}
