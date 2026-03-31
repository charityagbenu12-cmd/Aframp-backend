use uuid::Uuid;

use crate::bug_bounty::models::{BugBountyReport, CreateReportRequest, ReportStatus};

/// Returns true if `new` matches an existing open report on both
/// `affected_component` AND `vulnerability_type`.
pub fn is_duplicate(new: &CreateReportRequest, existing: &[BugBountyReport]) -> bool {
    find_original(new, existing).is_some()
}

/// Returns the ID of the first open report that matches `new` on both
/// `affected_component` and `vulnerability_type`, or `None` if no match.
pub fn find_original(new: &CreateReportRequest, existing: &[BugBountyReport]) -> Option<Uuid> {
    existing
        .iter()
        .filter(|r| {
            !matches!(
                r.status,
                ReportStatus::Duplicate
                    | ReportStatus::OutOfScope
                    | ReportStatus::Rejected
                    | ReportStatus::Resolved
            )
        })
        .find(|r| {
            r.affected_component.eq_ignore_ascii_case(&new.affected_component)
                && r.vulnerability_type.eq_ignore_ascii_case(&new.vulnerability_type)
        })
        .map(|r| r.id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use serde_json::json;
    use crate::bug_bounty::models::Severity;

    /// Build a minimal `BugBountyReport` with sensible defaults for testing.
    fn make_report(
        affected_component: &str,
        vulnerability_type: &str,
        status: ReportStatus,
    ) -> BugBountyReport {
        let now = Utc::now();
        BugBountyReport {
            id: Uuid::new_v4(),
            researcher_id: "researcher-1".to_string(),
            severity: Severity::Medium,
            affected_component: affected_component.to_string(),
            vulnerability_type: vulnerability_type.to_string(),
            title: "Test Report".to_string(),
            description: "Test description".to_string(),
            proof_of_concept: None,
            submission_content: json!({}),
            status,
            duplicate_of: None,
            acknowledgement_sla_deadline: now + chrono::Duration::hours(24),
            triage_sla_deadline: now + chrono::Duration::hours(72),
            acknowledged_at: None,
            triaged_at: None,
            resolved_at: None,
            coordinated_disclosure_date: None,
            remediation_ref: None,
            source: "managed_platform".to_string(),
            created_at: now,
            updated_at: now,
        }
    }

    fn make_request(affected_component: &str, vulnerability_type: &str) -> CreateReportRequest {
        CreateReportRequest {
            researcher_id: "researcher-2".to_string(),
            severity: Severity::Medium,
            affected_component: affected_component.to_string(),
            vulnerability_type: vulnerability_type.to_string(),
            title: "New Report".to_string(),
            description: "New description".to_string(),
            proof_of_concept: None,
            submission_content: json!({}),
        }
    }

    #[test]
    fn same_component_and_same_vuln_type_is_duplicate() {
        let existing = vec![make_report("api/auth", "sql-injection", ReportStatus::New)];
        let new = make_request("api/auth", "sql-injection");
        assert!(is_duplicate(&new, &existing));
    }

    #[test]
    fn same_component_different_vuln_type_is_not_duplicate() {
        let existing = vec![make_report("api/auth", "sql-injection", ReportStatus::New)];
        let new = make_request("api/auth", "xss");
        assert!(!is_duplicate(&new, &existing));
    }

    #[test]
    fn different_component_same_vuln_type_is_not_duplicate() {
        let existing = vec![make_report("api/auth", "sql-injection", ReportStatus::New)];
        let new = make_request("api/payments", "sql-injection");
        assert!(!is_duplicate(&new, &existing));
    }

    #[test]
    fn empty_existing_reports_is_not_duplicate() {
        let new = make_request("api/auth", "sql-injection");
        assert!(!is_duplicate(&new, &[]));
    }

    #[test]
    fn matching_report_with_status_resolved_is_not_duplicate() {
        let existing = vec![make_report("api/auth", "sql-injection", ReportStatus::Resolved)];
        let new = make_request("api/auth", "sql-injection");
        assert!(!is_duplicate(&new, &existing));
    }

    #[test]
    fn matching_report_with_status_duplicate_is_not_duplicate() {
        let existing = vec![make_report("api/auth", "sql-injection", ReportStatus::Duplicate)];
        let new = make_request("api/auth", "sql-injection");
        assert!(!is_duplicate(&new, &existing));
    }

    #[test]
    fn matching_is_case_insensitive() {
        let existing = vec![make_report("API/Auth", "SQL-Injection", ReportStatus::New)];
        let new = make_request("api/auth", "sql-injection");
        assert!(is_duplicate(&new, &existing));
    }

    #[test]
    fn find_original_returns_correct_id() {
        let report = make_report("api/auth", "sql-injection", ReportStatus::New);
        let expected_id = report.id;
        let existing = vec![report];
        let new = make_request("api/auth", "sql-injection");
        assert_eq!(find_original(&new, &existing), Some(expected_id));
    }

    #[test]
    fn find_original_returns_none_when_no_match() {
        let existing = vec![make_report("api/auth", "sql-injection", ReportStatus::New)];
        let new = make_request("api/payments", "xss");
        assert_eq!(find_original(&new, &existing), None);
    }
}
