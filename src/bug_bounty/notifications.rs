use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

use crate::bug_bounty::models::{
    BugBountyError, BugBountyReport, CommunicationLogEntry, RewardRecord,
};

// ---------------------------------------------------------------------------
// Repository trait
// ---------------------------------------------------------------------------

/// Persistence interface required by `NotificationDispatcher`.
/// Implemented by `BugBountyRepository` (Task 8); can be mocked in tests.
#[async_trait]
pub trait NotificationRepository: Send + Sync {
    async fn insert_communication_log_entry(
        &self,
        entry: &CommunicationLogEntry,
    ) -> Result<(), BugBountyError>;
}

// ---------------------------------------------------------------------------
// Notification types
// ---------------------------------------------------------------------------

/// Notification types emitted by the dispatcher.
#[derive(Debug, Clone)]
pub enum NotificationType {
    Acknowledgement,
    StatusUpdate,
    RewardDecision,
    CoordinatedDisclosure,
}

impl NotificationType {
    pub fn as_str(&self) -> &'static str {
        match self {
            NotificationType::Acknowledgement => "acknowledgement",
            NotificationType::StatusUpdate => "status_update",
            NotificationType::RewardDecision => "reward_decision",
            NotificationType::CoordinatedDisclosure => "coordinated_disclosure",
        }
    }
}

// ---------------------------------------------------------------------------
// Dispatcher
// ---------------------------------------------------------------------------

/// Dispatches outbound researcher notifications and persists each one to the
/// `communication_log` via the injected `NotificationRepository`.
pub struct NotificationDispatcher<R: NotificationRepository> {
    repository: Arc<R>,
}

impl<R: NotificationRepository> NotificationDispatcher<R> {
    pub fn new(repository: Arc<R>) -> Self {
        Self { repository }
    }

    // -----------------------------------------------------------------------
    // Private helper
    // -----------------------------------------------------------------------

    fn build_entry(
        report_id: Uuid,
        notification_type: &str,
        content: serde_json::Value,
    ) -> CommunicationLogEntry {
        CommunicationLogEntry {
            id: Uuid::new_v4(),
            report_id,
            direction: "outbound".to_string(),
            notification_type: notification_type.to_string(),
            content,
            sent_at: Utc::now(),
        }
    }

    // -----------------------------------------------------------------------
    // Public send methods
    // -----------------------------------------------------------------------

    /// Send an automated acknowledgement to the researcher (Requirement 5.1).
    pub async fn send_acknowledgement(
        &self,
        report: &BugBountyReport,
    ) -> Result<CommunicationLogEntry, BugBountyError> {
        let notification_type = NotificationType::Acknowledgement.as_str();
        let content = json!({
            "report_id": report.id,
            "researcher_id": report.researcher_id,
            "title": report.title,
            "acknowledgement_sla_deadline": report.acknowledgement_sla_deadline,
        });

        let entry = Self::build_entry(report.id, notification_type, content);
        self.repository
            .insert_communication_log_entry(&entry)
            .await?;

        tracing::info!(
            report_id = %report.id,
            researcher_id = %report.researcher_id,
            notification_type = notification_type,
            "Researcher notification sent"
        );

        Ok(entry)
    }

    /// Send a triage status update to the researcher (Requirement 5.2).
    pub async fn send_status_update(
        &self,
        report: &BugBountyReport,
    ) -> Result<CommunicationLogEntry, BugBountyError> {
        let notification_type = NotificationType::StatusUpdate.as_str();
        let content = json!({
            "report_id": report.id,
            "researcher_id": report.researcher_id,
            "new_status": report.status,
        });

        let entry = Self::build_entry(report.id, notification_type, content);
        self.repository
            .insert_communication_log_entry(&entry)
            .await?;

        tracing::info!(
            report_id = %report.id,
            researcher_id = %report.researcher_id,
            notification_type = notification_type,
            "Researcher notification sent"
        );

        Ok(entry)
    }

    /// Send a reward decision notification to the researcher (Requirement 5.3).
    pub async fn send_reward_decision(
        &self,
        report: &BugBountyReport,
        reward: &RewardRecord,
    ) -> Result<CommunicationLogEntry, BugBountyError> {
        let notification_type = NotificationType::RewardDecision.as_str();
        let content = json!({
            "report_id": report.id,
            "researcher_id": report.researcher_id,
            "reward_id": reward.id,
            "amount_usd": reward.amount_usd,
            "justification": reward.justification,
            "payment_initiated_at": reward.payment_initiated_at,
        });

        let entry = Self::build_entry(report.id, notification_type, content);
        self.repository
            .insert_communication_log_entry(&entry)
            .await?;

        tracing::info!(
            report_id = %report.id,
            researcher_id = %report.researcher_id,
            notification_type = notification_type,
            "Researcher notification sent"
        );

        Ok(entry)
    }

    /// Send a coordinated disclosure notification to the researcher (Requirement 5.4).
    pub async fn send_coordinated_disclosure(
        &self,
        report: &BugBountyReport,
        disclosure_date: DateTime<Utc>,
    ) -> Result<CommunicationLogEntry, BugBountyError> {
        let notification_type = NotificationType::CoordinatedDisclosure.as_str();
        let content = json!({
            "report_id": report.id,
            "researcher_id": report.researcher_id,
            "remediation_ref": report.remediation_ref,
            "coordinated_disclosure_date": disclosure_date,
        });

        let entry = Self::build_entry(report.id, notification_type, content);
        self.repository
            .insert_communication_log_entry(&entry)
            .await?;

        tracing::info!(
            report_id = %report.id,
            researcher_id = %report.researcher_id,
            notification_type = notification_type,
            "Researcher notification sent"
        );

        Ok(entry)
    }
}

// ---------------------------------------------------------------------------
// Disclosure date helper
// ---------------------------------------------------------------------------

/// Returns a coordinated disclosure date that is strictly after `resolved_at`.
/// Default: 90 days after resolution (Requirement 5.4, 12.5).
pub fn disclosure_date_after_resolution(resolved_at: DateTime<Utc>) -> DateTime<Utc> {
    resolved_at + Duration::days(90)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bug_bounty::models::{ReportStatus, Severity};
    use rust_decimal::Decimal;
    use serde_json::Value;
    use tokio::sync::Mutex as TokioMutex;

    // -----------------------------------------------------------------------
    // Mock repository
    // -----------------------------------------------------------------------

    struct MockRepo {
        entries: TokioMutex<Vec<CommunicationLogEntry>>,
    }

    impl MockRepo {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                entries: TokioMutex::new(Vec::new()),
            })
        }

        async fn captured(&self) -> Vec<CommunicationLogEntry> {
            self.entries.lock().await.clone()
        }
    }

    #[async_trait]
    impl NotificationRepository for MockRepo {
        async fn insert_communication_log_entry(
            &self,
            entry: &CommunicationLogEntry,
        ) -> Result<(), BugBountyError> {
            self.entries.lock().await.push(entry.clone());
            Ok(())
        }
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn make_report() -> BugBountyReport {
        let now = Utc::now();
        BugBountyReport {
            id: Uuid::new_v4(),
            researcher_id: "researcher-1".to_string(),
            severity: Severity::High,
            affected_component: "api".to_string(),
            vulnerability_type: "sqli".to_string(),
            title: "SQL Injection in /api/users".to_string(),
            description: "Details here".to_string(),
            proof_of_concept: None,
            submission_content: Value::Null,
            status: ReportStatus::New,
            duplicate_of: None,
            acknowledgement_sla_deadline: now + Duration::hours(24),
            triage_sla_deadline: now + Duration::hours(72),
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

    fn make_reward(report: &BugBountyReport) -> RewardRecord {
        let now = Utc::now();
        RewardRecord {
            id: Uuid::new_v4(),
            report_id: report.id,
            researcher_id: report.researcher_id.clone(),
            amount_usd: Decimal::new(2000, 0),
            justification: "Valid high-severity finding".to_string(),
            escalation_justification: None,
            payment_initiated_at: now,
            created_by: Uuid::new_v4(),
            created_at: now,
        }
    }

    // -----------------------------------------------------------------------
    // disclosure_date_after_resolution tests
    // -----------------------------------------------------------------------

    #[test]
    fn disclosure_date_is_strictly_after_resolved_at() {
        let resolved_at = Utc::now();
        let disclosure = disclosure_date_after_resolution(resolved_at);
        assert!(disclosure > resolved_at);
    }

    #[test]
    fn disclosure_date_is_90_days_after_resolved_at() {
        let resolved_at = Utc::now();
        let disclosure = disclosure_date_after_resolution(resolved_at);
        let expected = resolved_at + Duration::days(90);
        assert_eq!(disclosure, expected);
    }

    #[test]
    fn disclosure_date_with_epoch_timestamp() {
        let resolved_at = DateTime::<Utc>::from_timestamp(0, 0).unwrap();
        let disclosure = disclosure_date_after_resolution(resolved_at);
        assert!(disclosure > resolved_at);
    }

    #[test]
    fn disclosure_date_with_far_future_timestamp() {
        let resolved_at = DateTime::<Utc>::from_timestamp(9_999_999_999, 0).unwrap();
        let disclosure = disclosure_date_after_resolution(resolved_at);
        assert!(disclosure > resolved_at);
    }

    // -----------------------------------------------------------------------
    // send_acknowledgement
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn send_acknowledgement_produces_correct_notification_type() {
        let repo = MockRepo::new();
        let dispatcher = NotificationDispatcher::new(Arc::clone(&repo));
        let report = make_report();

        let entry = dispatcher.send_acknowledgement(&report).await.unwrap();

        assert_eq!(entry.notification_type, "acknowledgement");
        assert_eq!(entry.report_id, report.id);
        assert_eq!(entry.direction, "outbound");

        let captured = repo.captured().await;
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].notification_type, "acknowledgement");
    }

    // -----------------------------------------------------------------------
    // send_status_update
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn send_status_update_produces_correct_notification_type() {
        let repo = MockRepo::new();
        let dispatcher = NotificationDispatcher::new(Arc::clone(&repo));
        let report = make_report();

        let entry = dispatcher.send_status_update(&report).await.unwrap();

        assert_eq!(entry.notification_type, "status_update");
        assert_eq!(entry.report_id, report.id);
        assert_eq!(entry.direction, "outbound");

        let captured = repo.captured().await;
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].notification_type, "status_update");
    }

    // -----------------------------------------------------------------------
    // send_reward_decision
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn send_reward_decision_produces_correct_notification_type() {
        let repo = MockRepo::new();
        let dispatcher = NotificationDispatcher::new(Arc::clone(&repo));
        let report = make_report();
        let reward = make_reward(&report);

        let entry = dispatcher
            .send_reward_decision(&report, &reward)
            .await
            .unwrap();

        assert_eq!(entry.notification_type, "reward_decision");
        assert_eq!(entry.report_id, report.id);
        assert_eq!(entry.direction, "outbound");

        let captured = repo.captured().await;
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].notification_type, "reward_decision");
    }

    // -----------------------------------------------------------------------
    // send_coordinated_disclosure
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn send_coordinated_disclosure_produces_correct_notification_type() {
        let repo = MockRepo::new();
        let dispatcher = NotificationDispatcher::new(Arc::clone(&repo));
        let report = make_report();
        let disclosure_date = disclosure_date_after_resolution(Utc::now());

        let entry = dispatcher
            .send_coordinated_disclosure(&report, disclosure_date)
            .await
            .unwrap();

        assert_eq!(entry.notification_type, "coordinated_disclosure");
        assert_eq!(entry.report_id, report.id);
        assert_eq!(entry.direction, "outbound");

        let captured = repo.captured().await;
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].notification_type, "coordinated_disclosure");
    }
}
