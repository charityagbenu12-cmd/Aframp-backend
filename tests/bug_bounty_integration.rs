//! Integration tests for the Bug Bounty Programme subsystem.
//!
//! These tests exercise the full report lifecycle and key programme workflows
//! using in-memory mock implementations of the repository layer, so they run
//! without a live PostgreSQL database.
//!
//! Tests that require a real database are gated with `#[cfg(feature = "integration")]`
//! and follow the same pattern as `tests/pentest_integration.rs`.
//!
//! The mock-based tests (no feature gate) exercise the service-layer business
//! logic end-to-end by calling the pure functions in `duplicate`, `sla`,
//! `rewards`, `transition`, and `notifications` directly, mirroring what
//! `BugBountyService` does internally.

// ---------------------------------------------------------------------------
// Shared helpers and mock types
// ---------------------------------------------------------------------------

#[cfg(test)]
mod helpers {
    use chrono::{DateTime, Duration, Utc};
    use rust_decimal::Decimal;
    use serde_json::json;
    use std::collections::HashMap;
    use uuid::Uuid;

    pub use Bitmesh_backend::bug_bounty::models::{
        BugBountyConfig, BugBountyReport, CommunicationLogEntry, CreateInvitationRequest,
        CreateReportRequest, ProgrammePhase, ProgrammeState, RecordRewardRequest, ReportStatus,
        ResearcherInvitation, RewardRecord, Severity, TransitionResult, UnmetCriterion,
        UpdateReportRequest,
    };
    pub use Bitmesh_backend::bug_bounty::notifications::{
        disclosure_date_after_resolution, NotificationDispatcher, NotificationRepository,
    };
    pub use Bitmesh_backend::bug_bounty::transition::ProgrammeStats;
    pub use Bitmesh_backend::bug_bounty::{duplicate, notifications, rewards, sla, transition};

    use async_trait::async_trait;
    use std::sync::Arc;
    use tokio::sync::Mutex;

    // -----------------------------------------------------------------------
    // In-memory mock repository
    // -----------------------------------------------------------------------

    /// Thread-safe in-memory store used by all integration tests.
    pub struct MockStore {
        pub reports: Mutex<Vec<BugBountyReport>>,
        pub comm_log: Mutex<Vec<CommunicationLogEntry>>,
        pub rewards: Mutex<Vec<RewardRecord>>,
        pub invitations: Mutex<Vec<ResearcherInvitation>>,
        pub programme_state: Mutex<ProgrammeState>,
    }

    impl MockStore {
        fn make_state(phase: ProgrammePhase, launched_at: DateTime<Utc>) -> ProgrammeState {
            ProgrammeState {
                id: Uuid::new_v4(),
                phase,
                launched_at,
                transitioned_to_public_at: None,
                transitioned_by: None,
            }
        }

        pub fn new(phase: ProgrammePhase) -> Arc<Self> {
            Arc::new(Self {
                reports: Mutex::new(Vec::new()),
                comm_log: Mutex::new(Vec::new()),
                rewards: Mutex::new(Vec::new()),
                invitations: Mutex::new(Vec::new()),
                programme_state: Mutex::new(Self::make_state(
                    phase,
                    Utc::now() - Duration::days(31),
                )),
            })
        }

        pub fn new_with_launch(phase: ProgrammePhase, launched_at: DateTime<Utc>) -> Arc<Self> {
            Arc::new(Self {
                reports: Mutex::new(Vec::new()),
                comm_log: Mutex::new(Vec::new()),
                rewards: Mutex::new(Vec::new()),
                invitations: Mutex::new(Vec::new()),
                programme_state: Mutex::new(Self::make_state(phase, launched_at)),
            })
        }
    }

    #[async_trait]
    impl NotificationRepository for MockStore {
        async fn insert_communication_log_entry(
            &self,
            entry: &CommunicationLogEntry,
        ) -> Result<(), Bitmesh_backend::bug_bounty::models::BugBountyError> {
            self.comm_log.lock().await.push(entry.clone());
            Ok(())
        }
    }

    // -----------------------------------------------------------------------
    // Service-layer helpers (replicate BugBountyService logic inline)
    // -----------------------------------------------------------------------

    /// Create a report, run duplicate detection, compute SLA deadlines,
    /// persist to the mock store, and dispatch an acknowledgement notification.
    pub async fn create_report(
        store: &Arc<MockStore>,
        dispatcher: &NotificationDispatcher<MockStore>,
        req: CreateReportRequest,
        config: &BugBountyConfig,
    ) -> Result<BugBountyReport, Bitmesh_backend::bug_bounty::models::BugBountyError> {
        // Private-phase invitation check
        let phase = store.programme_state.lock().await.phase.clone();
        if phase == ProgrammePhase::Private {
            let invitations = store.invitations.lock().await;
            let has_valid = invitations
                .iter()
                .any(|i| i.researcher_id == req.researcher_id && i.status == "active");
            if !has_valid {
                return Err(
                    Bitmesh_backend::bug_bounty::models::BugBountyError::InvitationRequired,
                );
            }
        }

        // Duplicate detection
        let open_reports: Vec<BugBountyReport> = store
            .reports
            .lock()
            .await
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
            .cloned()
            .collect();

        let original_id = duplicate::find_original(&req, &open_reports);
        let is_duplicate = original_id.is_some();
        let status = if is_duplicate {
            ReportStatus::Duplicate
        } else {
            ReportStatus::New
        };

        // SLA deadlines
        let now = Utc::now();
        let (ack_deadline, triage_deadline) = sla::compute_deadlines(now, config);

        let report = BugBountyReport {
            id: Uuid::new_v4(),
            researcher_id: req.researcher_id.clone(),
            severity: req.severity.clone(),
            affected_component: req.affected_component.clone(),
            vulnerability_type: req.vulnerability_type.clone(),
            title: req.title.clone(),
            description: req.description.clone(),
            proof_of_concept: req.proof_of_concept.clone(),
            submission_content: req.submission_content.clone(),
            status,
            duplicate_of: original_id,
            acknowledgement_sla_deadline: ack_deadline,
            triage_sla_deadline: triage_deadline,
            acknowledged_at: None,
            triaged_at: None,
            resolved_at: None,
            coordinated_disclosure_date: None,
            remediation_ref: None,
            source: "managed_platform".to_string(),
            created_at: now,
            updated_at: now,
        };

        store.reports.lock().await.push(report.clone());
        dispatcher.send_acknowledgement(&report).await?;

        Ok(report)
    }

    /// Update a report's status in the mock store, setting timestamp fields
    /// automatically (mirrors BugBountyService::update_report).
    pub async fn update_report_status(
        store: &Arc<MockStore>,
        dispatcher: &NotificationDispatcher<MockStore>,
        report_id: Uuid,
        new_status: ReportStatus,
    ) -> Result<BugBountyReport, Bitmesh_backend::bug_bounty::models::BugBountyError> {
        let now = Utc::now();
        let mut reports = store.reports.lock().await;
        let report = reports
            .iter_mut()
            .find(|r| r.id == report_id)
            .ok_or(Bitmesh_backend::bug_bounty::models::BugBountyError::ReportNotFound)?;

        match &new_status {
            ReportStatus::Acknowledged if report.acknowledged_at.is_none() => {
                report.acknowledged_at = Some(now);
            }
            ReportStatus::Triaged if report.triaged_at.is_none() => {
                report.triaged_at = Some(now);
            }
            ReportStatus::Resolved if report.resolved_at.is_none() => {
                report.resolved_at = Some(now);
                report.coordinated_disclosure_date = Some(disclosure_date_after_resolution(now));
            }
            _ => {}
        }

        report.status = new_status.clone();
        report.updated_at = now;
        let updated = report.clone();
        drop(reports);

        match &new_status {
            ReportStatus::Resolved => {
                let disclosure_date = updated
                    .coordinated_disclosure_date
                    .unwrap_or_else(|| disclosure_date_after_resolution(now));
                dispatcher
                    .send_coordinated_disclosure(&updated, disclosure_date)
                    .await?;
            }
            _ => {
                dispatcher.send_status_update(&updated).await?;
            }
        }

        Ok(updated)
    }

    /// Record a reward for a report in the mock store.
    pub async fn record_reward(
        store: &Arc<MockStore>,
        dispatcher: &NotificationDispatcher<MockStore>,
        report_id: Uuid,
        req: RecordRewardRequest,
        admin_id: Uuid,
        config: &BugBountyConfig,
    ) -> Result<RewardRecord, Bitmesh_backend::bug_bounty::models::BugBountyError> {
        let report = {
            let reports = store.reports.lock().await;
            reports
                .iter()
                .find(|r| r.id == report_id)
                .cloned()
                .ok_or(Bitmesh_backend::bug_bounty::models::BugBountyError::ReportNotFound)?
        };

        rewards::validate_tier(
            req.amount_usd,
            &report.severity,
            config,
            req.escalation_justification.as_deref(),
        )?;

        let now = Utc::now();
        let reward = RewardRecord {
            id: Uuid::new_v4(),
            report_id,
            researcher_id: report.researcher_id.clone(),
            amount_usd: req.amount_usd,
            justification: req.justification.clone(),
            escalation_justification: req.escalation_justification.clone(),
            payment_initiated_at: now,
            created_by: admin_id,
            created_at: now,
        };

        store.rewards.lock().await.push(reward.clone());
        dispatcher.send_reward_decision(&report, &reward).await?;

        Ok(reward)
    }

    /// Create an invitation in the mock store.
    pub async fn create_invitation(
        store: &Arc<MockStore>,
        researcher_id: &str,
        admin_id: Uuid,
    ) -> ResearcherInvitation {
        let now = Utc::now();
        let invitation = ResearcherInvitation {
            id: Uuid::new_v4(),
            researcher_id: researcher_id.to_string(),
            status: "active".to_string(),
            created_by: admin_id,
            created_at: now,
            revoked_at: None,
            revoked_by: None,
        };
        store.invitations.lock().await.push(invitation.clone());
        invitation
    }

    /// Attempt a private-to-public transition using the transition evaluator.
    pub async fn attempt_transition(
        store: &Arc<MockStore>,
        config: &BugBountyConfig,
        admin_id: Uuid,
    ) -> Result<TransitionResult, Bitmesh_backend::bug_bounty::models::BugBountyError> {
        let state = store.programme_state.lock().await.clone();
        let reports = store.reports.lock().await.clone();

        let researchers_participated: u32 = {
            let ids: std::collections::HashSet<&str> =
                reports.iter().map(|r| r.researcher_id.as_str()).collect();
            ids.len() as u32
        };

        let valid_statuses = [
            ReportStatus::Acknowledged,
            ReportStatus::Triaged,
            ReportStatus::InRemediation,
            ReportStatus::Resolved,
        ];
        let valid_findings_processed = reports
            .iter()
            .filter(|r| valid_statuses.contains(&r.status))
            .count() as u32;

        let resolved_count = reports
            .iter()
            .filter(|r| r.status == ReportStatus::Resolved)
            .count();
        let remediation_rate_percent = if valid_findings_processed == 0 {
            0.0
        } else {
            (resolved_count as f64 / valid_findings_processed as f64) * 100.0
        };

        let stats = ProgrammeStats {
            researchers_participated,
            valid_findings_processed,
            remediation_rate_percent,
        };

        let result = transition::evaluate_criteria(&state, &stats, config);

        if result.success {
            let now = Utc::now();
            let mut ps = store.programme_state.lock().await;
            ps.phase = ProgrammePhase::Public;
            ps.transitioned_to_public_at = Some(now);
            ps.transitioned_by = Some(admin_id);
            Ok(result)
        } else {
            Err(
                Bitmesh_backend::bug_bounty::models::BugBountyError::TransitionCriteriaNotMet {
                    unmet: result.unmet_criteria,
                },
            )
        }
    }

    // -----------------------------------------------------------------------
    // Shared request builders
    // -----------------------------------------------------------------------

    pub fn make_config_easy_transition() -> BugBountyConfig {
        BugBountyConfig {
            min_invited_researchers_participated: 1,
            min_valid_findings_processed: 1,
            min_remediation_rate_percent: 0.0,
            stabilisation_period_days: 0,
            ..BugBountyConfig::default()
        }
    }

    pub fn make_report_request(
        researcher_id: &str,
        component: &str,
        vuln_type: &str,
        severity: Severity,
    ) -> CreateReportRequest {
        CreateReportRequest {
            researcher_id: researcher_id.to_string(),
            severity,
            affected_component: component.to_string(),
            vulnerability_type: vuln_type.to_string(),
            title: format!("{vuln_type} in {component}"),
            description: "Integration test report".to_string(),
            proof_of_concept: Some("PoC details".to_string()),
            submission_content: json!({"source": "integration_test"}),
        }
    }
}

// ---------------------------------------------------------------------------
// 14.1 Full report lifecycle integration test
// ---------------------------------------------------------------------------

#[cfg(test)]
mod test_14_1_full_lifecycle {
    use super::helpers::*;
    use rust_decimal::Decimal;
    use std::sync::Arc;
    use uuid::Uuid;

    /// Requirements: 13.1
    ///
    /// Exercises the full report lifecycle:
    ///   intake → acknowledgement → triage → reward → resolution
    ///
    /// Verifies that `status`, `communication_log`, and `reward` records are
    /// correctly persisted at each stage.
    #[tokio::test]
    async fn full_report_lifecycle() {
        let config = BugBountyConfig::default();
        let admin_id = Uuid::new_v4();

        // Programme is public so no invitation check is needed for this test.
        let store = MockStore::new(ProgrammePhase::Public);
        let dispatcher = NotificationDispatcher::new(Arc::clone(&store));

        // ── Stage 1: Intake ──────────────────────────────────────────────────
        let req = make_report_request("alice", "api/auth", "sqli", Severity::High);
        let report = create_report(&store, &dispatcher, req, &config)
            .await
            .expect("create_report should succeed");

        // Status is New immediately after intake
        assert_eq!(report.status, ReportStatus::New);
        assert!(report.acknowledged_at.is_none());

        // Communication log has exactly 1 entry (acknowledgement)
        let log = store.comm_log.lock().await.clone();
        assert_eq!(log.len(), 1, "expected 1 comm log entry after intake");
        assert_eq!(log[0].notification_type, "acknowledgement");
        assert_eq!(log[0].report_id, report.id);
        drop(log);

        // ── Stage 2: Acknowledged ────────────────────────────────────────────
        let acked =
            update_report_status(&store, &dispatcher, report.id, ReportStatus::Acknowledged)
                .await
                .expect("update to Acknowledged should succeed");

        assert_eq!(acked.status, ReportStatus::Acknowledged);
        assert!(
            acked.acknowledged_at.is_some(),
            "acknowledged_at must be set"
        );

        let log = store.comm_log.lock().await.clone();
        assert_eq!(
            log.len(),
            2,
            "expected 2 comm log entries after acknowledgement"
        );
        assert_eq!(log[1].notification_type, "status_update");
        drop(log);

        // ── Stage 3: Triaged ─────────────────────────────────────────────────
        let triaged = update_report_status(&store, &dispatcher, report.id, ReportStatus::Triaged)
            .await
            .expect("update to Triaged should succeed");

        assert_eq!(triaged.status, ReportStatus::Triaged);
        assert!(triaged.triaged_at.is_some(), "triaged_at must be set");

        let log = store.comm_log.lock().await.clone();
        assert_eq!(log.len(), 3, "expected 3 comm log entries after triage");
        assert_eq!(log[2].notification_type, "status_update");
        drop(log);

        // ── Stage 4: Reward ──────────────────────────────────────────────────
        let reward_req = RecordRewardRequest {
            amount_usd: Decimal::new(2000, 0), // $2,000 — within High tier ($1k–$5k)
            justification: "Valid high-severity finding".to_string(),
            escalation_justification: None,
        };
        let reward = record_reward(
            &store,
            &dispatcher,
            report.id,
            reward_req,
            admin_id,
            &config,
        )
        .await
        .expect("record_reward should succeed");

        assert_eq!(reward.report_id, report.id);
        assert_eq!(reward.amount_usd, Decimal::new(2000, 0));

        let rewards = store.rewards.lock().await.clone();
        assert_eq!(rewards.len(), 1, "expected 1 reward record");
        assert_eq!(rewards[0].id, reward.id);
        drop(rewards);

        let log = store.comm_log.lock().await.clone();
        assert_eq!(log.len(), 4, "expected 4 comm log entries after reward");
        assert_eq!(log[3].notification_type, "reward_decision");
        drop(log);

        // ── Stage 5: Resolved ────────────────────────────────────────────────
        let resolved = update_report_status(&store, &dispatcher, report.id, ReportStatus::Resolved)
            .await
            .expect("update to Resolved should succeed");

        assert_eq!(resolved.status, ReportStatus::Resolved);
        assert!(resolved.resolved_at.is_some(), "resolved_at must be set");
        assert!(
            resolved.coordinated_disclosure_date.is_some(),
            "coordinated_disclosure_date must be set on resolution"
        );
        // Disclosure date must be strictly after resolved_at
        assert!(
            resolved.coordinated_disclosure_date.unwrap() > resolved.resolved_at.unwrap(),
            "coordinated_disclosure_date must be after resolved_at"
        );

        let log = store.comm_log.lock().await.clone();
        assert_eq!(log.len(), 5, "expected 5 comm log entries after resolution");
        assert_eq!(log[4].notification_type, "coordinated_disclosure");
    }
}

// ---------------------------------------------------------------------------
// 14.2 Duplicate detection workflow integration test
// ---------------------------------------------------------------------------

#[cfg(test)]
mod test_14_2_duplicate_detection {
    use super::helpers::*;
    use std::sync::Arc;

    /// Requirements: 13.2
    ///
    /// Submits multiple reports with overlapping affected_component and
    /// vulnerability_type. Verifies that:
    ///   - The second report (same component + same vuln_type) is flagged as Duplicate
    ///     and records the original report's ID.
    ///   - The original report is unaffected (still New).
    ///   - A third report with the same component but a different vuln_type is NOT
    ///     flagged as a duplicate (status = New).
    #[tokio::test]
    async fn duplicate_detection_workflow() {
        let config = BugBountyConfig::default();
        let store = MockStore::new(ProgrammePhase::Public);
        let dispatcher = NotificationDispatcher::new(Arc::clone(&store));

        // ── Report A: original ───────────────────────────────────────────────
        let req_a = make_report_request("alice", "api/auth", "sqli", Severity::High);
        let report_a = create_report(&store, &dispatcher, req_a, &config)
            .await
            .expect("create report A");

        assert_eq!(report_a.status, ReportStatus::New);
        assert!(report_a.duplicate_of.is_none());

        // ── Report B: same component + same vuln_type → Duplicate ────────────
        let req_b = make_report_request("bob", "api/auth", "sqli", Severity::Critical);
        let report_b = create_report(&store, &dispatcher, req_b, &config)
            .await
            .expect("create report B");

        assert_eq!(
            report_b.status,
            ReportStatus::Duplicate,
            "report B must be flagged as Duplicate"
        );
        assert_eq!(
            report_b.duplicate_of,
            Some(report_a.id),
            "report B must reference report A as the original"
        );

        // Original report A is unaffected
        let reports = store.reports.lock().await.clone();
        let a_in_store = reports.iter().find(|r| r.id == report_a.id).unwrap();
        assert_eq!(
            a_in_store.status,
            ReportStatus::New,
            "original report A must remain New"
        );
        drop(reports);

        // ── Report C: same component, different vuln_type → New ──────────────
        let req_c = make_report_request("carol", "api/auth", "xss", Severity::Medium);
        let report_c = create_report(&store, &dispatcher, req_c, &config)
            .await
            .expect("create report C");

        assert_eq!(
            report_c.status,
            ReportStatus::New,
            "report C (different vuln_type) must NOT be flagged as Duplicate"
        );
        assert!(report_c.duplicate_of.is_none());

        // Communication log: A gets ack, B gets ack (duplicate flag in content),
        // C gets ack — 3 acknowledgement entries total.
        let log = store.comm_log.lock().await.clone();
        let ack_entries: Vec<_> = log
            .iter()
            .filter(|e| e.notification_type == "acknowledgement")
            .collect();
        assert_eq!(ack_entries.len(), 3, "expected 3 acknowledgement entries");
    }
}

// ---------------------------------------------------------------------------
// 14.3 Invitation management integration test
// ---------------------------------------------------------------------------

#[cfg(test)]
mod test_14_3_invitation_management {
    use super::helpers::*;
    use std::sync::Arc;
    use uuid::Uuid;

    /// Requirements: 13.3
    ///
    /// Verifies the private programme invitation management workflow:
    ///   - Creating an invitation for a researcher.
    ///   - Accepting a report from an invited researcher.
    ///   - Rejecting a report from an uninvited researcher with InvitationRequired.
    #[tokio::test]
    async fn invitation_management_workflow() {
        let config = BugBountyConfig::default();
        let admin_id = Uuid::new_v4();

        // Programme is in private phase
        let store = MockStore::new(ProgrammePhase::Private);
        let dispatcher = NotificationDispatcher::new(Arc::clone(&store));

        // ── Create invitation for "alice" ────────────────────────────────────
        let invitation = create_invitation(&store, "alice", admin_id).await;
        assert_eq!(invitation.researcher_id, "alice");
        assert_eq!(invitation.status, "active");

        let invitations = store.invitations.lock().await.clone();
        assert_eq!(invitations.len(), 1);
        drop(invitations);

        // ── Alice (invited) can submit a report ──────────────────────────────
        let req_alice = make_report_request("alice", "api/payments", "idor", Severity::High);
        let report_alice = create_report(&store, &dispatcher, req_alice, &config)
            .await
            .expect("alice (invited) should be able to submit a report");

        assert_eq!(report_alice.status, ReportStatus::New);
        assert_eq!(report_alice.researcher_id, "alice");

        // ── Bob (not invited) is rejected ────────────────────────────────────
        let req_bob = make_report_request("bob", "api/payments", "sqli", Severity::Critical);
        let result_bob = create_report(&store, &dispatcher, req_bob, &config).await;

        assert!(
            result_bob.is_err(),
            "bob (uninvited) must be rejected during private phase"
        );
        assert!(
            matches!(
                result_bob.unwrap_err(),
                Bitmesh_backend::bug_bounty::models::BugBountyError::InvitationRequired
            ),
            "error must be InvitationRequired"
        );

        // Only alice's report is in the store
        let reports = store.reports.lock().await.clone();
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].researcher_id, "alice");
    }
}

// ---------------------------------------------------------------------------
// 14.4 Transition workflow integration test
// ---------------------------------------------------------------------------

#[cfg(test)]
mod test_14_4_transition_workflow {
    use super::helpers::*;
    use std::sync::Arc;
    use uuid::Uuid;

    /// Requirements: 13.4
    ///
    /// Verifies the private-to-public transition workflow:
    ///   1. Attempt transition with no findings → fails with TransitionCriteriaNotMet,
    ///      unmet_criteria is non-empty.
    ///   2. Create enough reports and invitations to meet all criteria.
    ///   3. Attempt transition → succeeds.
    ///   4. After transition, an uninvited researcher can submit a report.
    #[tokio::test]
    async fn transition_workflow() {
        // Use a config with low thresholds so we can satisfy them easily.
        let config = BugBountyConfig {
            min_invited_researchers_participated: 2,
            min_valid_findings_processed: 2,
            min_remediation_rate_percent: 100.0,
            stabilisation_period_days: 0, // no wait required
            ..BugBountyConfig::default()
        };
        let admin_id = Uuid::new_v4();

        // Programme launched 1 day ago (stabilisation_period_days = 0 so this is fine)
        let store = MockStore::new_with_launch(
            ProgrammePhase::Private,
            chrono::Utc::now() - chrono::Duration::days(1),
        );
        let dispatcher = NotificationDispatcher::new(Arc::clone(&store));

        // ── Step 1: Attempt transition with no findings → must fail ──────────
        let result = attempt_transition(&store, &config, admin_id).await;
        assert!(
            result.is_err(),
            "transition must fail when criteria are unmet"
        );
        if let Err(
            Bitmesh_backend::bug_bounty::models::BugBountyError::TransitionCriteriaNotMet { unmet },
        ) = result
        {
            assert!(
                !unmet.is_empty(),
                "unmet_criteria must be non-empty when transition fails"
            );
        } else {
            panic!("expected TransitionCriteriaNotMet error");
        }

        // ── Step 2: Satisfy all criteria ─────────────────────────────────────
        // Invite two researchers
        create_invitation(&store, "alice", admin_id).await;
        create_invitation(&store, "bob", admin_id).await;

        // Alice submits a report
        let req_alice = make_report_request("alice", "api/auth", "sqli", Severity::High);
        let report_alice = create_report(&store, &dispatcher, req_alice, &config)
            .await
            .expect("alice report");

        // Bob submits a report
        let req_bob = make_report_request("bob", "api/payments", "idor", Severity::Medium);
        let report_bob = create_report(&store, &dispatcher, req_bob, &config)
            .await
            .expect("bob report");

        // Move both reports to Resolved (satisfies remediation_rate = 100%)
        update_report_status(&store, &dispatcher, report_alice.id, ReportStatus::Triaged)
            .await
            .unwrap();
        update_report_status(&store, &dispatcher, report_alice.id, ReportStatus::Resolved)
            .await
            .unwrap();
        update_report_status(&store, &dispatcher, report_bob.id, ReportStatus::Triaged)
            .await
            .unwrap();
        update_report_status(&store, &dispatcher, report_bob.id, ReportStatus::Resolved)
            .await
            .unwrap();

        // ── Step 3: Attempt transition → must succeed ────────────────────────
        let result = attempt_transition(&store, &config, admin_id).await;
        assert!(
            result.is_ok(),
            "transition must succeed when all criteria are met"
        );
        let transition_result = result.unwrap();
        assert!(transition_result.success);
        assert!(transition_result.unmet_criteria.is_empty());

        // Programme phase is now Public
        let phase = store.programme_state.lock().await.phase.clone();
        assert_eq!(phase, ProgrammePhase::Public);

        // ── Step 4: Uninvited researcher can submit after transition ──────────
        let req_carol = make_report_request("carol", "api/admin", "xss", Severity::Low);
        let report_carol = create_report(&store, &dispatcher, req_carol, &config)
            .await
            .expect("carol (uninvited) must be able to submit after public transition");

        assert_eq!(report_carol.researcher_id, "carol");
        assert_eq!(report_carol.status, ReportStatus::New);
    }
}

// ---------------------------------------------------------------------------
// 14.5 Monthly cost report integration test
// ---------------------------------------------------------------------------

#[cfg(test)]
mod test_14_5_monthly_cost_report {
    use super::helpers::*;
    use rust_decimal::Decimal;
    use std::sync::Arc;
    use uuid::Uuid;

    /// Requirements: 13.5
    ///
    /// Processes a known set of reports and rewards, then verifies that the
    /// aggregated totals match the expected values.
    ///
    /// Reports:
    ///   - Report 1: Critical  → reward $5,000
    ///   - Report 2: High      → reward $2,000
    ///   - Report 3: Medium    → reward $500
    ///
    /// Expected total: $7,500
    #[tokio::test]
    async fn monthly_cost_report() {
        let config = BugBountyConfig::default();
        let admin_id = Uuid::new_v4();

        let store = MockStore::new(ProgrammePhase::Public);
        let dispatcher = NotificationDispatcher::new(Arc::clone(&store));

        // ── Create 3 reports ─────────────────────────────────────────────────
        let req_critical = make_report_request("alice", "api/auth", "rce", Severity::Critical);
        let report_critical = create_report(&store, &dispatcher, req_critical, &config)
            .await
            .expect("critical report");

        let req_high = make_report_request("bob", "api/payments", "sqli", Severity::High);
        let report_high = create_report(&store, &dispatcher, req_high, &config)
            .await
            .expect("high report");

        let req_medium = make_report_request("carol", "api/users", "idor", Severity::Medium);
        let report_medium = create_report(&store, &dispatcher, req_medium, &config)
            .await
            .expect("medium report");

        // ── Record rewards ───────────────────────────────────────────────────
        let reward_critical = record_reward(
            &store,
            &dispatcher,
            report_critical.id,
            RecordRewardRequest {
                amount_usd: Decimal::new(5000, 0),
                justification: "Critical RCE".to_string(),
                escalation_justification: None,
            },
            admin_id,
            &config,
        )
        .await
        .expect("critical reward");

        let reward_high = record_reward(
            &store,
            &dispatcher,
            report_high.id,
            RecordRewardRequest {
                amount_usd: Decimal::new(2000, 0),
                justification: "High SQL injection".to_string(),
                escalation_justification: None,
            },
            admin_id,
            &config,
        )
        .await
        .expect("high reward");

        let reward_medium = record_reward(
            &store,
            &dispatcher,
            report_medium.id,
            RecordRewardRequest {
                amount_usd: Decimal::new(500, 0),
                justification: "Medium IDOR".to_string(),
                escalation_justification: None,
            },
            admin_id,
            &config,
        )
        .await
        .expect("medium reward");

        // ── Verify individual reward amounts ─────────────────────────────────
        assert_eq!(reward_critical.amount_usd, Decimal::new(5000, 0));
        assert_eq!(reward_high.amount_usd, Decimal::new(2000, 0));
        assert_eq!(reward_medium.amount_usd, Decimal::new(500, 0));

        // ── Verify total rewards paid = $7,500 ───────────────────────────────
        let rewards = store.rewards.lock().await.clone();
        assert_eq!(rewards.len(), 3, "expected 3 reward records");

        let total: Decimal = rewards.iter().map(|r| r.amount_usd).sum();
        assert_eq!(
            total,
            Decimal::new(7500, 0),
            "total rewards paid must equal $7,500"
        );

        // ── Verify per-researcher totals ─────────────────────────────────────
        let mut by_researcher: std::collections::HashMap<String, Decimal> =
            std::collections::HashMap::new();
        for r in &rewards {
            *by_researcher.entry(r.researcher_id.clone()).or_default() += r.amount_usd;
        }
        assert_eq!(
            by_researcher["alice"],
            Decimal::new(5000, 0),
            "alice total must be $5,000"
        );
        assert_eq!(
            by_researcher["bob"],
            Decimal::new(2000, 0),
            "bob total must be $2,000"
        );
        assert_eq!(
            by_researcher["carol"],
            Decimal::new(500, 0),
            "carol total must be $500"
        );

        // ── Verify sum_rewards_by_month equivalent ───────────────────────────
        // All rewards were created in the same calendar month (now), so the
        // monthly total must equal the grand total.
        let current_month = chrono::Utc::now().format("%Y-%m").to_string();
        let mut by_month: std::collections::HashMap<String, Decimal> =
            std::collections::HashMap::new();
        for r in &rewards {
            let month = r.created_at.format("%Y-%m").to_string();
            *by_month.entry(month).or_default() += r.amount_usd;
        }
        assert_eq!(
            by_month[&current_month],
            Decimal::new(7500, 0),
            "monthly total for current month must equal $7,500"
        );
    }
}

// ---------------------------------------------------------------------------
// Database-backed integration tests (require `integration` feature + DATABASE_URL)
// ---------------------------------------------------------------------------

/// These tests mirror the mock-based tests above but use a real PostgreSQL
/// database via `BugBountyService` and `BugBountyRepository`.
///
/// Run with:
///   DATABASE_URL=postgres://... cargo test --features integration bug_bounty_integration
#[cfg(all(test, feature = "integration"))]
mod db_integration {
    use prometheus::Registry;
    use rust_decimal::Decimal;
    use std::sync::Arc;
    use uuid::Uuid;
    use Bitmesh_backend::bug_bounty::{
        metrics::BugBountyMetrics, models::*, notifications::NotificationDispatcher,
        repository::BugBountyRepository, service::BugBountyService,
    };

    async fn make_service() -> BugBountyService {
        let url =
            std::env::var("DATABASE_URL").expect("DATABASE_URL required for integration tests");
        let pool = sqlx::PgPool::connect(&url).await.expect("db connect");
        let repo = Arc::new(BugBountyRepository::new(pool));
        let dispatcher = Arc::new(NotificationDispatcher::new(Arc::clone(&repo)));
        let config = BugBountyConfig::default();
        let registry = Registry::new();
        let metrics = Arc::new(BugBountyMetrics::new(&registry).expect("metrics"));
        BugBountyService::new(repo, dispatcher, config, metrics)
    }

    #[tokio::test]
    async fn db_full_lifecycle() {
        let svc = make_service().await;
        let admin_id = Uuid::new_v4();

        let report = svc
            .create_report(
                CreateReportRequest {
                    researcher_id: "db-alice".to_string(),
                    severity: Severity::High,
                    affected_component: "api/auth".to_string(),
                    vulnerability_type: "sqli".to_string(),
                    title: "DB lifecycle test".to_string(),
                    description: "Integration test".to_string(),
                    proof_of_concept: None,
                    submission_content: serde_json::json!({}),
                },
                admin_id,
            )
            .await
            .expect("create report");

        assert_eq!(report.status, ReportStatus::New);

        let acked = svc
            .update_report(
                report.id,
                UpdateReportRequest {
                    status: Some(ReportStatus::Acknowledged),
                    severity: None,
                    remediation_ref: None,
                    coordinated_disclosure_date: None,
                },
                admin_id,
            )
            .await
            .expect("acknowledge");

        assert_eq!(acked.status, ReportStatus::Acknowledged);
        assert!(acked.acknowledged_at.is_some());

        let reward = svc
            .record_reward(
                report.id,
                RecordRewardRequest {
                    amount_usd: Decimal::new(2000, 0),
                    justification: "Valid finding".to_string(),
                    escalation_justification: None,
                },
                admin_id,
            )
            .await
            .expect("record reward");

        assert_eq!(reward.amount_usd, Decimal::new(2000, 0));

        let resolved = svc
            .update_report(
                report.id,
                UpdateReportRequest {
                    status: Some(ReportStatus::Resolved),
                    severity: None,
                    remediation_ref: None,
                    coordinated_disclosure_date: None,
                },
                admin_id,
            )
            .await
            .expect("resolve");

        assert_eq!(resolved.status, ReportStatus::Resolved);
        assert!(resolved.resolved_at.is_some());
        assert!(resolved.coordinated_disclosure_date.is_some());
    }

    #[tokio::test]
    async fn db_duplicate_detection() {
        let svc = make_service().await;
        let admin_id = Uuid::new_v4();

        let report_a = svc
            .create_report(
                CreateReportRequest {
                    researcher_id: "db-alice".to_string(),
                    severity: Severity::High,
                    affected_component: "db-api/auth".to_string(),
                    vulnerability_type: "db-sqli".to_string(),
                    title: "Original".to_string(),
                    description: "Original report".to_string(),
                    proof_of_concept: None,
                    submission_content: serde_json::json!({}),
                },
                admin_id,
            )
            .await
            .expect("create report A");

        assert_eq!(report_a.status, ReportStatus::New);

        let report_b = svc
            .create_report(
                CreateReportRequest {
                    researcher_id: "db-bob".to_string(),
                    severity: Severity::Critical,
                    affected_component: "db-api/auth".to_string(),
                    vulnerability_type: "db-sqli".to_string(),
                    title: "Duplicate".to_string(),
                    description: "Duplicate report".to_string(),
                    proof_of_concept: None,
                    submission_content: serde_json::json!({}),
                },
                admin_id,
            )
            .await
            .expect("create report B");

        assert_eq!(report_b.status, ReportStatus::Duplicate);
        assert_eq!(report_b.duplicate_of, Some(report_a.id));
    }

    #[tokio::test]
    async fn db_monthly_cost_report() {
        let svc = make_service().await;
        let admin_id = Uuid::new_v4();

        let report = svc
            .create_report(
                CreateReportRequest {
                    researcher_id: "db-cost-alice".to_string(),
                    severity: Severity::Critical,
                    affected_component: "db-cost-api".to_string(),
                    vulnerability_type: "db-cost-rce".to_string(),
                    title: "Cost test".to_string(),
                    description: "Cost report".to_string(),
                    proof_of_concept: None,
                    submission_content: serde_json::json!({}),
                },
                admin_id,
            )
            .await
            .expect("create report");

        svc.record_reward(
            report.id,
            RecordRewardRequest {
                amount_usd: Decimal::new(5000, 0),
                justification: "Critical finding".to_string(),
                escalation_justification: None,
            },
            admin_id,
        )
        .await
        .expect("record reward");

        let metrics = svc.get_metrics().await.expect("get metrics");
        assert!(
            metrics.total_rewards_paid_usd >= Decimal::new(5000, 0),
            "total rewards must include the $5,000 reward"
        );
    }
}
