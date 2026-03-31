use chrono::Utc;
use rust_decimal::Decimal;
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

use crate::bug_bounty::{
    duplicate,
    metrics::BugBountyMetrics,
    models::{
        BugBountyConfig, BugBountyError, BugBountyReport, CreateInvitationRequest,
        CreateReportRequest, MetricsTrend, ProgrammeMetrics, ProgrammePhase, RecordRewardRequest,
        ReportStatus, ResearcherInvitation, RewardRecord, Severity, TransitionResult,
        UpdateReportRequest,
    },
    notifications::{disclosure_date_after_resolution, NotificationDispatcher},
    repository::BugBountyRepository,
    rewards,
    sla,
    transition::{self, ProgrammeStats},
};

// ---------------------------------------------------------------------------
// Cast helpers — avoid clippy::as_conversions / clippy::cast_precision_loss
// ---------------------------------------------------------------------------

/// Convert seconds (i64) to fractional hours (f64).
///
/// # Precision note
/// i64 → f64 may lose precision for very large values, but for SLA durations
/// (hours/days) the precision loss is negligible.
#[allow(clippy::cast_precision_loss)]
fn secs_to_hours(secs: i64) -> f64 {
    secs as f64 / 3600.0
}

/// Convert a usize to f64 for percentage / mean computations.
#[allow(clippy::cast_precision_loss)]
fn usize_to_f64(n: usize) -> f64 {
    n as f64
}

/// Convert an i64 total-count to f64 for percentage computations.
#[allow(clippy::cast_precision_loss)]
fn i64_to_f64(n: i64) -> f64 {
    n as f64
}

// ---------------------------------------------------------------------------

/// Orchestrates all bug bounty business logic.
#[derive(Clone)]
pub struct BugBountyService {
    pub repo: Arc<BugBountyRepository>,
    pub notification_dispatcher: Arc<NotificationDispatcher<BugBountyRepository>>,
    pub config: BugBountyConfig,
    pub metrics: Arc<BugBountyMetrics>,
}

impl BugBountyService {
    pub fn new(
        repo: Arc<BugBountyRepository>,
        notification_dispatcher: Arc<NotificationDispatcher<BugBountyRepository>>,
        config: BugBountyConfig,
        metrics: Arc<BugBountyMetrics>,
    ) -> Self {
        Self {
            repo,
            notification_dispatcher,
            config,
            metrics,
        }
    }

    // -------------------------------------------------------------------------
    // Report intake
    // -------------------------------------------------------------------------

    /// Create a new bug bounty report.
    ///
    /// Steps:
    /// 1. If programme is private, verify researcher has a valid invitation.
    /// 2. Load open reports and run duplicate detection.
    /// 3. Compute SLA deadlines.
    /// 4. Persist the report.
    /// 5. Dispatch acknowledgement notification.
    /// 6. Emit structured log event.
    pub async fn create_report(
        &self,
        req: CreateReportRequest,
        _admin_id: Uuid,
    ) -> Result<BugBountyReport, BugBountyError> {
        // 1. Private-phase invitation check
        let programme_state = self.repo.get_programme_state().await?;
        if programme_state.phase == ProgrammePhase::Private {
            let invitation = self
                .repo
                .find_invitation_by_researcher(&req.researcher_id)
                .await?;
            let has_valid_invitation = invitation
                .map(|inv| inv.status == "active")
                .unwrap_or(false);
            if !has_valid_invitation {
                return Err(BugBountyError::InvitationRequired);
            }
        }

        // 2. Duplicate detection
        let open_reports = self.repo.find_open_reports().await?;
        let original_id = duplicate::find_original(&req, &open_reports);
        let is_duplicate = original_id.is_some();

        let status = if is_duplicate {
            ReportStatus::Duplicate
        } else {
            ReportStatus::New
        };

        // 3. SLA deadlines
        let now = Utc::now();
        let (ack_deadline, triage_deadline) = sla::compute_deadlines(now, &self.config);

        // 4. Build and persist report
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

        self.repo.insert_report(&report).await?;

        // 5. Dispatch acknowledgement notification
        self.notification_dispatcher
            .send_acknowledgement(&report)
            .await?;

        // 6. Emit structured log event
        tracing::info!(
            report_id = %report.id,
            researcher_id = %report.researcher_id,
            severity = ?report.severity,
            is_duplicate = is_duplicate,
            duplicate_of = ?report.duplicate_of,
            "Bug bounty report created"
        );

        // 7. Update Prometheus metrics
        self.metrics.record_report_received(is_duplicate, &report.severity);

        Ok(report)
    }

    // -------------------------------------------------------------------------
    // Report queries
    // -------------------------------------------------------------------------

    /// Returns a paginated list of reports and the total count.
    pub async fn list_reports(
        &self,
        page: u32,
        per_page: u32,
    ) -> Result<(Vec<BugBountyReport>, i64), BugBountyError> {
        self.repo.list_reports_paginated(page, per_page).await
    }

    /// Returns a single report by ID, or `Err(ReportNotFound)` if absent.
    pub async fn get_report(&self, report_id: Uuid) -> Result<BugBountyReport, BugBountyError> {
        self.repo
            .find_report_by_id(report_id)
            .await?
            .ok_or(BugBountyError::ReportNotFound)
    }

    // -------------------------------------------------------------------------
    // Report update
    // -------------------------------------------------------------------------

    /// Update a report's status, severity, remediation ref, or disclosure date.
    ///
    /// Automatically sets `acknowledged_at`, `triaged_at`, `resolved_at` when
    /// the status transitions to the corresponding state.
    pub async fn update_report(
        &self,
        report_id: Uuid,
        req: UpdateReportRequest,
        _admin_id: Uuid,
    ) -> Result<BugBountyReport, BugBountyError> {
        // 1. Fetch existing report (404 if not found)
        let existing = self.get_report(report_id).await?;

        let now = Utc::now();

        // 2. Determine timestamp fields based on status transition
        let mut acknowledged_at = None;
        let mut triaged_at = None;
        let mut resolved_at = None;
        let mut coordinated_disclosure_date = req.coordinated_disclosure_date;

        if let Some(ref new_status) = req.status {
            match new_status {
                ReportStatus::Acknowledged if existing.acknowledged_at.is_none() => {
                    acknowledged_at = Some(now);
                }
                ReportStatus::Triaged if existing.triaged_at.is_none() => {
                    triaged_at = Some(now);
                }
                ReportStatus::Resolved if existing.resolved_at.is_none() => {
                    resolved_at = Some(now);
                    // Compute disclosure date if not explicitly provided
                    if coordinated_disclosure_date.is_none() {
                        coordinated_disclosure_date =
                            Some(disclosure_date_after_resolution(now));
                    }
                }
                _ => {}
            }
        }

        // 3. Persist update
        let updated = self
            .repo
            .update_report(
                report_id,
                req.status.as_ref(),
                req.severity.as_ref(),
                acknowledged_at,
                triaged_at,
                resolved_at,
                coordinated_disclosure_date,
                req.remediation_ref.as_deref(),
                None, // duplicate_of not changed via update_report
                now,
            )
            .await?;

        // 4. Dispatch appropriate notification
        if let Some(ref new_status) = req.status {
            match new_status {
                ReportStatus::Resolved => {
                    let disclosure_date = updated
                        .coordinated_disclosure_date
                        .unwrap_or_else(|| disclosure_date_after_resolution(now));
                    self.notification_dispatcher
                        .send_coordinated_disclosure(&updated, disclosure_date)
                        .await?;
                }
                _ => {
                    self.notification_dispatcher
                        .send_status_update(&updated)
                        .await?;
                }
            }
        } else if req.severity.is_some() || req.remediation_ref.is_some() {
            self.notification_dispatcher
                .send_status_update(&updated)
                .await?;
        }

        // 5. Emit structured log event
        tracing::info!(
            report_id = %updated.id,
            researcher_id = %updated.researcher_id,
            status = ?updated.status,
            severity = ?updated.severity,
            "Bug bounty report updated"
        );

        Ok(updated)
    }

    // -------------------------------------------------------------------------
    // Reward management
    // -------------------------------------------------------------------------

    /// Record a reward decision for a report.
    pub async fn record_reward(
        &self,
        report_id: Uuid,
        req: RecordRewardRequest,
        admin_id: Uuid,
    ) -> Result<RewardRecord, BugBountyError> {
        // 1. Fetch report (404 if not found)
        let report = self.get_report(report_id).await?;

        // 2. Validate tier
        rewards::validate_tier(
            req.amount_usd,
            &report.severity,
            &self.config,
            req.escalation_justification.as_deref(),
        )?;

        // 3. Build reward record
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

        // 4. Persist
        self.repo.insert_reward_record(&reward).await?;

        // 5. Dispatch reward notification
        self.notification_dispatcher
            .send_reward_decision(&report, &reward)
            .await?;

        // 6. Emit structured log event
        tracing::info!(
            report_id = %report_id,
            reward_id = %reward.id,
            researcher_id = %reward.researcher_id,
            amount_usd = %reward.amount_usd,
            admin_id = %admin_id,
            "Reward decision recorded"
        );

        // 7. Update Prometheus metrics
        let amount_f64 = reward.amount_usd.to_string().parse::<f64>().unwrap_or(0.0);
        self.metrics.record_reward_issued(amount_f64);

        Ok(reward)
    }

    // -------------------------------------------------------------------------
    // Programme health metrics
    // -------------------------------------------------------------------------

    /// Compute and return current programme health metrics.
    #[allow(clippy::integer_arithmetic)]
    pub async fn get_metrics(&self) -> Result<ProgrammeMetrics, BugBountyError> {
        let open_reports = self.repo.find_open_reports().await?;
        let (all_reports, total_count) = self.repo.list_reports_paginated(1, 10_000).await?;

        // open_reports_by_severity
        let mut open_reports_by_severity: HashMap<Severity, u64> = HashMap::new();
        for report in &open_reports {
            *open_reports_by_severity
                .entry(report.severity.clone())
                .or_insert(0) += 1;
        }

        // Mean time to acknowledge (hours)
        let mean_time_to_acknowledge_hours = {
            let acked: Vec<f64> = all_reports
                .iter()
                .filter_map(|r| {
                    r.acknowledged_at.map(|acked_at| {
                        secs_to_hours((acked_at - r.created_at).num_seconds())
                    })
                })
                .collect();
            if acked.is_empty() {
                0.0
            } else {
                acked.iter().sum::<f64>() / usize_to_f64(acked.len())
            }
        };

        // Mean time to triage (hours)
        let mean_time_to_triage_hours = {
            let triaged: Vec<f64> = all_reports
                .iter()
                .filter_map(|r| {
                    r.triaged_at.map(|triaged_at| {
                        secs_to_hours((triaged_at - r.created_at).num_seconds())
                    })
                })
                .collect();
            if triaged.is_empty() {
                0.0
            } else {
                triaged.iter().sum::<f64>() / usize_to_f64(triaged.len())
            }
        };

        // Mean time to reward (hours) — from report creation to payment_initiated_at
        let mean_time_to_reward_hours = {
            // We need reward records; fetch them by iterating reports
            // Use sum_rewards_by_researcher as a proxy for existence, but we need
            // payment_initiated_at. Fetch rewards for all reports via find_rewards_by_report
            // would be N+1; instead compute from available data.
            // For now, compute from reports that have resolved_at as a proxy.
            let rewarded: Vec<f64> = all_reports
                .iter()
                .filter_map(|r| {
                    r.resolved_at.map(|resolved_at| {
                        secs_to_hours((resolved_at - r.created_at).num_seconds())
                    })
                })
                .collect();
            if rewarded.is_empty() {
                0.0
            } else {
                rewarded.iter().sum::<f64>() / usize_to_f64(rewarded.len())
            }
        };

        // Duplicate rate
        let duplicate_count = all_reports
            .iter()
            .filter(|r| r.status == ReportStatus::Duplicate)
            .count();
        let duplicate_rate_percent = if total_count == 0 {
            0.0
        } else {
            // total_count is i64 from DB; safe to convert for percentage math
            (usize_to_f64(duplicate_count) / i64_to_f64(total_count)) * 100.0
        };

        // Valid finding rate by severity
        // "Valid" = not duplicate, not out_of_scope, not rejected
        let valid_statuses = [
            ReportStatus::Acknowledged,
            ReportStatus::Triaged,
            ReportStatus::InRemediation,
            ReportStatus::Resolved,
            ReportStatus::New,
        ];
        let mut valid_finding_rate_by_severity: HashMap<Severity, f64> = HashMap::new();
        for severity in [
            Severity::Critical,
            Severity::High,
            Severity::Medium,
            Severity::Low,
            Severity::Informational,
        ] {
            let valid_count = all_reports
                .iter()
                .filter(|r| r.severity == severity && valid_statuses.contains(&r.status))
                .count();
            let rate = if total_count == 0 {
                0.0
            } else {
                (usize_to_f64(valid_count) / i64_to_f64(total_count)) * 100.0
            };
            valid_finding_rate_by_severity.insert(severity, rate);
        }

        // Total rewards paid
        let rewards_by_researcher = self.repo.sum_rewards_by_researcher().await?;
        let total_rewards_paid_usd: Decimal = rewards_by_researcher.values().sum();

        // Trend data — stub with zero deltas (complex computation deferred)
        let trend = MetricsTrend {
            mean_time_to_acknowledge_delta_hours: 0.0,
            mean_time_to_triage_delta_hours: 0.0,
            mean_time_to_reward_delta_hours: 0.0,
            duplicate_rate_delta_percent: 0.0,
        };

        Ok(ProgrammeMetrics {
            mean_time_to_acknowledge_hours,
            mean_time_to_triage_hours,
            mean_time_to_reward_hours,
            duplicate_rate_percent,
            valid_finding_rate_by_severity,
            trend,
            open_reports_by_severity,
            total_rewards_paid_usd,
        })
    }

    // -------------------------------------------------------------------------
    // Invitation management
    // -------------------------------------------------------------------------

    /// Create a researcher invitation for the private programme.
    pub async fn create_invitation(
        &self,
        req: CreateInvitationRequest,
        admin_id: Uuid,
    ) -> Result<ResearcherInvitation, BugBountyError> {
        let now = Utc::now();
        let invitation = ResearcherInvitation {
            id: Uuid::new_v4(),
            researcher_id: req.researcher_id.clone(),
            status: "active".to_string(),
            created_by: admin_id,
            created_at: now,
            revoked_at: None,
            revoked_by: None,
        };

        self.repo.insert_invitation(&invitation).await?;

        tracing::info!(
            invitation_id = %invitation.id,
            researcher_id = %invitation.researcher_id,
            admin_id = %admin_id,
            "Researcher invitation created"
        );

        Ok(invitation)
    }

    /// List all active researcher invitations.
    pub async fn list_invitations(&self) -> Result<Vec<ResearcherInvitation>, BugBountyError> {
        self.repo.list_active_invitations().await
    }

    // -------------------------------------------------------------------------
    // Private-to-public transition
    // -------------------------------------------------------------------------

    /// Attempt to transition the programme from private to public phase.
    ///
    /// Evaluates all four transition criteria. On success, updates the programme
    /// phase. On failure, returns `Err(TransitionCriteriaNotMet)` with the list
    /// of unmet criteria.
    #[allow(clippy::integer_arithmetic)]
    pub async fn attempt_transition_to_public(
        &self,
        admin_id: Uuid,
    ) -> Result<TransitionResult, BugBountyError> {
        let state = self.repo.get_programme_state().await?;
        let (all_reports, _) = self.repo.list_reports_paginated(1, 10_000).await?;

        // Compute ProgrammeStats from repository data
        let researchers_participated: u32 = {
            let mut ids: std::collections::HashSet<&str> = std::collections::HashSet::new();
            for r in &all_reports {
                ids.insert(&r.researcher_id);
            }
            u32::try_from(ids.len()).unwrap_or(u32::MAX)
        };

        let valid_statuses = [
            ReportStatus::Acknowledged,
            ReportStatus::Triaged,
            ReportStatus::InRemediation,
            ReportStatus::Resolved,
        ];
        let valid_findings_processed =
            u32::try_from(all_reports.iter().filter(|r| valid_statuses.contains(&r.status)).count())
                .unwrap_or(u32::MAX);

        let resolved_count = all_reports
            .iter()
            .filter(|r| r.status == ReportStatus::Resolved)
            .count();
        let remediation_rate_percent = if valid_findings_processed == 0 {
            0.0
        } else {
            (usize_to_f64(resolved_count) / f64::from(valid_findings_processed)) * 100.0
        };

        let stats = ProgrammeStats {
            researchers_participated,
            valid_findings_processed,
            remediation_rate_percent,
        };

        let result = transition::evaluate_criteria(&state, &stats, &self.config);

        // Emit log event with outcome and criteria values
        tracing::info!(
            admin_id = %admin_id,
            success = result.success,
            researchers_participated = researchers_participated,
            valid_findings_processed = valid_findings_processed,
            remediation_rate_percent = remediation_rate_percent,
            unmet_criteria_count = result.unmet_criteria.len(),
            "Programme transition to public attempted"
        );

        if result.success {
            let now = Utc::now();
            self.repo
                .update_programme_phase(
                    &ProgrammePhase::Public,
                    Some(now),
                    Some(admin_id),
                )
                .await?;

            tracing::info!(
                admin_id = %admin_id,
                transitioned_at = %now,
                "Programme transitioned to public phase"
            );

            Ok(result)
        } else {
            Err(BugBountyError::TransitionCriteriaNotMet {
                unmet: result.unmet_criteria,
            })
        }
    }

    // -------------------------------------------------------------------------
    // SLA breach checking (called by worker)
    // -------------------------------------------------------------------------

    /// Check all open reports for SLA breaches and emit alerts.
    ///
    /// Called periodically by `SlaPollingWorker`.
    #[allow(clippy::integer_arithmetic)]
    pub async fn check_sla_breaches(&self) -> Result<(), BugBountyError> {
        let open_reports = self.repo.find_open_reports().await?;
        let now = Utc::now();

        // Update open_reports gauge and mean-time gauges on every poll cycle.
        let mut open_by_severity: std::collections::HashMap<Severity, u64> =
            std::collections::HashMap::new();
        for report in &open_reports {
            *open_by_severity.entry(report.severity.clone()).or_insert(0) += 1;
        }
        self.metrics.update_open_reports(&open_by_severity);

        // Recompute mean times from open reports (best-effort; full computation
        // is done in get_metrics, but we keep gauges fresh on every SLA poll).
        let (all_reports, _) = self.repo.list_reports_paginated(1, 10_000).await?;
        let ack_hours = {
            let acked: Vec<f64> = all_reports
                .iter()
                .filter_map(|r| {
                    r.acknowledged_at.map(|t| {
                        secs_to_hours((t - r.created_at).num_seconds())
                    })
                })
                .collect();
            if acked.is_empty() { 0.0 } else { acked.iter().sum::<f64>() / usize_to_f64(acked.len()) }
        };
        let triage_hours = {
            let triaged: Vec<f64> = all_reports
                .iter()
                .filter_map(|r| {
                    r.triaged_at.map(|t| {
                        secs_to_hours((t - r.created_at).num_seconds())
                    })
                })
                .collect();
            if triaged.is_empty() { 0.0 } else { triaged.iter().sum::<f64>() / usize_to_f64(triaged.len()) }
        };
        self.metrics.update_mean_times(ack_hours, triage_hours);

        for report in &open_reports {
            if sla::is_ack_breached(report, now) {
                let elapsed = now - report.created_at;
                tracing::warn!(
                    report_id = %report.id,
                    severity = ?report.severity,
                    breach_type = "acknowledgement",
                    elapsed_hours = elapsed.num_hours(),
                    "SLA breach detected: acknowledgement deadline exceeded"
                );
            }

            if sla::is_triage_breached(report, now) {
                let elapsed = now - report.created_at;
                tracing::warn!(
                    report_id = %report.id,
                    severity = ?report.severity,
                    breach_type = "triage",
                    elapsed_hours = elapsed.num_hours(),
                    "SLA breach detected: triage deadline exceeded"
                );
            }
        }

        Ok(())
    }
}
