//! Background worker for the security compliance framework.
//!
//! Responsibilities:
//!   1. Hourly SLA breach detection and alerting
//!   2. Daily compliance posture score computation and persistence
//!   3. Monthly compliance report generation
//!   4. Prometheus metric synchronisation

use chrono::{Datelike, Utc};
use std::sync::Arc;
use tokio::sync::watch;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::security_compliance::{
    config::SecurityComplianceConfig,
    metrics,
    models::{CompliancePosture, ComplianceReport, VulnSeverity, Vulnerability},
    repository::SecurityComplianceRepository,
    scoring::PostureScorer,
};

pub struct SecurityComplianceWorker {
    repo: Arc<SecurityComplianceRepository>,
    config: Arc<SecurityComplianceConfig>,
}

impl SecurityComplianceWorker {
    pub fn new(
        repo: SecurityComplianceRepository,
        config: SecurityComplianceConfig,
    ) -> Self {
        Self {
            repo: Arc::new(repo),
            config: Arc::new(config),
        }
    }

    pub async fn run(self, mut shutdown_rx: watch::Receiver<bool>) {
        info!(
            sla_check_interval_secs = self.config.sla_check_interval.as_secs(),
            posture_compute_interval_secs = self.config.posture_compute_interval.as_secs(),
            "security compliance worker started"
        );

        let mut sla_ticker =
            tokio::time::interval(self.config.sla_check_interval);
        let mut posture_ticker =
            tokio::time::interval(self.config.posture_compute_interval);

        sla_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        posture_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        // Run an initial posture computation on startup.
        self.compute_and_persist_posture().await;

        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        info!("security compliance worker stopping");
                        break;
                    }
                }

                _ = sla_ticker.tick() => {
                    self.check_sla_breaches().await;
                    self.sync_metrics().await;
                }

                _ = posture_ticker.tick() => {
                    self.compute_and_persist_posture().await;
                    self.maybe_generate_monthly_report().await;
                }
            }
        }

        info!("security compliance worker stopped");
    }

    // ── SLA breach detection ──────────────────────────────────────────────────

    async fn check_sla_breaches(&self) {
        let warning_hours = self.config.sla_warning_hours_before;

        match self.repo.list_approaching_sla_deadline(warning_hours).await {
            Ok(rows) => {
                for row in &rows {
                    let hours_left = (row.sla_deadline - Utc::now()).num_hours();
                    warn!(
                        vuln_id = %row.id,
                        title = %row.title,
                        severity = %row.severity.as_str(),
                        hours_until_breach = hours_left,
                        "⚠️  vulnerability approaching SLA deadline"
                    );
                }
            }
            Err(e) => error!(error = %e, "failed to check SLA deadlines"),
        }

        // Log already-breached vulnerabilities as errors (triggers alerting).
        match self.repo.list_open_vulnerabilities().await {
            Ok(rows) => {
                for row in &rows {
                    let vuln: Vulnerability = row.clone().into();
                    if vuln.is_sla_breached() {
                        error!(
                            vuln_id = %vuln.id,
                            title = %vuln.title,
                            severity = %vuln.severity,
                            sla_deadline = %vuln.sla_deadline,
                            "🚨 SLA BREACH: vulnerability past remediation deadline"
                        );
                    }
                }
            }
            Err(e) => error!(error = %e, "failed to list open vulnerabilities for SLA check"),
        }
    }

    // ── Posture score computation ─────────────────────────────────────────────

    async fn compute_and_persist_posture(&self) {
        let open_rows = match self.repo.list_open_vulnerabilities().await {
            Ok(rows) => rows,
            Err(e) => {
                error!(error = %e, "failed to fetch open vulnerabilities for posture computation");
                return;
            }
        };

        let open_vulns: Vec<Vulnerability> = open_rows.into_iter().map(Into::into).collect();
        let scorer = PostureScorer::new(&self.config);
        let score = scorer.compute_score(&open_vulns);
        let counts = PostureScorer::count_by_severity(&open_vulns);
        let sla_breached = PostureScorer::count_sla_breached(&open_vulns) as i32;
        let breakdown = scorer.domain_breakdown(&open_vulns);

        let snapshot = CompliancePosture {
            id: Uuid::new_v4(),
            snapshot_date: Utc::now().date_naive(),
            posture_score: score,
            open_critical: counts.critical,
            open_high: counts.high,
            open_medium: counts.medium,
            open_low: counts.low,
            open_informational: counts.informational,
            sla_breached_count: sla_breached,
            domain_breakdown: breakdown,
            computed_at: Utc::now(),
        };

        if let Err(e) = self.repo.upsert_posture_snapshot(&snapshot).await {
            error!(error = %e, "failed to persist posture snapshot");
        }

        // Update Prometheus metrics.
        metrics::posture_score().set(score);
        metrics::open_vulns_by_severity()
            .with_label_values(&["critical"])
            .set(counts.critical as f64);
        metrics::open_vulns_by_severity()
            .with_label_values(&["high"])
            .set(counts.high as f64);
        metrics::open_vulns_by_severity()
            .with_label_values(&["medium"])
            .set(counts.medium as f64);
        metrics::open_vulns_by_severity()
            .with_label_values(&["low"])
            .set(counts.low as f64);
        metrics::open_vulns_by_severity()
            .with_label_values(&["informational"])
            .set(counts.informational as f64);

        // Alert if posture score drops below minimum threshold.
        if score < self.config.min_posture_score {
            error!(
                posture_score = score,
                min_threshold = self.config.min_posture_score,
                "🚨 COMPLIANCE ALERT: posture score below minimum threshold"
            );
        }

        info!(
            posture_score = score,
            open_critical = counts.critical,
            open_high = counts.high,
            sla_breached = sla_breached,
            "compliance posture computed"
        );
    }

    // ── Prometheus metric sync ────────────────────────────────────────────────

    async fn sync_metrics(&self) {
        let open_rows = match self.repo.list_open_vulnerabilities().await {
            Ok(rows) => rows,
            Err(_) => return,
        };

        for row in &open_rows {
            let vuln: Vulnerability = row.clone().into();
            let days = vuln.hours_until_sla_breach() as f64 / 24.0;
            metrics::days_until_sla_breach()
                .with_label_values(&[&vuln.id.to_string(), vuln.severity.as_str()])
                .set(days);
        }
    }

    // ── Monthly report generation ─────────────────────────────────────────────

    async fn maybe_generate_monthly_report(&self) {
        let now = Utc::now();
        // Generate on the 1st of each month.
        if now.day() != 1 {
            return;
        }

        let period_end = now.date_naive();
        let period_start = {
            let prev_month = if now.month() == 1 {
                chrono::NaiveDate::from_ymd_opt(now.year() - 1, 12, 1)
            } else {
                chrono::NaiveDate::from_ymd_opt(now.year(), now.month() - 1, 1)
            };
            prev_month.unwrap_or(period_end)
        };

        let start_dt = period_start
            .and_hms_opt(0, 0, 0)
            .map(|dt| dt.and_utc())
            .unwrap_or(now);
        let end_dt = now;

        let (new_count, remediated_count, sla_breaches) = tokio::join!(
            self.repo.count_new_in_period(start_dt, end_dt),
            self.repo.count_resolved_in_period(start_dt, end_dt),
            self.repo.count_sla_breaches_in_period(start_dt, end_dt),
        );

        let new_count = new_count.unwrap_or(0);
        let remediated_count = remediated_count.unwrap_or(0);
        let sla_breaches = sla_breaches.unwrap_or(0);

        // Fetch posture scores for start and end of period.
        let score_start = self
            .repo
            .posture_snapshot_for_date(period_start)
            .await
            .ok()
            .flatten()
            .map(|r| {
                use std::str::FromStr;
                f64::from_str(&r.posture_score.to_string()).unwrap_or(0.0)
            });

        let score_end = self
            .repo
            .latest_posture_snapshot()
            .await
            .ok()
            .flatten()
            .map(|r| {
                use std::str::FromStr;
                f64::from_str(&r.posture_score.to_string()).unwrap_or(0.0)
            });

        let report_data = serde_json::json!({
            "period": {
                "start": period_start,
                "end": period_end,
            },
            "summary": {
                "new_vulnerabilities": new_count,
                "remediated": remediated_count,
                "sla_breaches": sla_breaches,
                "posture_score_start": score_start,
                "posture_score_end": score_end,
            },
            "generated_at": now,
            "format_version": "1.0",
        });

        let report = ComplianceReport {
            id: Uuid::new_v4(),
            report_period_start: period_start,
            report_period_end: period_end,
            new_vulns_count: new_count as i32,
            remediated_count: remediated_count as i32,
            sla_breaches_count: sla_breaches as i32,
            posture_score_start: score_start,
            posture_score_end: score_end,
            report_data,
            generated_at: now,
            generated_by: "system".to_string(),
        };

        match self.repo.insert_compliance_report(&report).await {
            Ok(()) => info!(
                report_id = %report.id,
                period_start = %period_start,
                "monthly compliance report generated"
            ),
            Err(e) => error!(error = %e, "failed to persist monthly compliance report"),
        }
    }
}
