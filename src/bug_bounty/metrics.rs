//! Prometheus metrics for the Bug Bounty Programme subsystem.
//!
//! Exposes gauges and counters as required by Requirements 8.4, 8.5, and 11.2.
//! All metrics are registered with the global registry via `register()`.

use prometheus::{
    register_counter_vec_with_registry, register_counter_with_registry,
    register_gauge_vec_with_registry, register_gauge_with_registry, Counter, CounterVec, Gauge,
    GaugeVec, Registry,
};
use std::collections::HashMap;

use crate::bug_bounty::models::Severity;

// ---------------------------------------------------------------------------
// Registration (called from src/metrics/mod.rs register_all)
// ---------------------------------------------------------------------------

/// Register all bug bounty metrics with the supplied registry.
///
/// This pre-registers the metric names so they appear in `/metrics` output
/// even before the first `BugBountyMetrics::new` call. Errors are silently
/// ignored (duplicate registration is benign).
pub fn register(r: &Registry) {
    let _ = register_gauge_vec_with_registry!(
        "bb_open_reports",
        "Open bug bounty report count per severity",
        &["severity"],
        r
    );
    let _ = register_gauge_with_registry!(
        "bb_mean_time_to_acknowledge_hours",
        "Mean time to acknowledge bug bounty reports in hours",
        r
    );
    let _ = register_gauge_with_registry!(
        "bb_mean_time_to_triage_hours",
        "Mean time to triage bug bounty reports in hours",
        r
    );
    let _ = register_gauge_with_registry!(
        "bb_total_rewards_paid_usd",
        "Total bug bounty rewards paid in USD",
        r
    );
    let _ = register_counter_with_registry!(
        "bb_reports_received_total",
        "Total bug bounty reports received",
        r
    );
    let _ = register_counter_vec_with_registry!(
        "bb_valid_findings_total",
        "Total valid bug bounty findings per severity",
        &["severity"],
        r
    );
    let _ = register_counter_with_registry!(
        "bb_duplicates_detected_total",
        "Total duplicate bug bounty reports detected",
        r
    );
    let _ = register_counter_with_registry!(
        "bb_rewards_issued_total",
        "Total bug bounty rewards issued",
        r
    );
}

// ---------------------------------------------------------------------------
// BugBountyMetrics struct
// ---------------------------------------------------------------------------

/// Holds all Prometheus metric handles for the bug bounty subsystem.
///
/// Construct via `BugBountyMetrics::new(registry)` and share as `Arc<BugBountyMetrics>`.
#[derive(Clone)]
pub struct BugBountyMetrics {
    pub open_reports: GaugeVec,
    pub mean_time_to_acknowledge_hours: Gauge,
    pub mean_time_to_triage_hours: Gauge,
    pub total_rewards_paid_usd: Gauge,
    pub reports_received_total: Counter,
    pub valid_findings_total: CounterVec,
    pub duplicates_detected_total: Counter,
    pub rewards_issued_total: Counter,
}

impl BugBountyMetrics {
    /// Create and register all bug bounty metrics with the given registry.
    pub fn new(registry: &Registry) -> Result<Self, prometheus::Error> {
        let open_reports = register_gauge_vec_with_registry!(
            "bb_open_reports",
            "Open bug bounty report count per severity",
            &["severity"],
            registry
        )?;

        let mean_time_to_acknowledge_hours = register_gauge_with_registry!(
            "bb_mean_time_to_acknowledge_hours",
            "Mean time to acknowledge bug bounty reports in hours",
            registry
        )?;

        let mean_time_to_triage_hours = register_gauge_with_registry!(
            "bb_mean_time_to_triage_hours",
            "Mean time to triage bug bounty reports in hours",
            registry
        )?;

        let total_rewards_paid_usd = register_gauge_with_registry!(
            "bb_total_rewards_paid_usd",
            "Total bug bounty rewards paid in USD",
            registry
        )?;

        let reports_received_total = register_counter_with_registry!(
            "bb_reports_received_total",
            "Total bug bounty reports received",
            registry
        )?;

        let valid_findings_total = register_counter_vec_with_registry!(
            "bb_valid_findings_total",
            "Total valid bug bounty findings per severity",
            &["severity"],
            registry
        )?;

        let duplicates_detected_total = register_counter_with_registry!(
            "bb_duplicates_detected_total",
            "Total duplicate bug bounty reports detected",
            registry
        )?;

        let rewards_issued_total = register_counter_with_registry!(
            "bb_rewards_issued_total",
            "Total bug bounty rewards issued",
            registry
        )?;

        Ok(Self {
            open_reports,
            mean_time_to_acknowledge_hours,
            mean_time_to_triage_hours,
            total_rewards_paid_usd,
            reports_received_total,
            valid_findings_total,
            duplicates_detected_total,
            rewards_issued_total,
        })
    }

    // -----------------------------------------------------------------------
    // Helper methods
    // -----------------------------------------------------------------------

    /// Record a new report being received.
    ///
    /// - Always increments `reports_received_total`.
    /// - If `is_duplicate`, increments `duplicates_detected_total`.
    /// - Otherwise increments `valid_findings_total` for the given severity.
    pub fn record_report_received(&self, is_duplicate: bool, severity: &Severity) {
        self.reports_received_total.inc();
        if is_duplicate {
            self.duplicates_detected_total.inc();
        } else {
            self.valid_findings_total
                .with_label_values(&[severity_label(severity)])
                .inc();
        }
    }

    /// Record a reward being issued.
    ///
    /// Increments `rewards_issued_total` and adds `amount_usd` to
    /// `total_rewards_paid_usd`.
    pub fn record_reward_issued(&self, amount_usd: f64) {
        self.rewards_issued_total.inc();
        self.total_rewards_paid_usd.add(amount_usd);
    }

    /// Set the `open_reports` gauge for each severity from the provided map.
    pub fn update_open_reports(&self, counts: &HashMap<Severity, u64>) {
        for (severity, count) in counts {
            self.open_reports
                .with_label_values(&[severity_label(severity)])
                // u64 → f64: precision loss only for counts > 2^53, safe for metrics
                .set(f64::from(u32::try_from(*count).unwrap_or(u32::MAX)));
        }
    }

    /// Set the mean-time gauges.
    pub fn update_mean_times(&self, ack_hours: f64, triage_hours: f64) {
        self.mean_time_to_acknowledge_hours.set(ack_hours);
        self.mean_time_to_triage_hours.set(triage_hours);
    }
}

// ---------------------------------------------------------------------------
// Module-level convenience functions (backed by the static OnceLock handles)
// ---------------------------------------------------------------------------

/// Returns the lowercase Prometheus label string for a `Severity` variant.
pub fn severity_label(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Informational => "informational",
    }
}
