//! Prometheus metrics for the security compliance framework.

use prometheus::{
    register_counter_vec_with_registry, register_gauge_vec_with_registry,
    register_gauge_with_registry, CounterVec, Gauge, GaugeVec, Registry,
};
use std::sync::OnceLock;

// ── Open vulnerability counts per severity ────────────────────────────────────

static OPEN_VULNS_BY_SEVERITY: OnceLock<GaugeVec> = OnceLock::new();

pub fn open_vulns_by_severity() -> &'static GaugeVec {
    OPEN_VULNS_BY_SEVERITY
        .get()
        .expect("security compliance metrics not initialised")
}

// ── Compliance posture score ──────────────────────────────────────────────────

static POSTURE_SCORE: OnceLock<Gauge> = OnceLock::new();

pub fn posture_score() -> &'static Gauge {
    POSTURE_SCORE
        .get()
        .expect("security compliance metrics not initialised")
}

// ── Days until next SLA breach per open vulnerability ────────────────────────

static DAYS_UNTIL_SLA_BREACH: OnceLock<GaugeVec> = OnceLock::new();

pub fn days_until_sla_breach() -> &'static GaugeVec {
    DAYS_UNTIL_SLA_BREACH
        .get()
        .expect("security compliance metrics not initialised")
}

// ── SLA breached count ────────────────────────────────────────────────────────

static SLA_BREACHED_TOTAL: OnceLock<GaugeVec> = OnceLock::new();

pub fn sla_breached_total() -> &'static GaugeVec {
    SLA_BREACHED_TOTAL
        .get()
        .expect("security compliance metrics not initialised")
}

// ── Vulnerability lifecycle event counters ────────────────────────────────────

static VULN_EVENTS_TOTAL: OnceLock<CounterVec> = OnceLock::new();

pub fn vuln_events_total() -> &'static CounterVec {
    VULN_EVENTS_TOTAL
        .get()
        .expect("security compliance metrics not initialised")
}

// ── Scan run results ──────────────────────────────────────────────────────────

static SCAN_RUNS_TOTAL: OnceLock<CounterVec> = OnceLock::new();

pub fn scan_runs_total() -> &'static CounterVec {
    SCAN_RUNS_TOTAL
        .get()
        .expect("security compliance metrics not initialised")
}

// ── Registration ──────────────────────────────────────────────────────────────

pub fn register(r: &Registry) {
    OPEN_VULNS_BY_SEVERITY
        .set(
            register_gauge_vec_with_registry!(
                "aframp_security_open_vulns_by_severity",
                "Number of open vulnerabilities per severity level",
                &["severity"],
                r
            )
            .unwrap(),
        )
        .ok();

    POSTURE_SCORE
        .set(
            register_gauge_with_registry!(
                "aframp_security_compliance_posture_score",
                "Platform compliance posture score (0-100, higher is better)",
                r
            )
            .unwrap(),
        )
        .ok();

    DAYS_UNTIL_SLA_BREACH
        .set(
            register_gauge_vec_with_registry!(
                "aframp_security_days_until_sla_breach",
                "Days remaining until SLA breach per open vulnerability (negative = already breached)",
                &["vuln_id", "severity"],
                r
            )
            .unwrap(),
        )
        .ok();

    SLA_BREACHED_TOTAL
        .set(
            register_gauge_vec_with_registry!(
                "aframp_security_sla_breached_count",
                "Number of open vulnerabilities that have breached their SLA deadline",
                &["severity"],
                r
            )
            .unwrap(),
        )
        .ok();

    VULN_EVENTS_TOTAL
        .set(
            register_counter_vec_with_registry!(
                "aframp_security_vuln_events_total",
                "Total vulnerability lifecycle events by event type and severity",
                &["event", "severity", "source"],
                r
            )
            .unwrap(),
        )
        .ok();

    SCAN_RUNS_TOTAL
        .set(
            register_counter_vec_with_registry!(
                "aframp_security_scan_runs_total",
                "Total security scan runs by scan type and result",
                &["scan_type", "result"],
                r
            )
            .unwrap(),
        )
        .ok();
}
