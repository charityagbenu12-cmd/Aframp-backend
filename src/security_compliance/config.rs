//! Configuration for the security compliance framework.
//!
//! All values are loaded from environment variables with sensible defaults.

use std::time::Duration;

#[derive(Debug, Clone)]
pub struct SecurityComplianceConfig {
    // ── SLA deadlines (hours) ────────────────────────────────────────────────
    pub sla_critical_hours: i64,
    pub sla_high_hours: i64,
    pub sla_medium_hours: i64,
    pub sla_low_hours: i64,
    pub sla_informational_hours: i64,

    // ── Posture scoring ──────────────────────────────────────────────────────
    /// Minimum acceptable posture score before alerting fires.
    pub min_posture_score: f64,
    /// Maximum possible penalty (score starts at 100, penalties deducted).
    pub max_score_penalty: f64,

    // ── SLA breach alerting ──────────────────────────────────────────────────
    /// How many hours before SLA deadline to fire a warning alert.
    pub sla_warning_hours_before: i64,

    // ── Worker intervals ─────────────────────────────────────────────────────
    /// How often the SLA breach checker runs.
    pub sla_check_interval: Duration,
    /// How often the daily posture score is computed.
    pub posture_compute_interval: Duration,

    // ── CI/CD integration ────────────────────────────────────────────────────
    /// Severities that cause a CI build to fail on new findings.
    pub ci_fail_severities: Vec<String>,

    // ── Reporting ────────────────────────────────────────────────────────────
    pub report_output_dir: String,
}

impl Default for SecurityComplianceConfig {
    fn default() -> Self {
        Self {
            sla_critical_hours: 24,
            sla_high_hours: 7 * 24,
            sla_medium_hours: 30 * 24,
            sla_low_hours: 90 * 24,
            sla_informational_hours: 365 * 24,

            min_posture_score: 70.0,
            max_score_penalty: 100.0,

            sla_warning_hours_before: 4,

            sla_check_interval: Duration::from_secs(3600),       // hourly
            posture_compute_interval: Duration::from_secs(86400), // daily

            ci_fail_severities: vec!["critical".to_string(), "high".to_string()],

            report_output_dir: "/tmp/compliance-reports".to_string(),
        }
    }
}

impl SecurityComplianceConfig {
    pub fn from_env() -> Self {
        let mut cfg = Self::default();

        macro_rules! env_i64 {
            ($var:expr, $field:expr) => {
                if let Ok(v) = std::env::var($var) {
                    if let Ok(n) = v.parse::<i64>() {
                        $field = n;
                    }
                }
            };
        }
        macro_rules! env_f64 {
            ($var:expr, $field:expr) => {
                if let Ok(v) = std::env::var($var) {
                    if let Ok(n) = v.parse::<f64>() {
                        $field = n;
                    }
                }
            };
        }
        macro_rules! env_secs {
            ($var:expr, $field:expr) => {
                if let Ok(v) = std::env::var($var) {
                    if let Ok(n) = v.parse::<u64>() {
                        $field = Duration::from_secs(n);
                    }
                }
            };
        }

        env_i64!("SEC_SLA_CRITICAL_HOURS", cfg.sla_critical_hours);
        env_i64!("SEC_SLA_HIGH_HOURS", cfg.sla_high_hours);
        env_i64!("SEC_SLA_MEDIUM_HOURS", cfg.sla_medium_hours);
        env_i64!("SEC_SLA_LOW_HOURS", cfg.sla_low_hours);
        env_i64!("SEC_SLA_INFORMATIONAL_HOURS", cfg.sla_informational_hours);
        env_f64!("SEC_MIN_POSTURE_SCORE", cfg.min_posture_score);
        env_i64!("SEC_SLA_WARNING_HOURS_BEFORE", cfg.sla_warning_hours_before);
        env_secs!("SEC_SLA_CHECK_INTERVAL_SECS", cfg.sla_check_interval);
        env_secs!("SEC_POSTURE_COMPUTE_INTERVAL_SECS", cfg.posture_compute_interval);

        if let Ok(v) = std::env::var("SEC_REPORT_OUTPUT_DIR") {
            cfg.report_output_dir = v;
        }

        cfg
    }

    /// Returns the SLA hours for a given severity string.
    pub fn sla_hours_for(&self, severity: &str) -> i64 {
        match severity {
            "critical" => self.sla_critical_hours,
            "high" => self.sla_high_hours,
            "medium" => self.sla_medium_hours,
            "low" => self.sla_low_hours,
            _ => self.sla_informational_hours,
        }
    }
}
