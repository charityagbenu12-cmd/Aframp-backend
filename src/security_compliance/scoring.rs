//! Compliance posture score computation.
//!
//! Score formula:
//!   score = max(0, 100 - Σ(weight_i × age_multiplier_i))
//!
//! Where:
//!   weight_i         = severity base weight (critical=40, high=15, medium=5, low=1)
//!   age_multiplier_i = 1.0 + (age_fraction × 2.0)
//!                      age_fraction = elapsed_hours / sla_hours  (capped at 1.0)
//!
//! This means a critical vuln at its SLA deadline has 3× the weight of a
//! freshly discovered one, incentivising rapid remediation.

use chrono::Utc;
use serde::Serialize;
use std::collections::HashMap;

use crate::security_compliance::{
    config::SecurityComplianceConfig,
    models::{VulnSeverity, VulnStatus, Vulnerability},
};

pub struct PostureScorer<'a> {
    config: &'a SecurityComplianceConfig,
}

impl<'a> PostureScorer<'a> {
    pub fn new(config: &'a SecurityComplianceConfig) -> Self {
        Self { config }
    }

    /// Compute the platform-wide posture score from a slice of open vulnerabilities.
    /// Returns a value in [0.0, 100.0].
    pub fn compute_score(&self, open_vulns: &[Vulnerability]) -> f64 {
        let penalty: f64 = open_vulns
            .iter()
            .filter(|v| matches!(v.status, VulnStatus::Open | VulnStatus::Acknowledged))
            .map(|v| self.vuln_penalty(v))
            .sum();

        (100.0_f64 - penalty).max(0.0)
    }

    /// Penalty contribution of a single vulnerability.
    pub fn vuln_penalty(&self, vuln: &Vulnerability) -> f64 {
        let base = vuln.severity.base_weight();
        let age_multiplier = self.age_multiplier(vuln);
        base * age_multiplier
    }

    /// Age multiplier: 1.0 at discovery, up to 3.0 at SLA deadline.
    pub fn age_multiplier(&self, vuln: &Vulnerability) -> f64 {
        let sla_hours = self.config.sla_hours_for(vuln.severity.as_str()) as f64;
        if sla_hours <= 0.0 {
            return 3.0;
        }
        let elapsed_hours = (Utc::now() - vuln.discovered_at).num_hours() as f64;
        let age_fraction = (elapsed_hours / sla_hours).min(1.0).max(0.0);
        1.0 + age_fraction * 2.0
    }

    /// Per-source domain breakdown: maps source → { score_impact, open_count }.
    pub fn domain_breakdown(&self, open_vulns: &[Vulnerability]) -> serde_json::Value {
        let mut by_source: HashMap<&str, (f64, usize)> = HashMap::new();

        for v in open_vulns
            .iter()
            .filter(|v| matches!(v.status, VulnStatus::Open | VulnStatus::Acknowledged))
        {
            let entry = by_source.entry(v.source.as_str()).or_insert((0.0, 0));
            entry.0 += self.vuln_penalty(v);
            entry.1 += 1;
        }

        let map: serde_json::Map<String, serde_json::Value> = by_source
            .into_iter()
            .map(|(source, (impact, count))| {
                (
                    source.to_string(),
                    serde_json::json!({
                        "score_impact": (impact * 100.0).round() / 100.0,
                        "open_count": count
                    }),
                )
            })
            .collect();

        serde_json::Value::Object(map)
    }

    /// Count open vulnerabilities by severity.
    pub fn count_by_severity(open_vulns: &[Vulnerability]) -> SeverityCounts {
        let mut counts = SeverityCounts::default();
        for v in open_vulns
            .iter()
            .filter(|v| matches!(v.status, VulnStatus::Open | VulnStatus::Acknowledged))
        {
            match v.severity {
                VulnSeverity::Critical => counts.critical += 1,
                VulnSeverity::High => counts.high += 1,
                VulnSeverity::Medium => counts.medium += 1,
                VulnSeverity::Low => counts.low += 1,
                VulnSeverity::Informational => counts.informational += 1,
            }
        }
        counts
    }

    /// Count vulnerabilities that have breached their SLA.
    pub fn count_sla_breached(open_vulns: &[Vulnerability]) -> usize {
        open_vulns.iter().filter(|v| v.is_sla_breached()).count()
    }
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct SeverityCounts {
    pub critical: i32,
    pub high: i32,
    pub medium: i32,
    pub low: i32,
    pub informational: i32,
}
