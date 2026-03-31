//! Unit tests for the security compliance framework.

#[cfg(test)]
mod tests {
    use chrono::{Duration, Utc};
    use uuid::Uuid;

    use crate::security_compliance::{
        config::SecurityComplianceConfig,
        models::{VulnSeverity, VulnSource, VulnStatus, Vulnerability},
        scoring::PostureScorer,
    };

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn make_vuln(severity: VulnSeverity, hours_old: i64) -> Vulnerability {
        let config = SecurityComplianceConfig::default();
        let discovered_at = Utc::now() - Duration::hours(hours_old);
        let sla_deadline =
            discovered_at + Duration::hours(config.sla_hours_for(severity.as_str()));
        Vulnerability {
            id: Uuid::new_v4(),
            title: format!("Test vuln {:?}", severity),
            description: "Test".to_string(),
            severity,
            status: VulnStatus::Open,
            source: VulnSource::CargoAudit,
            affected_component: "test-crate".to_string(),
            cve_reference: None,
            affected_versions: None,
            remediation_guidance: None,
            discovered_at,
            sla_deadline,
            acknowledged_at: None,
            acknowledged_by: None,
            remediation_plan: None,
            resolved_at: None,
            resolved_by: None,
            remediation_notes: None,
            resolving_commit: None,
            risk_accepted_at: None,
            risk_accepted_by: None,
            risk_justification: None,
            risk_expiry_date: None,
            raw_finding: None,
            created_at: discovered_at,
            updated_at: discovered_at,
        }
    }

    // ── Posture score tests ───────────────────────────────────────────────────

    #[test]
    fn test_perfect_score_with_no_open_vulns() {
        let config = SecurityComplianceConfig::default();
        let scorer = PostureScorer::new(&config);
        let score = scorer.compute_score(&[]);
        assert_eq!(score, 100.0);
    }

    #[test]
    fn test_score_decreases_with_open_vulns() {
        let config = SecurityComplianceConfig::default();
        let scorer = PostureScorer::new(&config);

        let vulns = vec![make_vuln(VulnSeverity::Critical, 1)];
        let score = scorer.compute_score(&vulns);
        assert!(score < 100.0, "score should decrease with open critical vuln");
        assert!(score >= 0.0, "score should not go below 0");
    }

    #[test]
    fn test_critical_has_higher_penalty_than_low() {
        let config = SecurityComplianceConfig::default();
        let scorer = PostureScorer::new(&config);

        let critical_vulns = vec![make_vuln(VulnSeverity::Critical, 1)];
        let low_vulns = vec![make_vuln(VulnSeverity::Low, 1)];

        let critical_score = scorer.compute_score(&critical_vulns);
        let low_score = scorer.compute_score(&low_vulns);

        assert!(
            critical_score < low_score,
            "critical vuln should produce lower score than low vuln"
        );
    }

    #[test]
    fn test_score_never_goes_below_zero() {
        let config = SecurityComplianceConfig::default();
        let scorer = PostureScorer::new(&config);

        // Many critical vulns should floor at 0, not go negative.
        let vulns: Vec<Vulnerability> = (0..20)
            .map(|_| make_vuln(VulnSeverity::Critical, 1))
            .collect();
        let score = scorer.compute_score(&vulns);
        assert_eq!(score, 0.0);
    }

    #[test]
    fn test_resolved_vulns_do_not_affect_score() {
        let config = SecurityComplianceConfig::default();
        let scorer = PostureScorer::new(&config);

        let mut vuln = make_vuln(VulnSeverity::Critical, 1);
        vuln.status = VulnStatus::Resolved;

        let score = scorer.compute_score(&[vuln]);
        assert_eq!(score, 100.0, "resolved vulns should not affect score");
    }

    #[test]
    fn test_risk_accepted_vulns_do_not_affect_score() {
        let config = SecurityComplianceConfig::default();
        let scorer = PostureScorer::new(&config);

        let mut vuln = make_vuln(VulnSeverity::High, 1);
        vuln.status = VulnStatus::RiskAccepted;

        let score = scorer.compute_score(&[vuln]);
        assert_eq!(score, 100.0, "risk-accepted vulns should not affect score");
    }

    // ── Age multiplier tests ──────────────────────────────────────────────────

    #[test]
    fn test_age_multiplier_at_discovery_is_one() {
        let config = SecurityComplianceConfig::default();
        let scorer = PostureScorer::new(&config);

        let vuln = make_vuln(VulnSeverity::High, 0); // just discovered
        let multiplier = scorer.age_multiplier(&vuln);
        // At t=0, age_fraction=0, multiplier=1.0
        assert!(
            (multiplier - 1.0).abs() < 0.1,
            "age multiplier at discovery should be ~1.0, got {}",
            multiplier
        );
    }

    #[test]
    fn test_age_multiplier_at_sla_deadline_is_three() {
        let config = SecurityComplianceConfig::default();
        let scorer = PostureScorer::new(&config);

        // Create a vuln that is exactly at its SLA deadline.
        let sla_hours = config.sla_hours_for("high");
        let vuln = make_vuln(VulnSeverity::High, sla_hours);
        let multiplier = scorer.age_multiplier(&vuln);
        // At SLA deadline, age_fraction=1.0, multiplier=3.0
        assert!(
            (multiplier - 3.0).abs() < 0.1,
            "age multiplier at SLA deadline should be ~3.0, got {}",
            multiplier
        );
    }

    // ── SLA deadline computation tests ───────────────────────────────────────

    #[test]
    fn test_sla_deadline_critical_is_24_hours() {
        let config = SecurityComplianceConfig::default();
        assert_eq!(config.sla_hours_for("critical"), 24);
    }

    #[test]
    fn test_sla_deadline_high_is_7_days() {
        let config = SecurityComplianceConfig::default();
        assert_eq!(config.sla_hours_for("high"), 7 * 24);
    }

    #[test]
    fn test_sla_deadline_medium_is_30_days() {
        let config = SecurityComplianceConfig::default();
        assert_eq!(config.sla_hours_for("medium"), 30 * 24);
    }

    #[test]
    fn test_sla_deadline_low_is_90_days() {
        let config = SecurityComplianceConfig::default();
        assert_eq!(config.sla_hours_for("low"), 90 * 24);
    }

    #[test]
    fn test_sla_breach_detection_for_overdue_vuln() {
        let config = SecurityComplianceConfig::default();
        // A critical vuln discovered 25 hours ago is past its 24-hour SLA.
        let vuln = make_vuln(VulnSeverity::Critical, 25);
        assert!(vuln.is_sla_breached(), "critical vuln 25h old should be SLA breached");
    }

    #[test]
    fn test_no_sla_breach_for_fresh_critical_vuln() {
        // A critical vuln discovered 1 hour ago is within its 24-hour SLA.
        let vuln = make_vuln(VulnSeverity::Critical, 1);
        assert!(!vuln.is_sla_breached(), "critical vuln 1h old should not be SLA breached");
    }

    #[test]
    fn test_resolved_vuln_not_sla_breached() {
        let mut vuln = make_vuln(VulnSeverity::Critical, 25);
        vuln.status = VulnStatus::Resolved;
        assert!(
            !vuln.is_sla_breached(),
            "resolved vuln should not be considered SLA breached"
        );
    }

    // ── Allowlist enforcement tests ───────────────────────────────────────────

    #[test]
    fn test_allowlist_entry_active_before_expiry() {
        use crate::security_compliance::models::AllowlistEntry;
        let entry = AllowlistEntry {
            id: Uuid::new_v4(),
            identifier: "RUSTSEC-2024-0001".to_string(),
            source: VulnSource::CargoAudit,
            justification: "False positive — not reachable in our code path".to_string(),
            added_by: "security-team".to_string(),
            expiry_date: Utc::now() + Duration::days(30),
            created_at: Utc::now(),
        };
        assert!(entry.is_active(), "entry with future expiry should be active");
    }

    #[test]
    fn test_allowlist_entry_inactive_after_expiry() {
        use crate::security_compliance::models::AllowlistEntry;
        let entry = AllowlistEntry {
            id: Uuid::new_v4(),
            identifier: "RUSTSEC-2023-0001".to_string(),
            source: VulnSource::CargoAudit,
            justification: "Expired acceptance".to_string(),
            added_by: "security-team".to_string(),
            expiry_date: Utc::now() - Duration::days(1),
            created_at: Utc::now() - Duration::days(31),
        };
        assert!(!entry.is_active(), "entry with past expiry should be inactive");
    }

    // ── Severity count tests ──────────────────────────────────────────────────

    #[test]
    fn test_count_by_severity() {
        let vulns = vec![
            make_vuln(VulnSeverity::Critical, 1),
            make_vuln(VulnSeverity::Critical, 2),
            make_vuln(VulnSeverity::High, 1),
            make_vuln(VulnSeverity::Medium, 1),
        ];
        let counts = PostureScorer::count_by_severity(&vulns);
        assert_eq!(counts.critical, 2);
        assert_eq!(counts.high, 1);
        assert_eq!(counts.medium, 1);
        assert_eq!(counts.low, 0);
    }

    #[test]
    fn test_count_sla_breached() {
        let vulns = vec![
            make_vuln(VulnSeverity::Critical, 25), // breached (24h SLA)
            make_vuln(VulnSeverity::Critical, 1),  // not breached
            make_vuln(VulnSeverity::High, 1),      // not breached
        ];
        let breached = PostureScorer::count_sla_breached(&vulns);
        assert_eq!(breached, 1, "only the 25h-old critical should be breached");
    }

    // ── Domain breakdown tests ────────────────────────────────────────────────

    #[test]
    fn test_domain_breakdown_groups_by_source() {
        let config = SecurityComplianceConfig::default();
        let scorer = PostureScorer::new(&config);

        let mut cargo_vuln = make_vuln(VulnSeverity::High, 1);
        cargo_vuln.source = VulnSource::CargoAudit;

        let mut sast_vuln = make_vuln(VulnSeverity::Medium, 1);
        sast_vuln.source = VulnSource::Sast;

        let breakdown = scorer.domain_breakdown(&[cargo_vuln, sast_vuln]);
        let obj = breakdown.as_object().unwrap();
        assert!(obj.contains_key("cargo_audit"), "breakdown should include cargo_audit");
        assert!(obj.contains_key("sast"), "breakdown should include sast");
    }
}
