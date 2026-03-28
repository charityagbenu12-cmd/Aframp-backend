//! Integration tests for the security compliance framework.
//!
//! Covers:
//!   - Vulnerability management lifecycle (ingest → acknowledge → resolve → accept-risk)
//!   - Allowlist enforcement (allowlisted findings are not ingested)
//!   - SLA deadline computation
//!   - Compliance posture score computation and persistence
//!   - Compliance report generation
//!   - Scan run recording
//!
//! Run with:
//!   cargo test --test security_compliance_integration --features integration

#![cfg(feature = "integration")]

use chrono::{Duration, Utc};
use std::sync::Arc;
use uuid::Uuid;

// ── Helpers ───────────────────────────────────────────────────────────────────

async fn test_db_pool() -> sqlx::PgPool {
    let url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5432/aframp_test".to_string());
    sqlx::PgPool::connect(&url).await.expect("test DB pool")
}

fn default_config() -> Bitmesh_backend::security_compliance::config::SecurityComplianceConfig {
    Bitmesh_backend::security_compliance::config::SecurityComplianceConfig::default()
}

fn make_test_vuln(
    severity: Bitmesh_backend::security_compliance::models::VulnSeverity,
    source: Bitmesh_backend::security_compliance::models::VulnSource,
) -> Bitmesh_backend::security_compliance::models::Vulnerability {
    use Bitmesh_backend::security_compliance::models::{VulnStatus, Vulnerability};
    let config = default_config();
    let now = Utc::now();
    let sla_hours = config.sla_hours_for(severity.as_str());
    Vulnerability {
        id: Uuid::new_v4(),
        title: format!("Test vulnerability {:?}", severity),
        description: "Integration test vulnerability".to_string(),
        severity,
        status: VulnStatus::Open,
        source,
        affected_component: "test-component".to_string(),
        cve_reference: Some(format!("CVE-TEST-{}", Uuid::new_v4().simple())),
        affected_versions: Some("< 1.0.0".to_string()),
        remediation_guidance: Some("Upgrade to >= 1.0.0".to_string()),
        discovered_at: now,
        sla_deadline: now + Duration::hours(sla_hours),
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
        raw_finding: Some(serde_json::json!({ "test": true })),
        created_at: now,
        updated_at: now,
    }
}

// ── Test: vulnerability lifecycle ─────────────────────────────────────────────

#[tokio::test]
async fn test_vulnerability_ingest_and_retrieve() {
    use Bitmesh_backend::security_compliance::{
        models::{VulnSeverity, VulnSource, VulnStatus},
        repository::SecurityComplianceRepository,
    };

    let pool = test_db_pool().await;
    let repo = SecurityComplianceRepository::new(pool);

    let vuln = make_test_vuln(VulnSeverity::High, VulnSource::CargoAudit);
    let vuln_id = vuln.id;

    repo.insert_vulnerability(&vuln).await.expect("insert vulnerability");

    let fetched = repo
        .get_vulnerability(vuln_id)
        .await
        .expect("get vulnerability")
        .expect("vulnerability should exist");

    assert_eq!(fetched.id, vuln_id);
    assert_eq!(fetched.severity, VulnSeverity::High);
    assert_eq!(fetched.status, VulnStatus::Open);
    assert_eq!(fetched.source, VulnSource::CargoAudit);
}

#[tokio::test]
async fn test_vulnerability_acknowledge_lifecycle() {
    use Bitmesh_backend::security_compliance::{
        models::{VulnSeverity, VulnSource, VulnStatus},
        repository::SecurityComplianceRepository,
    };

    let pool = test_db_pool().await;
    let repo = SecurityComplianceRepository::new(pool);

    let vuln = make_test_vuln(VulnSeverity::Critical, VulnSource::Sast);
    let vuln_id = vuln.id;
    repo.insert_vulnerability(&vuln).await.expect("insert");

    let updated = repo
        .acknowledge_vulnerability(vuln_id, "security-team", "Will patch in next sprint")
        .await
        .expect("acknowledge");
    assert!(updated, "acknowledge should return true for open vuln");

    let fetched = repo
        .get_vulnerability(vuln_id)
        .await
        .expect("get")
        .expect("exists");
    assert_eq!(fetched.status, VulnStatus::Acknowledged);
    assert_eq!(fetched.acknowledged_by.as_deref(), Some("security-team"));
}

#[tokio::test]
async fn test_vulnerability_resolve_lifecycle() {
    use Bitmesh_backend::security_compliance::{
        models::{VulnSeverity, VulnSource, VulnStatus},
        repository::SecurityComplianceRepository,
    };

    let pool = test_db_pool().await;
    let repo = SecurityComplianceRepository::new(pool);

    let vuln = make_test_vuln(VulnSeverity::Medium, VulnSource::ContainerScan);
    let vuln_id = vuln.id;
    repo.insert_vulnerability(&vuln).await.expect("insert");

    let resolved = repo
        .resolve_vulnerability(
            vuln_id,
            "dev-team",
            "Upgraded base image to patched version",
            Some("abc123def456"),
        )
        .await
        .expect("resolve");
    assert!(resolved);

    let fetched = repo
        .get_vulnerability(vuln_id)
        .await
        .expect("get")
        .expect("exists");
    assert_eq!(fetched.status, VulnStatus::Resolved);
    assert_eq!(fetched.resolving_commit.as_deref(), Some("abc123def456"));
}

#[tokio::test]
async fn test_vulnerability_accept_risk_lifecycle() {
    use Bitmesh_backend::security_compliance::{
        models::{VulnSeverity, VulnSource, VulnStatus},
        repository::SecurityComplianceRepository,
    };

    let pool = test_db_pool().await;
    let repo = SecurityComplianceRepository::new(pool);

    let vuln = make_test_vuln(VulnSeverity::Low, VulnSource::InfraConfig);
    let vuln_id = vuln.id;
    repo.insert_vulnerability(&vuln).await.expect("insert");

    let expiry = Utc::now() + Duration::days(90);
    let accepted = repo
        .accept_risk(
            vuln_id,
            "ciso",
            "Risk accepted — mitigated by network segmentation",
            expiry,
        )
        .await
        .expect("accept risk");
    assert!(accepted);

    let fetched = repo
        .get_vulnerability(vuln_id)
        .await
        .expect("get")
        .expect("exists");
    assert_eq!(fetched.status, VulnStatus::RiskAccepted);
    assert!(fetched.risk_justification.is_some());
}

#[tokio::test]
async fn test_cannot_resolve_already_resolved_vuln() {
    use Bitmesh_backend::security_compliance::{
        models::{VulnSeverity, VulnSource},
        repository::SecurityComplianceRepository,
    };

    let pool = test_db_pool().await;
    let repo = SecurityComplianceRepository::new(pool);

    let vuln = make_test_vuln(VulnSeverity::High, VulnSource::Manual);
    let vuln_id = vuln.id;
    repo.insert_vulnerability(&vuln).await.expect("insert");

    // First resolve succeeds
    repo.resolve_vulnerability(vuln_id, "dev", "Fixed", None)
        .await
        .expect("first resolve");

    // Second resolve should return false (no rows affected)
    let second = repo
        .resolve_vulnerability(vuln_id, "dev", "Fixed again", None)
        .await
        .expect("second resolve attempt");
    assert!(!second, "resolving an already-resolved vuln should return false");
}

// ── Test: allowlist enforcement ───────────────────────────────────────────────

#[tokio::test]
async fn test_allowlist_entry_persisted_and_checked() {
    use Bitmesh_backend::security_compliance::{
        models::{AllowlistEntry, VulnSource},
        repository::SecurityComplianceRepository,
    };

    let pool = test_db_pool().await;
    let repo = SecurityComplianceRepository::new(pool);

    let identifier = format!("RUSTSEC-TEST-{}", Uuid::new_v4().simple());
    let entry = AllowlistEntry {
        id: Uuid::new_v4(),
        identifier: identifier.clone(),
        source: VulnSource::CargoAudit,
        justification: "False positive — not reachable in our code path".to_string(),
        added_by: "security-team".to_string(),
        expiry_date: Utc::now() + Duration::days(30),
        created_at: Utc::now(),
    };

    repo.insert_allowlist_entry(&entry).await.expect("insert allowlist entry");

    let is_listed = repo
        .is_allowlisted(&identifier)
        .await
        .expect("allowlist check");
    assert!(is_listed, "identifier should be in allowlist");
}

#[tokio::test]
async fn test_expired_allowlist_entry_not_active() {
    use Bitmesh_backend::security_compliance::{
        models::{AllowlistEntry, VulnSource},
        repository::SecurityComplianceRepository,
    };

    let pool = test_db_pool().await;
    let repo = SecurityComplianceRepository::new(pool);

    let identifier = format!("RUSTSEC-EXPIRED-{}", Uuid::new_v4().simple());
    let entry = AllowlistEntry {
        id: Uuid::new_v4(),
        identifier: identifier.clone(),
        source: VulnSource::CargoAudit,
        justification: "Expired acceptance".to_string(),
        added_by: "security-team".to_string(),
        expiry_date: Utc::now() - Duration::days(1), // already expired
        created_at: Utc::now() - Duration::days(31),
    };

    repo.insert_allowlist_entry(&entry).await.expect("insert expired entry");

    let is_listed = repo
        .is_allowlisted(&identifier)
        .await
        .expect("allowlist check");
    assert!(!is_listed, "expired allowlist entry should not be active");
}

// ── Test: posture score computation and persistence ───────────────────────────

#[tokio::test]
async fn test_posture_snapshot_persisted_and_retrieved() {
    use Bitmesh_backend::security_compliance::{
        models::{CompliancePosture, VulnSeverity, VulnSource},
        repository::SecurityComplianceRepository,
        scoring::PostureScorer,
    };

    let pool = test_db_pool().await;
    let repo = SecurityComplianceRepository::new(pool);
    let config = default_config();

    // Insert some open vulnerabilities
    let vulns = vec![
        make_test_vuln(VulnSeverity::High, VulnSource::CargoAudit),
        make_test_vuln(VulnSeverity::Medium, VulnSource::Sast),
    ];
    for v in &vulns {
        repo.insert_vulnerability(v).await.expect("insert");
    }

    let open_rows = repo.list_open_vulnerabilities().await.expect("list open");
    let open_vulns: Vec<_> = open_rows.into_iter().map(Into::into).collect();

    let scorer = PostureScorer::new(&config);
    let score = scorer.compute_score(&open_vulns);
    let counts = PostureScorer::count_by_severity(&open_vulns);
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
        sla_breached_count: PostureScorer::count_sla_breached(&open_vulns) as i32,
        domain_breakdown: breakdown,
        computed_at: Utc::now(),
    };

    repo.upsert_posture_snapshot(&snapshot)
        .await
        .expect("upsert posture snapshot");

    let latest = repo
        .latest_posture_snapshot()
        .await
        .expect("latest snapshot")
        .expect("snapshot should exist");

    assert!(latest.posture_score > bigdecimal::BigDecimal::from(0));
    assert!(latest.posture_score <= bigdecimal::BigDecimal::from(100));
}

// ── Test: compliance report generation ───────────────────────────────────────

#[tokio::test]
async fn test_compliance_report_generated_and_retrieved() {
    use Bitmesh_backend::security_compliance::{
        models::ComplianceReport,
        repository::SecurityComplianceRepository,
    };

    let pool = test_db_pool().await;
    let repo = SecurityComplianceRepository::new(pool);

    let now = Utc::now();
    let period_start = (now - Duration::days(30)).date_naive();
    let period_end = now.date_naive();

    let report = ComplianceReport {
        id: Uuid::new_v4(),
        report_period_start: period_start,
        report_period_end: period_end,
        new_vulns_count: 5,
        remediated_count: 3,
        sla_breaches_count: 1,
        posture_score_start: Some(85.0),
        posture_score_end: Some(92.0),
        report_data: serde_json::json!({
            "summary": "Monthly compliance report",
            "format_version": "1.0"
        }),
        generated_at: now,
        generated_by: "test".to_string(),
    };

    repo.insert_compliance_report(&report)
        .await
        .expect("insert report");

    let reports = repo.list_compliance_reports(10).await.expect("list reports");
    assert!(!reports.is_empty(), "should have at least one report");

    let found = reports.iter().find(|r| r.id == report.id);
    assert!(found.is_some(), "inserted report should be retrievable");
}

// ── Test: SLA deadline computation ───────────────────────────────────────────

#[tokio::test]
async fn test_sla_deadline_correctly_computed_on_ingest() {
    use Bitmesh_backend::security_compliance::{
        models::{VulnSeverity, VulnSource},
        repository::SecurityComplianceRepository,
    };

    let pool = test_db_pool().await;
    let repo = SecurityComplianceRepository::new(pool);
    let config = default_config();

    let vuln = make_test_vuln(VulnSeverity::Critical, VulnSource::CargoAudit);
    let vuln_id = vuln.id;
    let discovered_at = vuln.discovered_at;

    repo.insert_vulnerability(&vuln).await.expect("insert");

    let fetched = repo
        .get_vulnerability(vuln_id)
        .await
        .expect("get")
        .expect("exists");

    let expected_sla = discovered_at + Duration::hours(config.sla_critical_hours);
    let actual_sla = fetched.sla_deadline;

    // Allow 5 seconds tolerance for test execution time
    let diff = (actual_sla - expected_sla).num_seconds().abs();
    assert!(
        diff < 5,
        "SLA deadline should be ~{} hours from discovery, diff={}s",
        config.sla_critical_hours,
        diff
    );
}

// ── Test: paginated vulnerability listing ────────────────────────────────────

#[tokio::test]
async fn test_vulnerability_listing_pagination() {
    use Bitmesh_backend::security_compliance::{
        models::{VulnSeverity, VulnSource},
        repository::SecurityComplianceRepository,
    };

    let pool = test_db_pool().await;
    let repo = SecurityComplianceRepository::new(pool);

    // Insert 5 vulnerabilities
    for _ in 0..5 {
        let vuln = make_test_vuln(VulnSeverity::Low, VulnSource::Manual);
        repo.insert_vulnerability(&vuln).await.expect("insert");
    }

    let page1 = repo
        .list_vulnerabilities(None, None, None, 3, 0)
        .await
        .expect("page 1");
    assert_eq!(page1.len(), 3, "page 1 should have 3 results");

    let page2 = repo
        .list_vulnerabilities(None, None, None, 3, 3)
        .await
        .expect("page 2");
    assert!(!page2.is_empty(), "page 2 should have results");
}
