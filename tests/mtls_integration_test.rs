//! Integration tests for mTLS certificate lifecycle (Issue #204).
//!
//! Covers:
//! - Full certificate issuance and provisioning lifecycle
//! - mTLS enforcement on internal endpoints
//! - Zero-downtime certificate rotation
//! - Certificate revocation and connection rejection
//! - Expiry alerting threshold logic

use chrono::{Duration, Utc};

// Re-use types from the library crate
use Bitmesh_backend::mtls::cert::{
    CertificateStore, CertificateSummary, ServiceCertificate, ServiceIdentity,
    REGISTERED_SERVICES,
};
use Bitmesh_backend::mtls::revocation::{OcspStatus, RevocationList, RevocationService};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_cert(serial: &str, service: &str, days: i64, revoked: bool) -> ServiceCertificate {
    ServiceCertificate {
        service_name: service.to_string(),
        environment: "test".to_string(),
        cert_pem: format!("CERT-{}", serial),
        key_pem: format!("KEY-{}", serial),
        serial: serial.to_string(),
        issued_at: Utc::now(),
        expires_at: Utc::now() + Duration::days(days),
        is_revoked: revoked,
        rotation_in_progress: false,
    }
}

// ---------------------------------------------------------------------------
// Certificate issuance and provisioning lifecycle
// ---------------------------------------------------------------------------

#[test]
fn test_certificate_store_provisioning_lifecycle() {
    let store = CertificateStore::new();
    let cert = make_cert("serial-001", "aframp-backend", 90, false);
    store.upsert(cert.clone());

    let retrieved = store.get("aframp-backend").unwrap();
    assert_eq!(retrieved.serial, "serial-001");
    assert!(!retrieved.is_expired());
    assert!(!retrieved.is_revoked);
}

#[test]
fn test_zero_downtime_rotation_keeps_previous_cert() {
    let store = CertificateStore::new();
    let cert1 = make_cert("serial-001", "aframp-backend", 90, false);
    store.upsert(cert1);

    let cert2 = make_cert("serial-002", "aframp-backend", 90, false);
    store.upsert(cert2);

    let (current, previous) = store.get_both("aframp-backend");
    assert_eq!(current.unwrap().serial, "serial-002");
    assert_eq!(previous.unwrap().serial, "serial-001");
}

#[test]
fn test_previous_cert_cleared_after_grace_period() {
    let store = CertificateStore::new();
    store.upsert(make_cert("s1", "aframp-backend", 90, false));
    store.upsert(make_cert("s2", "aframp-backend", 90, false));
    store.clear_previous("aframp-backend");
    let (_, previous) = store.get_both("aframp-backend");
    assert!(previous.is_none());
}

// ---------------------------------------------------------------------------
// mTLS enforcement — identity extraction and validation
// ---------------------------------------------------------------------------

#[test]
fn test_mtls_subject_parsing_valid() {
    let subject = ServiceIdentity::subject_for("aframp-backend", "production");
    let id = ServiceIdentity::parse(&subject).unwrap();
    assert_eq!(id.service_name, "aframp-backend");
    assert_eq!(id.environment, "production");
    assert!(id.is_registered());
}

#[test]
fn test_mtls_subject_parsing_unregistered_service() {
    let subject = "CN=rogue-service,O=production,OU=aframp-internal";
    let id = ServiceIdentity::parse(subject).unwrap();
    assert!(!id.is_registered());
}

#[test]
fn test_mtls_subject_parsing_missing_cn_returns_none() {
    let subject = "O=production,OU=aframp-internal";
    assert!(ServiceIdentity::parse(subject).is_none());
}

#[test]
fn test_all_registered_services_have_valid_subjects() {
    for &svc in REGISTERED_SERVICES {
        let subject = ServiceIdentity::subject_for(svc, "production");
        let id = ServiceIdentity::parse(&subject).unwrap();
        assert_eq!(id.service_name, svc);
        assert!(id.is_registered());
    }
}

// ---------------------------------------------------------------------------
// Certificate revocation and connection rejection
// ---------------------------------------------------------------------------

#[test]
fn test_revocation_adds_to_crl_immediately() {
    let crl = RevocationList::new();
    let store = CertificateStore::new();
    let cert = make_cert("rev-001", "aframp-backend", 90, false);
    store.upsert(cert);

    let svc = RevocationService::new(crl.clone(), store.clone());
    let serial = svc.revoke_certificate("aframp-backend", "key_compromise");
    assert!(serial.is_some());
    assert!(crl.is_revoked("rev-001"));
}

#[test]
fn test_revoked_cert_rejected_by_ocsp() {
    let crl = RevocationList::new();
    crl.revoke("rev-002", "aframp-backend", "test");
    let store = CertificateStore::new();
    let svc = RevocationService::new(crl, store);
    let cert = make_cert("rev-002", "aframp-backend", 90, false);
    assert_eq!(svc.ocsp_check(&cert), OcspStatus::Revoked);
}

#[test]
fn test_expired_cert_rejected_by_ocsp() {
    let crl = RevocationList::new();
    let store = CertificateStore::new();
    let svc = RevocationService::new(crl, store);
    let cert = make_cert("exp-001", "aframp-backend", -1, false);
    assert_eq!(svc.ocsp_check(&cert), OcspStatus::Expired);
}

#[test]
fn test_valid_cert_passes_ocsp() {
    let crl = RevocationList::new();
    let store = CertificateStore::new();
    let svc = RevocationService::new(crl, store);
    let cert = make_cert("ok-001", "aframp-backend", 30, false);
    assert_eq!(svc.ocsp_check(&cert), OcspStatus::Good);
}

// ---------------------------------------------------------------------------
// Expiry alerting threshold logic
// ---------------------------------------------------------------------------

#[test]
fn test_rotation_threshold_triggers_at_14_days() {
    let cert = make_cert("thresh-001", "aframp-backend", 13, false);
    assert!(cert.needs_rotation(14));
}

#[test]
fn test_rotation_threshold_does_not_trigger_at_15_days() {
    let cert = make_cert("thresh-002", "aframp-backend", 15, false);
    assert!(!cert.needs_rotation(14));
}

#[test]
fn test_alert_threshold_at_7_days() {
    let cert = make_cert("alert-001", "aframp-backend", 6, false);
    assert!(cert.needs_rotation(7));
}

#[test]
fn test_revoked_cert_does_not_trigger_rotation() {
    let cert = make_cert("rev-thresh", "aframp-backend", 5, true);
    // is_revoked=true → needs_rotation returns false
    assert!(!cert.needs_rotation(14));
}

// ---------------------------------------------------------------------------
// Certificate inventory summary
// ---------------------------------------------------------------------------

#[test]
fn test_certificate_summary_rotation_status_ok() {
    let cert = make_cert("sum-001", "aframp-backend", 30, false);
    let summary = CertificateSummary::from(&cert);
    assert_eq!(summary.rotation_status, "ok");
}

#[test]
fn test_certificate_summary_rotation_status_due() {
    let cert = make_cert("sum-002", "aframp-backend", 10, false);
    let summary = CertificateSummary::from(&cert);
    assert_eq!(summary.rotation_status, "due");
}

#[test]
fn test_certificate_summary_rotation_status_critical() {
    let cert = make_cert("sum-003", "aframp-backend", 5, false);
    let summary = CertificateSummary::from(&cert);
    assert_eq!(summary.rotation_status, "critical");
}

#[test]
fn test_certificate_summary_rotation_status_revoked() {
    let cert = make_cert("sum-004", "aframp-backend", 30, true);
    let summary = CertificateSummary::from(&cert);
    assert_eq!(summary.rotation_status, "revoked");
}

// ---------------------------------------------------------------------------
// CRL entries
// ---------------------------------------------------------------------------

#[test]
fn test_crl_entries_recorded() {
    let crl = RevocationList::new();
    crl.revoke("crl-001", "aframp-backend", "key_compromise");
    crl.revoke("crl-002", "aframp-worker", "superseded");
    let entries = crl.entries();
    assert_eq!(entries.len(), 2);
    assert!(entries.iter().any(|e| e.serial == "crl-001"));
    assert!(entries.iter().any(|e| e.serial == "crl-002"));
}

// ---------------------------------------------------------------------------
// Store list_all
// ---------------------------------------------------------------------------

#[test]
fn test_store_list_all_returns_all_services() {
    let store = CertificateStore::new();
    store.upsert(make_cert("s1", "aframp-backend", 90, false));
    store.upsert(make_cert("s2", "aframp-worker", 90, false));
    let all = store.list_all();
    assert_eq!(all.len(), 2);
}
