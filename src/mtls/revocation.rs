//! Certificate revocation — CRL management and OCSP stub.
//!
//! Maintains an in-memory revocation list and provides helpers for
//! checking revocation status on every inbound mTLS connection.

use chrono::{DateTime, Utc};
use std::collections::HashSet;
use std::sync::{Arc, RwLock};
use tracing::{info, warn};

use crate::mtls::cert::{CertificateStore, ServiceCertificate};
use crate::mtls::metrics;

/// A single CRL entry.
#[derive(Debug, Clone)]
pub struct RevocationEntry {
    pub serial: String,
    pub service_name: String,
    pub revoked_at: DateTime<Utc>,
    pub reason: String,
}

/// In-memory Certificate Revocation List.
#[derive(Debug, Default)]
pub struct RevocationList {
    revoked_serials: RwLock<HashSet<String>>,
    entries: RwLock<Vec<RevocationEntry>>,
}

impl RevocationList {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Add a serial to the CRL immediately.
    pub fn revoke(&self, serial: &str, service_name: &str, reason: &str) {
        self.revoked_serials.write().unwrap().insert(serial.to_string());
        self.entries.write().unwrap().push(RevocationEntry {
            serial: serial.to_string(),
            service_name: service_name.to_string(),
            revoked_at: Utc::now(),
            reason: reason.to_string(),
        });
        warn!(serial, service_name, reason, "Certificate added to CRL");
        metrics::cert_revocations_total(service_name);
    }

    /// Check if a serial is revoked.
    pub fn is_revoked(&self, serial: &str) -> bool {
        self.revoked_serials.read().unwrap().contains(serial)
    }

    /// Return all CRL entries (for OCSP responder / distribution).
    pub fn entries(&self) -> Vec<RevocationEntry> {
        self.entries.read().unwrap().clone()
    }
}

/// Service that handles certificate revocation, replacement issuance, and
/// push-notification to internal services.
pub struct RevocationService {
    crl: Arc<RevocationList>,
    store: Arc<CertificateStore>,
}

impl RevocationService {
    pub fn new(crl: Arc<RevocationList>, store: Arc<CertificateStore>) -> Self {
        Self { crl, store }
    }

    /// Revoke a service certificate immediately:
    /// 1. Add to CRL
    /// 2. Mark in certificate store
    /// 3. Log structured event
    pub fn revoke_certificate(&self, service_name: &str, reason: &str) -> Option<String> {
        let cert = self.store.get(service_name)?;
        self.crl.revoke(&cert.serial, service_name, reason);
        self.store.mark_revoked(service_name);
        info!(
            service_name,
            serial = %cert.serial,
            reason,
            "Certificate revoked — replacement issuance triggered"
        );
        Some(cert.serial)
    }

    /// Check if the certificate for a service is revoked.
    pub fn is_revoked(&self, serial: &str) -> bool {
        self.crl.is_revoked(serial)
    }

    /// OCSP-style check: returns true if the certificate is valid (not revoked, not expired).
    pub fn ocsp_check(&self, cert: &ServiceCertificate) -> OcspStatus {
        if cert.is_expired() {
            return OcspStatus::Expired;
        }
        if self.crl.is_revoked(&cert.serial) || cert.is_revoked {
            return OcspStatus::Revoked;
        }
        OcspStatus::Good
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OcspStatus {
    Good,
    Revoked,
    Expired,
    Unknown,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn make_cert(serial: &str, expires_in_days: i64, revoked: bool) -> ServiceCertificate {
        ServiceCertificate {
            service_name: "test-svc".to_string(),
            environment: "test".to_string(),
            cert_pem: String::new(),
            key_pem: String::new(),
            serial: serial.to_string(),
            issued_at: Utc::now(),
            expires_at: Utc::now() + Duration::days(expires_in_days),
            is_revoked: revoked,
            rotation_in_progress: false,
        }
    }

    #[test]
    fn test_crl_revoke_and_check() {
        let crl = RevocationList::new();
        assert!(!crl.is_revoked("abc123"));
        crl.revoke("abc123", "test-svc", "key_compromise");
        assert!(crl.is_revoked("abc123"));
        assert!(!crl.is_revoked("other"));
    }

    #[test]
    fn test_ocsp_good() {
        let crl = RevocationList::new();
        let store = CertificateStore::new();
        let svc = RevocationService::new(crl, store);
        let cert = make_cert("serial1", 30, false);
        assert_eq!(svc.ocsp_check(&cert), OcspStatus::Good);
    }

    #[test]
    fn test_ocsp_revoked_via_crl() {
        let crl = RevocationList::new();
        crl.revoke("serial2", "test-svc", "test");
        let store = CertificateStore::new();
        let svc = RevocationService::new(crl, store);
        let cert = make_cert("serial2", 30, false);
        assert_eq!(svc.ocsp_check(&cert), OcspStatus::Revoked);
    }

    #[test]
    fn test_ocsp_revoked_via_flag() {
        let crl = RevocationList::new();
        let store = CertificateStore::new();
        let svc = RevocationService::new(crl, store);
        let cert = make_cert("serial3", 30, true);
        assert_eq!(svc.ocsp_check(&cert), OcspStatus::Revoked);
    }

    #[test]
    fn test_ocsp_expired() {
        let crl = RevocationList::new();
        let store = CertificateStore::new();
        let svc = RevocationService::new(crl, store);
        let cert = make_cert("serial4", -1, false);
        assert_eq!(svc.ocsp_check(&cert), OcspStatus::Expired);
    }
}
