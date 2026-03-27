//! Certificate types — ServiceIdentity, ServiceCertificate, CertificateStore.
//!
//! Uses rcgen for X.509 certificate generation (pure Rust, no OpenSSL dependency).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Registered service identities that may receive certificates.
/// Only services in this registry can be issued a leaf certificate.
pub const REGISTERED_SERVICES: &[&str] = &[
    "aframp-backend",
    "aframp-worker",
    "aframp-payment-processor",
    "aframp-stellar-monitor",
    "aframp-bill-processor",
    "aframp-batch-processor",
];

/// Parsed certificate subject fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceIdentity {
    /// Service name extracted from CN (e.g. "aframp-backend").
    pub service_name: String,
    /// Environment extracted from O (e.g. "production").
    pub environment: String,
    /// Full subject string.
    pub subject: String,
}

impl ServiceIdentity {
    /// Build a subject string from service name and environment.
    /// Format: `CN=<service_name>,O=<environment>,OU=aframp-internal`
    pub fn subject_for(service_name: &str, environment: &str) -> String {
        format!(
            "CN={},O={},OU=aframp-internal",
            service_name, environment
        )
    }

    /// Parse a subject string into a ServiceIdentity.
    /// Returns `None` if the subject does not match the expected format.
    pub fn parse(subject: &str) -> Option<Self> {
        let mut cn = None;
        let mut o = None;
        for part in subject.split(',') {
            let part = part.trim();
            if let Some(v) = part.strip_prefix("CN=") {
                cn = Some(v.to_string());
            } else if let Some(v) = part.strip_prefix("O=") {
                o = Some(v.to_string());
            }
        }
        Some(Self {
            service_name: cn?,
            environment: o.unwrap_or_default(),
            subject: subject.to_string(),
        })
    }

    /// Returns true if this identity is in the registered service registry.
    pub fn is_registered(&self) -> bool {
        REGISTERED_SERVICES.contains(&self.service_name.as_str())
    }
}

/// A provisioned leaf service certificate with its private key (in-memory only).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceCertificate {
    pub service_name: String,
    pub environment: String,
    /// PEM-encoded certificate.
    pub cert_pem: String,
    /// PEM-encoded private key — never written to disk outside secrets manager.
    pub key_pem: String,
    /// Certificate serial number (hex string).
    pub serial: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub is_revoked: bool,
    /// Whether a rotation is currently in progress.
    pub rotation_in_progress: bool,
}

impl ServiceCertificate {
    pub fn days_until_expiry(&self) -> i64 {
        (self.expires_at - Utc::now()).num_days()
    }

    pub fn is_expired(&self) -> bool {
        Utc::now() >= self.expires_at
    }

    pub fn needs_rotation(&self, threshold_days: i64) -> bool {
        self.days_until_expiry() <= threshold_days && !self.is_revoked
    }
}

/// In-memory certificate store shared across the application.
/// Holds the current and (during rotation grace period) previous certificate.
#[derive(Debug, Default)]
pub struct CertificateStore {
    inner: RwLock<HashMap<String, CertEntry>>,
}

#[derive(Debug, Clone)]
struct CertEntry {
    current: ServiceCertificate,
    /// Previous certificate kept during zero-downtime rotation grace period.
    previous: Option<ServiceCertificate>,
}

impl CertificateStore {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Store a new certificate, moving the current one to `previous`.
    pub fn upsert(&self, cert: ServiceCertificate) {
        let mut map = self.inner.write().unwrap();
        let entry = map.entry(cert.service_name.clone()).or_insert_with(|| CertEntry {
            current: cert.clone(),
            previous: None,
        });
        let old = std::mem::replace(&mut entry.current, cert);
        entry.previous = Some(old);
    }

    /// Get the current certificate for a service.
    pub fn get(&self, service_name: &str) -> Option<ServiceCertificate> {
        self.inner.read().unwrap().get(service_name).map(|e| e.current.clone())
    }

    /// Get both current and previous certificates (for zero-downtime rotation).
    pub fn get_both(&self, service_name: &str) -> (Option<ServiceCertificate>, Option<ServiceCertificate>) {
        let map = self.inner.read().unwrap();
        match map.get(service_name) {
            Some(e) => (Some(e.current.clone()), e.previous.clone()),
            None => (None, None),
        }
    }

    /// List all current certificates.
    pub fn list_all(&self) -> Vec<ServiceCertificate> {
        self.inner.read().unwrap().values().map(|e| e.current.clone()).collect()
    }

    /// Mark a certificate as revoked.
    pub fn mark_revoked(&self, service_name: &str) {
        let mut map = self.inner.write().unwrap();
        if let Some(entry) = map.get_mut(service_name) {
            entry.current.is_revoked = true;
        }
    }

    /// Clear the previous certificate after the rotation grace period.
    pub fn clear_previous(&self, service_name: &str) {
        let mut map = self.inner.write().unwrap();
        if let Some(entry) = map.get_mut(service_name) {
            entry.previous = None;
        }
    }
}

/// Summary of a certificate for the admin inventory endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateSummary {
    pub service_name: String,
    pub serial: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub days_until_expiry: i64,
    pub is_revoked: bool,
    pub rotation_in_progress: bool,
    pub rotation_status: String,
}

impl From<&ServiceCertificate> for CertificateSummary {
    fn from(c: &ServiceCertificate) -> Self {
        let days = c.days_until_expiry();
        let rotation_status = if c.is_revoked {
            "revoked".to_string()
        } else if c.rotation_in_progress {
            "rotating".to_string()
        } else if days <= 7 {
            "critical".to_string()
        } else if days <= 14 {
            "due".to_string()
        } else {
            "ok".to_string()
        };
        Self {
            service_name: c.service_name.clone(),
            serial: c.serial.clone(),
            issued_at: c.issued_at,
            expires_at: c.expires_at,
            days_until_expiry: days,
            is_revoked: c.is_revoked,
            rotation_in_progress: c.rotation_in_progress,
            rotation_status,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn test_subject_round_trip() {
        let subject = ServiceIdentity::subject_for("aframp-backend", "production");
        let parsed = ServiceIdentity::parse(&subject).unwrap();
        assert_eq!(parsed.service_name, "aframp-backend");
        assert_eq!(parsed.environment, "production");
    }

    #[test]
    fn test_parse_invalid_subject_returns_none() {
        assert!(ServiceIdentity::parse("not-a-valid-subject").is_none());
    }

    #[test]
    fn test_registered_service_check() {
        let id = ServiceIdentity {
            service_name: "aframp-backend".to_string(),
            environment: "production".to_string(),
            subject: "CN=aframp-backend,O=production,OU=aframp-internal".to_string(),
        };
        assert!(id.is_registered());

        let unknown = ServiceIdentity {
            service_name: "rogue-service".to_string(),
            environment: "production".to_string(),
            subject: "CN=rogue-service,O=production,OU=aframp-internal".to_string(),
        };
        assert!(!unknown.is_registered());
    }

    #[test]
    fn test_days_until_expiry() {
        let cert = ServiceCertificate {
            service_name: "test".to_string(),
            environment: "test".to_string(),
            cert_pem: String::new(),
            key_pem: String::new(),
            serial: "01".to_string(),
            issued_at: Utc::now(),
            expires_at: Utc::now() + Duration::days(10),
            is_revoked: false,
            rotation_in_progress: false,
        };
        assert!(cert.days_until_expiry() >= 9 && cert.days_until_expiry() <= 10);
        assert!(cert.needs_rotation(14));
        assert!(!cert.needs_rotation(5));
    }

    #[test]
    fn test_rotation_threshold_calculation() {
        let cert = ServiceCertificate {
            service_name: "test".to_string(),
            environment: "test".to_string(),
            cert_pem: String::new(),
            key_pem: String::new(),
            serial: "02".to_string(),
            issued_at: Utc::now(),
            expires_at: Utc::now() + Duration::days(20),
            is_revoked: false,
            rotation_in_progress: false,
        };
        // 20 days left, threshold 14 → no rotation needed
        assert!(!cert.needs_rotation(14));
        // threshold 21 → rotation needed
        assert!(cert.needs_rotation(21));
    }

    #[test]
    fn test_certificate_store_zero_downtime_rotation() {
        let store = CertificateStore::new();
        let cert1 = ServiceCertificate {
            service_name: "svc".to_string(),
            environment: "test".to_string(),
            cert_pem: "cert1".to_string(),
            key_pem: "key1".to_string(),
            serial: "01".to_string(),
            issued_at: Utc::now(),
            expires_at: Utc::now() + Duration::days(90),
            is_revoked: false,
            rotation_in_progress: false,
        };
        store.upsert(cert1.clone());
        let cert2 = ServiceCertificate {
            serial: "02".to_string(),
            cert_pem: "cert2".to_string(),
            key_pem: "key2".to_string(),
            ..cert1
        };
        store.upsert(cert2);
        let (current, previous) = store.get_both("svc");
        assert_eq!(current.unwrap().serial, "02");
        assert_eq!(previous.unwrap().serial, "01");
    }
}
