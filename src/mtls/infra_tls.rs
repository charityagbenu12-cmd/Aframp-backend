//! Infrastructure TLS helpers — PostgreSQL and Redis mTLS client identity.
//!
//! Each service connects to PostgreSQL and Redis using its own leaf certificate
//! (issued by the intermediate CA) so the database can enforce per-service
//! access control at the TLS layer.
//!
//! In practice the DATABASE_URL and REDIS_URL already carry `sslmode=verify-full`
//! (enforced by config_validation.rs in production).  This module provides
//! helpers that build the per-service TLS identity from the in-memory
//! CertificateStore so the same cert lifecycle applies to infra connections.

use std::sync::Arc;
use tracing::{info, warn};

use crate::mtls::cert::CertificateStore;

/// Returns the PEM certificate and key for the current service, suitable for
/// injecting into a PostgreSQL `sslcert` / `sslkey` connection parameter or a
/// Redis TLS client identity.
///
/// Returns `None` when the store has no certificate yet (e.g. during startup
/// before provisioning completes) or when the certificate is revoked/expired.
pub fn service_tls_identity(
    store: &Arc<CertificateStore>,
    service_name: &str,
) -> Option<(String, String)> {
    let cert = store.get(service_name)?;
    if cert.is_revoked || cert.is_expired() {
        warn!(
            service_name,
            serial = %cert.serial,
            "mTLS infra: certificate is revoked or expired — skipping identity injection"
        );
        return None;
    }
    info!(
        service_name,
        serial = %cert.serial,
        expires_at = %cert.expires_at,
        "mTLS infra: injecting service TLS identity for infrastructure connection"
    );
    Some((cert.cert_pem, cert.key_pem))
}

/// Build a PostgreSQL connection string that includes the per-service mTLS
/// client certificate parameters.
///
/// The base URL must already contain `sslmode=verify-full` and `sslrootcert=...`
/// (or equivalent).  This function appends `sslcert` and `sslkey` inline
/// parameters if a valid service identity is available.
///
/// Note: SQLx does not support inline PEM in the URL; in production the cert
/// and key should be written to a tmpfs path and referenced via `sslcert=<path>`.
/// This function returns the paths and PEM content so the caller can handle
/// the write.
pub fn postgres_mtls_params(
    store: &Arc<CertificateStore>,
    service_name: &str,
) -> Option<InfraMtlsParams> {
    let (cert_pem, key_pem) = service_tls_identity(store, service_name)?;
    Some(InfraMtlsParams { cert_pem, key_pem })
}

/// PEM content for a per-service infrastructure mTLS identity.
#[derive(Debug, Clone)]
pub struct InfraMtlsParams {
    /// PEM-encoded client certificate.
    pub cert_pem: String,
    /// PEM-encoded client private key.
    pub key_pem: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use crate::mtls::cert::ServiceCertificate;

    fn make_cert(service: &str, days: i64, revoked: bool) -> ServiceCertificate {
        ServiceCertificate {
            service_name: service.to_string(),
            environment: "test".to_string(),
            cert_pem: format!("CERT-{}", service),
            key_pem: format!("KEY-{}", service),
            serial: "01".to_string(),
            issued_at: Utc::now(),
            expires_at: Utc::now() + Duration::days(days),
            is_revoked: revoked,
            rotation_in_progress: false,
        }
    }

    #[test]
    fn test_valid_cert_returns_identity() {
        let store = CertificateStore::new();
        store.upsert(make_cert("aframp-backend", 30, false));
        let result = service_tls_identity(&store, "aframp-backend");
        assert!(result.is_some());
        let (cert, key) = result.unwrap();
        assert_eq!(cert, "CERT-aframp-backend");
        assert_eq!(key, "KEY-aframp-backend");
    }

    #[test]
    fn test_revoked_cert_returns_none() {
        let store = CertificateStore::new();
        store.upsert(make_cert("aframp-backend", 30, true));
        assert!(service_tls_identity(&store, "aframp-backend").is_none());
    }

    #[test]
    fn test_expired_cert_returns_none() {
        let store = CertificateStore::new();
        store.upsert(make_cert("aframp-backend", -1, false));
        assert!(service_tls_identity(&store, "aframp-backend").is_none());
    }

    #[test]
    fn test_missing_service_returns_none() {
        let store = CertificateStore::new();
        assert!(service_tls_identity(&store, "aframp-backend").is_none());
    }

    #[test]
    fn test_postgres_mtls_params_valid() {
        let store = CertificateStore::new();
        store.upsert(make_cert("aframp-backend", 30, false));
        let params = postgres_mtls_params(&store, "aframp-backend");
        assert!(params.is_some());
        assert!(!params.unwrap().cert_pem.is_empty());
    }
}
