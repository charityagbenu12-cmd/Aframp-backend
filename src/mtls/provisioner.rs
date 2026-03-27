//! Certificate provisioner — provisions and rotates leaf service certificates.
//!
//! At service startup, checks if a valid certificate exists; if not (or if
//! within the rotation threshold), requests a new one from the intermediate CA.
//! Supports zero-downtime rotation by keeping the old cert valid during grace period.

use std::sync::Arc;
use tracing::{error, info, warn};

use crate::mtls::ca::IntermediateCa;
use crate::mtls::cert::{CertificateStore, ServiceCertificate};
use crate::mtls::config::MtlsConfig;
use crate::mtls::metrics;
use crate::mtls::revocation::RevocationService;

/// Handles certificate provisioning and rotation for a single service.
pub struct CertificateProvisioner {
    /// `None` when the intermediate CA PEM is not configured (dev / no-CA mode).
    ca: Option<Arc<IntermediateCa>>,
    store: Arc<CertificateStore>,
    revocation: Arc<RevocationService>,
    config: MtlsConfig,
}

impl CertificateProvisioner {
    pub fn new(
        ca: Arc<IntermediateCa>,
        store: Arc<CertificateStore>,
        revocation: Arc<RevocationService>,
        config: MtlsConfig,
    ) -> Self {
        Self { ca: Some(ca), store, revocation, config }
    }

    /// Create a provisioner with no CA configured (admin endpoints still work,
    /// but issuance will return an error).
    pub fn without_ca(
        store: Arc<CertificateStore>,
        revocation: Arc<RevocationService>,
        config: MtlsConfig,
    ) -> Self {
        Self { ca: None, store, revocation, config }
    }

    /// Provision a certificate at startup if none exists or rotation is due.
    /// Returns the current valid certificate.
    pub fn provision_at_startup(&self, service_name: &str) -> Result<ServiceCertificate, String> {
        match self.store.get(service_name) {
            Some(cert) if !cert.is_revoked && !cert.is_expired()
                && !cert.needs_rotation(self.config.rotation_threshold_days) =>
            {
                info!(service_name, "Existing certificate is valid — no provisioning needed");
                Ok(cert)
            }
            _ => {
                info!(service_name, "Provisioning new leaf certificate at startup");
                self.issue_and_store(service_name)
            }
        }
    }

    /// Issue a new certificate and store it (triggers zero-downtime rotation).
    pub fn issue_and_store(&self, service_name: &str) -> Result<ServiceCertificate, String> {
        let ca = self.ca.as_ref()
            .ok_or_else(|| "Intermediate CA not configured — set MTLS_INTERMEDIATE_CA_CERT_PEM and MTLS_INTERMEDIATE_CA_KEY_PEM".to_string())?;
        let mut cert = ca.issue_leaf_cert(service_name)
            .map_err(|e| format!("Certificate issuance failed: {}", e))?;
        cert.rotation_in_progress = true;
        self.store.upsert(cert.clone());
        metrics::cert_rotations_total(service_name);
        info!(
            service_name,
            serial = %cert.serial,
            expires_at = %cert.expires_at,
            "New leaf certificate stored"
        );
        // Mark rotation complete after storing
        let mut final_cert = cert.clone();
        final_cert.rotation_in_progress = false;
        self.store.upsert(final_cert.clone());
        Ok(final_cert)
    }

    /// Rotate a certificate for a service (admin-initiated or automated).
    pub fn rotate(&self, service_name: &str) -> Result<ServiceCertificate, String> {
        info!(service_name, "Certificate rotation initiated");
        self.issue_and_store(service_name)
    }

    /// Revoke and immediately replace a certificate.
    pub fn revoke_and_replace(
        &self,
        service_name: &str,
        reason: &str,
    ) -> Result<ServiceCertificate, String> {
        self.revocation.revoke_certificate(service_name, reason);
        warn!(service_name, reason, "Certificate revoked — issuing replacement");
        self.issue_and_store(service_name)
    }

    /// Check all registered services and rotate any approaching expiry.
    pub fn rotate_expiring(&self, service_names: &[&str]) {
        for &name in service_names {
            if let Some(cert) = self.store.get(name) {
                if cert.needs_rotation(self.config.rotation_threshold_days) {
                    info!(name, days_left = cert.days_until_expiry(), "Auto-rotating expiring certificate");
                    if let Err(e) = self.rotate(name) {
                        error!(name, error = %e, "Auto-rotation failed");
                    }
                }
            }
        }
    }
}
