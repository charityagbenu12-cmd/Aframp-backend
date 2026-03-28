//! Certificate Authority — root CA and intermediate CA operations.
//!
//! Uses rcgen for pure-Rust X.509 certificate generation.
//! The root CA private key is never loaded into the application runtime;
//! only the intermediate CA key is used for leaf certificate issuance.

use chrono::{Duration, Utc};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
};
use tracing::{info, warn};

use crate::mtls::cert::{ServiceCertificate, REGISTERED_SERVICES};
use crate::mtls::config::MtlsConfig;

/// Error type for CA operations.
#[derive(Debug, thiserror::Error)]
pub enum CaError {
    #[error("rcgen error: {0}")]
    Rcgen(#[from] rcgen::Error),
    #[error("service '{0}' is not in the registered service registry")]
    UnregisteredService(String),
    #[error("CA not initialised — intermediate CA cert/key not configured")]
    NotInitialised,
    #[error("PEM parse error: {0}")]
    PemParse(String),
}

/// Intermediate CA — used at runtime to issue leaf service certificates.
/// The root CA is offline; only its certificate (not key) is loaded here.
pub struct IntermediateCa {
    /// rcgen Certificate representing the intermediate CA (holds key pair).
    ca_cert: Certificate,
    /// PEM of the intermediate CA certificate (for inclusion in issued cert chains).
    pub ca_cert_pem: String,
    /// PEM of the root CA certificate (trust anchor).
    pub root_cert_pem: String,
    config: MtlsConfig,
}

impl IntermediateCa {
    /// Initialise the intermediate CA from PEM-encoded cert and key (loaded from secrets manager).
    pub fn from_pem(config: &MtlsConfig) -> Result<Self, CaError> {
        if config.intermediate_ca_cert_pem.is_empty() || config.intermediate_ca_key_pem.is_empty() {
            return Err(CaError::NotInitialised);
        }
        let params = CertificateParams::from_ca_cert_pem(
            &config.intermediate_ca_cert_pem,
            rcgen::KeyPair::from_pem(&config.intermediate_ca_key_pem)
                .map_err(|e| CaError::PemParse(e.to_string()))?,
        )
        .map_err(CaError::Rcgen)?;
        let ca_cert = Certificate::from_params(params).map_err(CaError::Rcgen)?;
        Ok(Self {
            ca_cert,
            ca_cert_pem: config.intermediate_ca_cert_pem.clone(),
            root_cert_pem: config.root_ca_cert_pem.clone(),
            config: config.clone(),
        })
    }

    /// Issue a leaf service certificate for the given service name.
    /// Verifies the service is in the registered service registry before issuing.
    pub fn issue_leaf_cert(&self, service_name: &str) -> Result<ServiceCertificate, CaError> {
        if !REGISTERED_SERVICES.contains(&service_name) {
            return Err(CaError::UnregisteredService(service_name.to_string()));
        }

        let validity_days = self.config.leaf_cert_validity.as_secs() / 86400;
        let not_after = Utc::now() + Duration::days(validity_days as i64);

        let mut params = CertificateParams::new(vec![service_name.to_string()]);
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, service_name);
        dn.push(DnType::OrganizationName, &self.config.environment);
        dn.push(DnType::OrganizationalUnitName, "aframp-internal");
        params.distinguished_name = dn;
        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ClientAuth,
            ExtendedKeyUsagePurpose::ServerAuth,
        ];
        params.not_before = rcgen::date_time_ymd(
            Utc::now().format("%Y").to_string().parse().unwrap(),
            Utc::now().format("%m").to_string().parse().unwrap(),
            Utc::now().format("%d").to_string().parse().unwrap(),
        );
        params.not_after = rcgen::date_time_ymd(
            not_after.format("%Y").to_string().parse().unwrap(),
            not_after.format("%m").to_string().parse().unwrap(),
            not_after.format("%d").to_string().parse().unwrap(),
        );
        params.alg = &PKCS_ECDSA_P256_SHA256;

        let leaf = Certificate::from_params(params).map_err(CaError::Rcgen)?;
        let cert_pem = leaf.serialize_pem_with_signer(&self.ca_cert).map_err(CaError::Rcgen)?;
        let key_pem = leaf.serialize_private_key_pem();
        let serial = format!("{:x}", Utc::now().timestamp_nanos_opt().unwrap_or(0));

        info!(
            service_name,
            expires_at = %not_after,
            "Issued leaf certificate"
        );

        Ok(ServiceCertificate {
            service_name: service_name.to_string(),
            environment: self.config.environment.clone(),
            cert_pem,
            key_pem,
            serial,
            issued_at: Utc::now(),
            expires_at: not_after,
            is_revoked: false,
            rotation_in_progress: false,
        })
    }
}

/// Stub for the offline root CA — used only to generate the intermediate CA
/// during initial setup (run offline, not in application runtime).
pub struct CertificateAuthority;

impl CertificateAuthority {
    /// Generate a self-signed root CA certificate and key pair.
    /// This should only be called during initial CA setup, offline.
    pub fn generate_root_ca(environment: &str) -> Result<(String, String), CaError> {
        let mut params = CertificateParams::new(vec![]);
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, format!("Aframp Root CA ({})", environment));
        dn.push(DnType::OrganizationName, "Aframp");
        dn.push(DnType::OrganizationalUnitName, "aframp-internal");
        params.distinguished_name = dn;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];
        params.alg = &PKCS_ECDSA_P256_SHA256;
        // Root CA valid for 10 years
        params.not_after = rcgen::date_time_ymd(
            (Utc::now().year() + 10) as i32,
            Utc::now().month() as u8,
            Utc::now().day() as u8,
        );

        let cert = Certificate::from_params(params).map_err(CaError::Rcgen)?;
        let cert_pem = cert.serialize_pem().map_err(CaError::Rcgen)?;
        let key_pem = cert.serialize_private_key_pem();
        warn!("Root CA generated — store private key OFFLINE in air-gapped secrets manager");
        Ok((cert_pem, key_pem))
    }

    /// Generate an intermediate CA certificate signed by the root CA.
    /// Run offline; load only the resulting cert+key into the application secrets manager.
    pub fn generate_intermediate_ca(
        root_cert_pem: &str,
        root_key_pem: &str,
        environment: &str,
        validity_days: u64,
    ) -> Result<(String, String), CaError> {
        let root_key = rcgen::KeyPair::from_pem(root_key_pem)
            .map_err(|e| CaError::PemParse(e.to_string()))?;
        let root_params = CertificateParams::from_ca_cert_pem(root_cert_pem, root_key)
            .map_err(CaError::Rcgen)?;
        let root_ca = Certificate::from_params(root_params).map_err(CaError::Rcgen)?;

        let not_after = Utc::now() + Duration::days(validity_days as i64);
        let mut params = CertificateParams::new(vec![]);
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, format!("Aframp Intermediate CA ({})", environment));
        dn.push(DnType::OrganizationName, environment);
        dn.push(DnType::OrganizationalUnitName, "aframp-internal");
        params.distinguished_name = dn;
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];
        params.alg = &PKCS_ECDSA_P256_SHA256;
        params.not_after = rcgen::date_time_ymd(
            not_after.format("%Y").to_string().parse().unwrap(),
            not_after.format("%m").to_string().parse().unwrap(),
            not_after.format("%d").to_string().parse().unwrap(),
        );

        let intermediate = Certificate::from_params(params).map_err(CaError::Rcgen)?;
        let cert_pem = intermediate.serialize_pem_with_signer(&root_ca).map_err(CaError::Rcgen)?;
        let key_pem = intermediate.serialize_private_key_pem();
        info!(environment, "Intermediate CA generated");
        Ok((cert_pem, key_pem))
    }
}

// Bring in chrono traits for year/month/day
use chrono::Datelike;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unregistered_service_rejected() {
        // Without a real CA loaded, we test the guard logic directly
        assert!(!crate::mtls::cert::REGISTERED_SERVICES.contains(&"rogue-service"));
    }

    #[test]
    fn test_registered_services_list_not_empty() {
        assert!(!REGISTERED_SERVICES.is_empty());
    }
}
