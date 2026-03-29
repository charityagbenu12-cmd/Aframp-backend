//! mTLS certificate management for service-to-service communication

use chrono::{DateTime, Duration, Utc};
use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum, MsbOption};
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::x509::extension::{BasicConstraints, KeyUsage, SubjectAlternativeName};
use openssl::x509::{X509Name, X509};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::sync::Arc;
use tracing::{error, info, warn};
use uuid::Uuid;

use super::types::{ServiceAuthError, ServiceAuthResult};

// ── Certificate validity ─────────────────────────────────────────────────────

const CERT_VALIDITY_DAYS: i64 = 365; // 1 year
const CERT_WARNING_THRESHOLD_DAYS: i64 = 30; // Alert when < 30 days remaining

// ── Service certificate ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceCertificate {
    pub id: Uuid,
    pub service_id: Uuid,
    pub certificate_pem: String,
    pub private_key_ref: String,
    pub serial_number: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revoked: bool,
}

// ── Certificate manager ──────────────────────────────────────────────────────

pub struct CertificateManager {
    pool: Arc<PgPool>,
    ca_cert: X509,
    ca_key: PKey<Private>,
}

impl CertificateManager {
    pub fn new(pool: Arc<PgPool>, ca_cert_pem: &str, ca_key_pem: &str) -> ServiceAuthResult<Self> {
        let ca_cert = X509::from_pem(ca_cert_pem.as_bytes())
            .map_err(|e| ServiceAuthError::CertificateError(format!("Invalid CA cert: {}", e)))?;

        let ca_key = PKey::private_key_from_pem(ca_key_pem.as_bytes())
            .map_err(|e| ServiceAuthError::CertificateError(format!("Invalid CA key: {}", e)))?;

        Ok(Self {
            pool,
            ca_cert,
            ca_key,
        })
    }

    /// Generate a new certificate for a service
    pub async fn generate_certificate(
        &self,
        service_id: Uuid,
        service_name: &str,
    ) -> ServiceAuthResult<ServiceCertificate> {
        // Generate RSA key pair
        let rsa = Rsa::generate(2048)
            .map_err(|e| ServiceAuthError::CertificateError(format!("Key generation failed: {}", e)))?;

        let key = PKey::from_rsa(rsa)
            .map_err(|e| ServiceAuthError::CertificateError(format!("Key conversion failed: {}", e)))?;

        // Generate serial number
        let mut serial = BigNum::new()
            .map_err(|e| ServiceAuthError::CertificateError(format!("Serial generation failed: {}", e)))?;
        serial
            .rand(159, MsbOption::MAYBE_ZERO, false)
            .map_err(|e| ServiceAuthError::CertificateError(format!("Serial generation failed: {}", e)))?;

        // Build certificate
        let mut cert_builder = X509::builder()
            .map_err(|e| ServiceAuthError::CertificateError(format!("Cert builder failed: {}", e)))?;

        cert_builder
            .set_version(2)
            .map_err(|e| ServiceAuthError::CertificateError(format!("Set version failed: {}", e)))?;

        let serial_asn1 = serial.to_asn1_integer()
            .map_err(|e| ServiceAuthError::CertificateError(format!("Serial conversion failed: {}", e)))?;
        cert_builder
            .set_serial_number(&serial_asn1)
            .map_err(|e| ServiceAuthError::CertificateError(format!("Set serial failed: {}", e)))?;

        // Set subject
        let mut subject_name = X509Name::builder()
            .map_err(|e| ServiceAuthError::CertificateError(format!("Name builder failed: {}", e)))?;
        subject_name
            .append_entry_by_text("CN", service_name)
            .map_err(|e| ServiceAuthError::CertificateError(format!("Set CN failed: {}", e)))?;
        subject_name
            .append_entry_by_text("O", "Aframp")
            .map_err(|e| ServiceAuthError::CertificateError(format!("Set O failed: {}", e)))?;
        let subject_name = subject_name.build();

        cert_builder
            .set_subject_name(&subject_name)
            .map_err(|e| ServiceAuthError::CertificateError(format!("Set subject failed: {}", e)))?;

        // Set issuer (CA)
        cert_builder
            .set_issuer_name(self.ca_cert.subject_name())
            .map_err(|e| ServiceAuthError::CertificateError(format!("Set issuer failed: {}", e)))?;

        // Set validity period
        let not_before = Asn1Time::days_from_now(0)
            .map_err(|e| ServiceAuthError::CertificateError(format!("Set not_before failed: {}", e)))?;
        let not_after = Asn1Time::days_from_now(CERT_VALIDITY_DAYS as u32)
            .map_err(|e| ServiceAuthError::CertificateError(format!("Set not_after failed: {}", e)))?;

        cert_builder
            .set_not_before(&not_before)
            .map_err(|e| ServiceAuthError::CertificateError(format!("Set not_before failed: {}", e)))?;
        cert_builder
            .set_not_after(&not_after)
            .map_err(|e| ServiceAuthError::CertificateError(format!("Set not_after failed: {}", e)))?;

        // Set public key
        cert_builder
            .set_pubkey(&key)
            .map_err(|e| ServiceAuthError::CertificateError(format!("Set pubkey failed: {}", e)))?;

        // Add extensions
        let basic_constraints = BasicConstraints::new().build()
            .map_err(|e| ServiceAuthError::CertificateError(format!("Basic constraints failed: {}", e)))?;
        cert_builder
            .append_extension(basic_constraints)
            .map_err(|e| ServiceAuthError::CertificateError(format!("Append extension failed: {}", e)))?;

        let key_usage = KeyUsage::new()
            .digital_signature()
            .key_encipherment()
            .build()
            .map_err(|e| ServiceAuthError::CertificateError(format!("Key usage failed: {}", e)))?;
        cert_builder
            .append_extension(key_usage)
            .map_err(|e| ServiceAuthError::CertificateError(format!("Append extension failed: {}", e)))?;

        let subject_alt_name = SubjectAlternativeName::new()
            .dns(service_name)
            .build(&cert_builder.x509v3_context(Some(&self.ca_cert), None))
            .map_err(|e| ServiceAuthError::CertificateError(format!("SAN failed: {}", e)))?;
        cert_builder
            .append_extension(subject_alt_name)
            .map_err(|e| ServiceAuthError::CertificateError(format!("Append extension failed: {}", e)))?;

        // Sign with CA key
        cert_builder
            .sign(&self.ca_key, MessageDigest::sha256())
            .map_err(|e| ServiceAuthError::CertificateError(format!("Signing failed: {}", e)))?;

        let cert = cert_builder.build();

        // Export to PEM
        let cert_pem = String::from_utf8(
            cert.to_pem()
                .map_err(|e| ServiceAuthError::CertificateError(format!("Cert PEM export failed: {}", e)))?,
        )
        .map_err(|e| ServiceAuthError::CertificateError(format!("UTF-8 conversion failed: {}", e)))?;

        let key_pem = String::from_utf8(
            key.private_key_to_pem_pkcs8()
                .map_err(|e| ServiceAuthError::CertificateError(format!("Key PEM export failed: {}", e)))?,
        )
        .map_err(|e| ServiceAuthError::CertificateError(format!("UTF-8 conversion failed: {}", e)))?;

        // Store private key in secrets manager (placeholder - implement actual secrets manager integration)
        let private_key_ref = format!("service_cert_key_{}", service_id);
        // TODO: Store key_pem in secrets manager

        let now = Utc::now();
        let expires_at = now + Duration::days(CERT_VALIDITY_DAYS);
        let serial_hex = hex::encode(serial.to_vec());

        // Store certificate in database
        let id = Uuid::new_v4();
        sqlx::query!(
            r#"
            INSERT INTO service_certificates (
                id, service_id, certificate_pem, private_key_ref,
                serial_number, issued_at, expires_at, revoked
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, FALSE)
            "#,
            id,
            service_id,
            &cert_pem,
            &private_key_ref,
            &serial_hex,
            now,
            expires_at,
        )
        .execute(&*self.pool)
        .await
        .map_err(|e| ServiceAuthError::DatabaseError(e.to_string()))?;

        info!(
            service_name = %service_name,
            serial = %serial_hex,
            expires_at = %expires_at,
            "Service certificate generated"
        );

        Ok(ServiceCertificate {
            id,
            service_id,
            certificate_pem: cert_pem,
            private_key_ref,
            serial_number: serial_hex,
            issued_at: now,
            expires_at,
            revoked: false,
        })
    }

    /// Get active certificate for a service
    pub async fn get_certificate(&self, service_id: Uuid) -> ServiceAuthResult<Option<ServiceCertificate>> {
        let row = sqlx::query!(
            r#"
            SELECT id, service_id, certificate_pem, private_key_ref,
                   serial_number, issued_at, expires_at, revoked
            FROM service_certificates
            WHERE service_id = $1 AND NOT revoked
            ORDER BY issued_at DESC
            LIMIT 1
            "#,
            service_id
        )
        .fetch_optional(&*self.pool)
        .await
        .map_err(|e| ServiceAuthError::DatabaseError(e.to_string()))?;

        Ok(row.map(|r| ServiceCertificate {
            id: r.id,
            service_id: r.service_id,
            certificate_pem: r.certificate_pem,
            private_key_ref: r.private_key_ref,
            serial_number: r.serial_number,
            issued_at: r.issued_at,
            expires_at: r.expires_at,
            revoked: r.revoked,
        }))
    }

    /// Check for certificates expiring soon
    pub async fn check_expiring_certificates(&self) -> ServiceAuthResult<Vec<ServiceCertificate>> {
        let threshold = Utc::now() + Duration::days(CERT_WARNING_THRESHOLD_DAYS);

        let rows = sqlx::query!(
            r#"
            SELECT id, service_id, certificate_pem, private_key_ref,
                   serial_number, issued_at, expires_at, revoked
            FROM service_certificates
            WHERE NOT revoked AND expires_at < $1
            ORDER BY expires_at
            "#,
            threshold
        )
        .fetch_all(&*self.pool)
        .await
        .map_err(|e| ServiceAuthError::DatabaseError(e.to_string()))?;

        Ok(rows
            .into_iter()
            .map(|r| ServiceCertificate {
                id: r.id,
                service_id: r.service_id,
                certificate_pem: r.certificate_pem,
                private_key_ref: r.private_key_ref,
                serial_number: r.serial_number,
                issued_at: r.issued_at,
                expires_at: r.expires_at,
                revoked: r.revoked,
            })
            .collect())
    }

    /// Revoke a certificate
    pub async fn revoke_certificate(&self, serial_number: &str) -> ServiceAuthResult<()> {
        sqlx::query!(
            "UPDATE service_certificates SET revoked = TRUE, revoked_at = $1 WHERE serial_number = $2",
            Utc::now(),
            serial_number
        )
        .execute(&*self.pool)
        .await
        .map_err(|e| ServiceAuthError::DatabaseError(e.to_string()))?;

        info!(serial = %serial_number, "Certificate revoked");

        Ok(())
    }
}
