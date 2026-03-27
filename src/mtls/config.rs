//! mTLS configuration

use std::time::Duration;

/// Top-level mTLS configuration loaded from environment variables.
#[derive(Debug, Clone)]
pub struct MtlsConfig {
    /// Service name used in certificate subject CN.
    pub service_name: String,
    /// Environment (e.g. "production", "staging", "development").
    pub environment: String,
    /// Leaf certificate validity period (default: 90 days).
    pub leaf_cert_validity: Duration,
    /// Intermediate CA validity period (default: 2 years).
    pub intermediate_cert_validity: Duration,
    /// How many days before expiry to trigger rotation (default: 14).
    pub rotation_threshold_days: i64,
    /// How many days before expiry to fire an alert (default: 7).
    pub alert_threshold_days: i64,
    /// PEM-encoded intermediate CA certificate (loaded from secrets manager / env).
    pub intermediate_ca_cert_pem: String,
    /// PEM-encoded intermediate CA private key (loaded from secrets manager / env).
    pub intermediate_ca_key_pem: String,
    /// PEM-encoded root CA certificate for trust anchor distribution.
    pub root_ca_cert_pem: String,
    /// Internal endpoint base URL for CA distribution.
    pub ca_distribution_url: String,
    /// Whether mTLS enforcement is enabled (can be disabled in development).
    pub enforce_mtls: bool,
}

impl MtlsConfig {
    pub fn from_env() -> Result<Self, String> {
        let service_name = std::env::var("SERVICE_NAME")
            .unwrap_or_else(|_| "aframp-backend".to_string());
        let environment = std::env::var("APP_ENV")
            .unwrap_or_else(|_| "development".to_string());
        let leaf_days: u64 = std::env::var("MTLS_LEAF_CERT_VALIDITY_DAYS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(90);
        let intermediate_days: u64 = std::env::var("MTLS_INTERMEDIATE_CERT_VALIDITY_DAYS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(730); // 2 years
        let rotation_threshold_days: i64 = std::env::var("MTLS_ROTATION_THRESHOLD_DAYS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(14);
        let alert_threshold_days: i64 = std::env::var("MTLS_ALERT_THRESHOLD_DAYS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(7);
        let intermediate_ca_cert_pem = std::env::var("MTLS_INTERMEDIATE_CA_CERT_PEM")
            .unwrap_or_default();
        let intermediate_ca_key_pem = std::env::var("MTLS_INTERMEDIATE_CA_KEY_PEM")
            .unwrap_or_default();
        let root_ca_cert_pem = std::env::var("MTLS_ROOT_CA_CERT_PEM")
            .unwrap_or_default();
        let ca_distribution_url = std::env::var("MTLS_CA_DISTRIBUTION_URL")
            .unwrap_or_else(|_| "http://internal-ca.aframp.internal".to_string());
        let enforce_mtls = std::env::var("MTLS_ENFORCE")
            .map(|v| v.to_lowercase() == "true")
            .unwrap_or(false);

        Ok(Self {
            service_name,
            environment,
            leaf_cert_validity: Duration::from_secs(leaf_days * 86400),
            intermediate_cert_validity: Duration::from_secs(intermediate_days * 86400),
            rotation_threshold_days,
            alert_threshold_days,
            intermediate_ca_cert_pem,
            intermediate_ca_key_pem,
            root_ca_cert_pem,
            ca_distribution_url,
            enforce_mtls,
        })
    }
}
