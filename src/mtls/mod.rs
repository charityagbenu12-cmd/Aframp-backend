//! mTLS (Mutual TLS) module — Issue #204
//!
//! Provides:
//! - Internal CA hierarchy (root CA + intermediate CA + leaf service certs)
//! - Certificate issuance, provisioning, rotation, and revocation
//! - mTLS enforcement middleware for Axum
//! - Certificate lifecycle management worker
//! - Prometheus metrics for certificate lifecycle and handshake events
//! - Admin API endpoints for certificate inventory and management

pub mod ca;
pub mod cert;
pub mod config;
pub mod infra_tls;
pub mod metrics;
pub mod middleware;
pub mod provisioner;
pub mod revocation;
pub mod worker;
pub mod admin;

pub use ca::{CertificateAuthority, IntermediateCa};
pub use cert::{ServiceCertificate, ServiceIdentity, CertificateStore};
pub use config::MtlsConfig;
pub use infra_tls::{service_tls_identity, postgres_mtls_params, InfraMtlsParams};
pub use provisioner::CertificateProvisioner;
pub use revocation::RevocationService;
pub use worker::CertLifecycleWorker;
