//! Microservice-to-microservice authentication system
//!
//! Implements:
//! - Service identity registration and management
//! - OAuth 2.0 Client Credentials flow for service tokens
//! - Token manager with proactive rotation
//! - Service token injection middleware
//! - Service token verification with allowlist enforcement
//! - mTLS support for highest sensitivity endpoints
//! - Service call allowlist management
//! - Comprehensive observability

pub mod allowlist;
pub mod certificate;
pub mod client;
pub mod middleware;
pub mod registration;
pub mod router;
pub mod token_manager;
pub mod types;

#[cfg(test)]
mod tests;

pub use allowlist::{AllowlistEntry, ServiceAllowlist, ServiceAllowlistRepository};
pub use certificate::{CertificateManager, ServiceCertificate};
pub use client::ServiceHttpClient;
pub use middleware::{service_token_verification, ServiceAuthState};
pub use registration::{ServiceIdentity, ServiceRegistration, ServiceRegistry};
pub use router::service_admin_router;
pub use token_manager::{ServiceTokenManager, TokenRefreshConfig};
pub use types::{
    AuthResult, AuthenticatedService, ServiceAuthAudit, ServiceAuthError, ServiceAuthResult,
    ServiceIdentityInfo, ServiceStatus, ServiceTokenClaims,
};
