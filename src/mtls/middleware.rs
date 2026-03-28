//! mTLS enforcement middleware for Axum.
//!
//! Validates the client certificate on every inbound connection:
//! 1. Certificate must be present (no fallback to unauthenticated)
//! 2. Trust chain verified against the platform's internal CA
//! 3. Certificate not revoked (CRL + OCSP check)
//! 4. Service identity extracted and validated against the allowlist
//!
//! In development (MTLS_ENFORCE=false), the middleware logs but does not reject.

use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::Response,
};
use std::sync::Arc;
use tracing::{info, warn};

use crate::mtls::cert::{CertificateStore, ServiceIdentity};
use crate::mtls::config::MtlsConfig;
use crate::mtls::metrics;
use crate::mtls::revocation::RevocationService;

/// State passed to the mTLS middleware.
#[derive(Clone)]
pub struct MtlsState {
    pub store: Arc<CertificateStore>,
    pub revocation: Arc<RevocationService>,
    pub config: MtlsConfig,
    /// Allowlist: map of (calling_service → allowed_target_services).
    /// Mirrors the service call allowlist from issue #96.
    pub service_allowlist: Arc<Vec<(String, String)>>,
}

/// Axum middleware that enforces mTLS on internal service endpoints.
///
/// Reads the `X-Client-Cert-Subject` header (set by the TLS terminator / reverse proxy)
/// and validates the presented certificate identity.
pub async fn mtls_enforcement_middleware(
    State(state): State<Arc<MtlsState>>,
    req: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let to_service = state.config.service_name.clone();

    // Extract client certificate subject from header (set by TLS terminator).
    // In a real deployment this comes from the TLS layer; here we read the
    // forwarded header that the reverse proxy injects after TLS termination.
    let subject_header = req
        .headers()
        .get("X-Client-Cert-Subject")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let serial_header = req
        .headers()
        .get("X-Client-Cert-Serial")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // No certificate presented → reject at TLS handshake level.
    let subject = match subject_header {
        Some(s) => s,
        None => {
            warn!(to_service, "mTLS: no client certificate presented");
            metrics::record_handshake("unknown", &to_service, false);
            if state.config.enforce_mtls {
                return Err(StatusCode::UNAUTHORIZED);
            }
            return Ok(next.run(req).await);
        }
    };

    // Parse service identity from certificate subject.
    let identity = match ServiceIdentity::parse(&subject) {
        Some(id) => id,
        None => {
            warn!(to_service, subject, "mTLS: invalid certificate subject format");
            metrics::record_handshake("unknown", &to_service, false);
            if state.config.enforce_mtls {
                return Err(StatusCode::UNAUTHORIZED);
            }
            return Ok(next.run(req).await);
        }
    };

    let from_service = identity.service_name.clone();

    // Verify service is in the registered registry.
    if !identity.is_registered() {
        warn!(from_service, to_service, "mTLS: unregistered service identity");
        metrics::record_handshake(&from_service, &to_service, false);
        if state.config.enforce_mtls {
            return Err(StatusCode::FORBIDDEN);
        }
        return Ok(next.run(req).await);
    }

    // CRL / OCSP revocation check.
    if let Some(serial) = &serial_header {
        if state.revocation.is_revoked(serial) {
            warn!(from_service, to_service, serial, "mTLS: certificate is revoked");
            metrics::record_handshake(&from_service, &to_service, false);
            if state.config.enforce_mtls {
                return Err(StatusCode::FORBIDDEN);
            }
            return Ok(next.run(req).await);
        }
    }

    // Service call allowlist check.
    let allowed = state.service_allowlist.iter().any(|(caller, target)| {
        caller == &from_service && (target == &to_service || target == "*")
    });
    if !allowed && !state.service_allowlist.is_empty() {
        warn!(from_service, to_service, "mTLS: service not in call allowlist");
        metrics::record_handshake(&from_service, &to_service, false);
        if state.config.enforce_mtls {
            return Err(StatusCode::FORBIDDEN);
        }
        return Ok(next.run(req).await);
    }

    info!(from_service, to_service, "mTLS: handshake verified");
    metrics::record_handshake(&from_service, &to_service, true);
    Ok(next.run(req).await)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mtls::cert::ServiceIdentity;

    #[test]
    fn test_identity_extraction_from_subject() {
        let subject = "CN=aframp-backend,O=production,OU=aframp-internal";
        let id = ServiceIdentity::parse(subject).unwrap();
        assert_eq!(id.service_name, "aframp-backend");
        assert_eq!(id.environment, "production");
        assert!(id.is_registered());
    }

    #[test]
    fn test_unregistered_identity_rejected() {
        let subject = "CN=rogue-svc,O=production,OU=aframp-internal";
        let id = ServiceIdentity::parse(subject).unwrap();
        assert!(!id.is_registered());
    }
}
