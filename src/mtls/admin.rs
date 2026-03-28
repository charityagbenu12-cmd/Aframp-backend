//! Admin API handlers for certificate inventory and management.
//!
//! GET  /api/admin/security/certificates              — list all service certificates
//! POST /api/admin/security/certificates/:svc/rotate  — rotate a specific service certificate
//! POST /api/admin/security/certificates/:svc/revoke  — revoke a specific service certificate

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::info;

use crate::mtls::cert::{CertificateSummary, CertificateStore};
use crate::mtls::provisioner::CertificateProvisioner;
use crate::mtls::revocation::RevocationService;

/// Shared state for mTLS admin handlers.
#[derive(Clone)]
pub struct MtlsAdminState {
    pub store: Arc<CertificateStore>,
    pub provisioner: Arc<CertificateProvisioner>,
    pub revocation: Arc<RevocationService>,
}

/// Response for the certificate inventory endpoint.
#[derive(Debug, Serialize, Deserialize)]
pub struct CertificateInventoryResponse {
    pub certificates: Vec<CertificateSummary>,
    pub total: usize,
}

/// GET /api/admin/security/certificates
/// Lists all platform service certificates with expiry and rotation status.
/// Super admin access only (enforced by the admin auth middleware upstream).
pub async fn list_certificates_handler(
    State(state): State<Arc<MtlsAdminState>>,
) -> impl IntoResponse {
    let certs = state.store.list_all();
    let summaries: Vec<CertificateSummary> = certs.iter().map(CertificateSummary::from).collect();
    let total = summaries.len();
    info!(total, "Admin: certificate inventory requested");
    Json(CertificateInventoryResponse { certificates: summaries, total })
}

/// POST /api/admin/security/certificates/:service_name/rotate
/// Admin-initiated immediate certificate rotation for a specific service.
pub async fn rotate_certificate_handler(
    State(state): State<Arc<MtlsAdminState>>,
    Path(service_name): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    info!(service_name, "Admin: certificate rotation requested");
    state
        .provisioner
        .rotate(&service_name)
        .map(|cert| {
            Json(serde_json::json!({
                "service_name": cert.service_name,
                "serial": cert.serial,
                "expires_at": cert.expires_at,
                "message": "Certificate rotated successfully"
            }))
        })
        .map_err(|e| {
            tracing::error!(service_name, error = %e, "Admin rotation failed");
            StatusCode::INTERNAL_SERVER_ERROR
        })
}

/// POST /api/admin/security/certificates/:service_name/revoke
/// Immediately revoke a service certificate and issue a replacement.
pub async fn revoke_certificate_handler(
    State(state): State<Arc<MtlsAdminState>>,
    Path(service_name): Path<String>,
    Json(body): Json<RevokeRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    info!(service_name, reason = %body.reason, "Admin: certificate revocation requested");
    state
        .provisioner
        .revoke_and_replace(&service_name, &body.reason)
        .map(|cert| {
            Json(serde_json::json!({
                "service_name": cert.service_name,
                "new_serial": cert.serial,
                "message": "Certificate revoked and replacement issued"
            }))
        })
        .map_err(|e| {
            tracing::error!(service_name, error = %e, "Admin revocation failed");
            StatusCode::INTERNAL_SERVER_ERROR
        })
}

#[derive(Debug, Deserialize)]
pub struct RevokeRequest {
    pub reason: String,
}

/// Build the admin router for mTLS certificate management.
pub fn mtls_admin_routes() -> axum::Router<Arc<MtlsAdminState>> {
    use axum::routing::{get, post};
    axum::Router::new()
        .route("/certificates", get(list_certificates_handler))
        .route("/certificates/:service_name/rotate", post(rotate_certificate_handler))
        .route("/certificates/:service_name/revoke", post(revoke_certificate_handler))
}
