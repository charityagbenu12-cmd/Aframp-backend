//! Role-Based Access Control (RBAC) middleware
//!
//! Extracts the caller's identity and role from the `X-User-Id` and
//! `X-User-Role` headers (populated by the upstream Identity Provider / API
//! gateway after JWT validation).
//!
//! # Headers expected
//! - `X-User-Id`   — unique user identifier (sub claim from JWT)
//! - `X-User-Role` — role granted to the user
//!
//! # Usage
//! ```no_run
//! use axum::{Router, routing::post};
//! use crate::middleware::rbac::{require_role, CallerIdentity, ROLE_MINT_OPERATOR};
//!
//! let app = Router::new()
//!     .route("/api/mint/requests", post(handler))
//!     .route_layer(axum::middleware::from_fn(require_role(ROLE_MINT_OPERATOR)));
//! ```

use axum::{
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;

// ============================================================================
// Role constants (single source of truth — mirrors mint_approval.rs)
// ============================================================================

pub const ROLE_MINT_OPERATOR: &str = "mint_operator";
pub const ROLE_COMPLIANCE_OFFICER: &str = "compliance_officer";
pub const ROLE_FINANCE_DIRECTOR: &str = "finance_director";

/// All roles that are allowed to interact with the mint approval workflow.
pub const MINT_WORKFLOW_ROLES: &[&str] = &[
    ROLE_MINT_OPERATOR,
    ROLE_COMPLIANCE_OFFICER,
    ROLE_FINANCE_DIRECTOR,
];

// ============================================================================
// Caller identity (injected into request extensions)
// ============================================================================

/// Authenticated caller extracted from IdP headers.
#[derive(Debug, Clone)]
pub struct CallerIdentity {
    pub user_id: String,
    pub role: String,
}

// ============================================================================
// Error response
// ============================================================================

#[derive(Debug, Serialize)]
struct RbacError {
    code: &'static str,
    message: String,
}

fn unauthorized(message: impl Into<String>) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(RbacError {
            code: "UNAUTHORIZED",
            message: message.into(),
        }),
    )
        .into_response()
}

fn forbidden(message: impl Into<String>) -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(RbacError {
            code: "FORBIDDEN",
            message: message.into(),
        }),
    )
        .into_response()
}

// ============================================================================
// Middleware: extract identity and inject into extensions
// ============================================================================

/// Middleware that extracts `X-User-Id` / `X-User-Role` headers and injects a
/// [`CallerIdentity`] into request extensions.
///
/// Returns 401 if the headers are missing or empty.
pub async fn extract_identity(mut request: Request, next: Next) -> Result<Response, Response> {
    let user_id = request
        .headers()
        .get("x-user-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| unauthorized("Missing X-User-Id header"))?;

    let role = request
        .headers()
        .get("x-user-role")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| unauthorized("Missing X-User-Role header"))?;

    request
        .extensions_mut()
        .insert(CallerIdentity { user_id, role });

    Ok(next.run(request).await)
}

// ============================================================================
// Middleware factory: require a specific role
// ============================================================================

/// Returns an async middleware function that enforces a single required role.
///
/// Assumes [`extract_identity`] has already run (i.e., `CallerIdentity` is in
/// request extensions). Returns 403 if the caller's role does not match.
pub fn require_role(
    required_role: &'static str,
) -> impl Fn(Request, Next) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Response, Response>> + Send>>
       + Clone
       + Send
       + 'static {
    move |request: Request, next: Next| {
        Box::pin(async move {
            let identity = request
                .extensions()
                .get::<CallerIdentity>()
                .cloned()
                .ok_or_else(|| unauthorized("Identity not resolved — ensure extract_identity runs first"))?;

            if identity.role != required_role {
                return Err(forbidden(format!(
                    "Role '{}' is not permitted. Required: '{}'",
                    identity.role, required_role
                )));
            }

            Ok(next.run(request).await)
        })
    }
}

/// Returns an async middleware function that enforces any of the given roles.
///
/// Use this for endpoints accessible by multiple roles (e.g., approve/reject
/// can be called by operator, compliance, or finance director).
pub fn require_any_mint_role(
) -> impl Fn(Request, Next) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Response, Response>> + Send>>
       + Clone
       + Send
       + 'static {
    move |request: Request, next: Next| {
        Box::pin(async move {
            let identity = request
                .extensions()
                .get::<CallerIdentity>()
                .cloned()
                .ok_or_else(|| unauthorized("Identity not resolved"))?;

            if !MINT_WORKFLOW_ROLES.contains(&identity.role.as_str()) {
                return Err(forbidden(format!(
                    "Role '{}' is not permitted for mint workflow operations",
                    identity.role
                )));
            }

            Ok(next.run(request).await)
        })
    }
}
