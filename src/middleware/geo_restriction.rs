//! Geo-Restriction Middleware
//!
//! Axum middleware for enforcing geographic access controls based on IP geolocation.

use crate::error::AppError;
use crate::services::geo_restriction::{GeoRestrictionService, PolicyContext, PolicyResult};
use axum::{
    extract::{Request, State},
    http::{header, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use serde_json::json;
use std::sync::Arc;
use tracing::{error, info, warn};
use uuid::Uuid;

/// Middleware configuration
#[derive(Debug, Clone)]
pub struct GeoRestrictionMiddlewareConfig {
    pub enabled: bool,
    pub exclude_paths: Vec<String>,
    pub require_consumer_auth: bool,
}

impl Default for GeoRestrictionMiddlewareConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            exclude_paths: vec![
                "/health".to_string(),
                "/metrics".to_string(),
                "/api/admin/geo".to_string(), // Allow admin access to geo endpoints
            ],
            require_consumer_auth: true,
        }
    }
}

impl GeoRestrictionMiddlewareConfig {
    pub fn from_env() -> Self {
        let exclude_paths = std::env::var("GEO_RESTRICTION_EXCLUDE_PATHS")
            .unwrap_or_else(|_| "/health,/metrics,/api/admin/geo".to_string())
            .split(',')
            .map(|s| s.trim().to_string())
            .collect();

        Self {
            enabled: std::env::var("GEO_RESTRICTION_MIDDLEWARE_ENABLED")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(true),
            exclude_paths,
            require_consumer_auth: std::env::var("GEO_RESTRICTION_REQUIRE_CONSUMER_AUTH")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(true),
        }
    }
}

/// Geo-restriction middleware state
#[derive(Clone)]
pub struct GeoRestrictionState {
    pub service: Arc<GeoRestrictionService>,
    pub config: GeoRestrictionMiddlewareConfig,
}

/// Extract consumer ID from request headers
fn extract_consumer_id(req: &Request) -> Option<Uuid> {
    req.headers()
        .get("x-consumer-id")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| Uuid::parse_str(s).ok())
}

/// Extract transaction type from request
fn extract_transaction_type(req: &Request) -> Option<String> {
    req.headers()
        .get("x-transaction-type")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string())
}

/// Extract enhanced verification flag
fn extract_enhanced_verification(req: &Request) -> bool {
    req.headers()
        .get("x-enhanced-verification")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.parse().ok())
        .unwrap_or(false)
}

/// Extract client IP address
fn extract_client_ip(req: &Request) -> String {
    // Check X-Forwarded-For header first (for proxies/load balancers)
    if let Some(forwarded_for) = req.headers().get("x-forwarded-for") {
        if let Ok(forwarded_str) = forwarded_for.to_str() {
            // Take the first IP in case of multiple
            if let Some(first_ip) = forwarded_str.split(',').next() {
                return first_ip.trim().to_string();
            }
        }
    }

    // Check X-Real-IP header
    if let Some(real_ip) = req.headers().get("x-real-ip") {
        if let Ok(ip_str) = real_ip.to_str() {
            return ip_str.to_string();
        }
    }

    // Fallback to connection info (this might not work in all Axum versions)
    // For now, default to a placeholder - in production this should be properly configured
    "127.0.0.1".to_string()
}

/// Check if path should be excluded from geo-restriction
fn is_excluded_path(path: &str, exclude_paths: &[String]) -> bool {
    exclude_paths.iter().any(|excluded| path.starts_with(excluded))
}

/// Geo-restriction middleware function
pub async fn geo_restriction_middleware(
    State(state): State<GeoRestrictionState>,
    req: Request,
    next: Next,
) -> Response {
    // Skip if middleware is disabled
    if !state.config.enabled {
        return next.run(req).await;
    }

    let path = req.uri().path();

    // Skip excluded paths
    if is_excluded_path(path, &state.config.exclude_paths) {
        return next.run(req).await;
    }

    // Extract request context
    let consumer_id = extract_consumer_id(&req);
    let ip_address = extract_client_ip(&req);
    let transaction_type = extract_transaction_type(&req);
    let enhanced_verification = extract_enhanced_verification(&req);

    // If consumer auth is required but no consumer ID, block
    if state.config.require_consumer_auth && consumer_id.is_none() {
        warn!(ip = %ip_address, path = %path, "Request without consumer ID in geo-restricted endpoint");
        return (
            StatusCode::UNAUTHORIZED,
            [(header::CONTENT_TYPE, "application/json")],
            json!({
                "error": "Authentication required",
                "message": "Consumer authentication is required for this endpoint"
            }).to_string(),
        ).into_response();
    }

    // Build policy context
    let context = PolicyContext {
        consumer_id,
        ip_address: ip_address.clone(),
        transaction_type,
        enhanced_verification,
    };

    // Evaluate geo-restriction policy
    match state.service.evaluate_policy(&context).await {
        Ok(PolicyResult::Allowed) => {
            info!(
                consumer_id = ?consumer_id,
                ip = %ip_address,
                path = %path,
                "Geo-restriction policy: ALLOWED"
            );
            next.run(req).await
        }
        Ok(PolicyResult::Restricted) => {
            warn!(
                consumer_id = ?consumer_id,
                ip = %ip_address,
                path = %path,
                "Geo-restriction policy: RESTRICTED"
            );
            (
                StatusCode::FORBIDDEN,
                [(header::CONTENT_TYPE, "application/json")],
                json!({
                    "error": "Access restricted",
                    "message": "Access from your location is restricted for this service"
                }).to_string(),
            ).into_response()
        }
        Ok(PolicyResult::Blocked) => {
            error!(
                consumer_id = ?consumer_id,
                ip = %ip_address,
                path = %path,
                "Geo-restriction policy: BLOCKED"
            );
            (
                StatusCode::FORBIDDEN,
                [(header::CONTENT_TYPE, "application/json")],
                json!({
                    "error": "Access blocked",
                    "message": "Access from your location is blocked for this service"
                }).to_string(),
            ).into_response()
        }
        Ok(PolicyResult::RequiresVerification) => {
            info!(
                consumer_id = ?consumer_id,
                ip = %ip_address,
                path = %path,
                "Geo-restriction policy: REQUIRES_VERIFICATION"
            );
            (
                StatusCode::UNAUTHORIZED,
                [(header::CONTENT_TYPE, "application/json")],
                json!({
                    "error": "Enhanced verification required",
                    "message": "Additional verification is required for access from your location",
                    "requires_verification": true
                }).to_string(),
            ).into_response()
        }
        Err(e) => {
            error!(
                consumer_id = ?consumer_id,
                ip = %ip_address,
                path = %path,
                error = %e,
                "Geo-restriction policy evaluation failed"
            );
            // On error, allow request to proceed to avoid blocking legitimate users
            // In production, you might want to have a more sophisticated fallback
            warn!("Allowing request due to policy evaluation error");
            next.run(req).await
        }
    }
}