//! IP Blocking Middleware
//!
//! Enforces IP blocks and shadow blocking for suspicious IPs.

use crate::error::AppError;
use crate::services::ip_detection::IpDetectionService;
use axum::{
    extract::Request,
    http::{header, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::sync::Arc;
use tracing::{error, info, warn};

/// State for IP blocking middleware
#[derive(Clone)]
pub struct IpBlockingState {
    pub detection_service: Arc<IpDetectionService>,
}

/// IP blocking middleware
pub async fn ip_blocking_middleware(
    state: axum::extract::State<IpBlockingState>,
    mut request: Request,
    next: Next,
) -> Response {
    // Extract client IP
    let client_ip = extract_client_ip(&request);

    if let Some(ip) = client_ip {
        // Check if IP is blocked
        match state.detection_service.is_ip_blocked(&ip).await {
            Ok(true) => {
                // IP is blocked - check block type
                match state.detection_service.get_ip_reputation(&ip).await {
                    Ok(Some(reputation)) => {
                        if reputation.is_shadow_blocked() {
                            // Shadow block - allow request but mark for silent hold
                            request.extensions_mut().insert(ShadowBlocked {});
                            info!(
                                ip = %ip,
                                block_type = "shadow",
                                "Shadow blocked IP allowed through with hold marker"
                            );
                        } else {
                            // Hard block - return 403
                            info!(
                                ip = %ip,
                                block_type = ?reputation.block_status,
                                "Hard blocked IP rejected"
                            );
                            return (StatusCode::FORBIDDEN, "Access denied").into_response();
                        }
                    }
                    Ok(None) => {
                        // Should not happen if IP is in blocked set, but allow through
                        warn!(ip = %ip, "IP in blocked set but no reputation record found");
                    }
                    Err(e) => {
                        // Log error but allow request to proceed
                        error!(error = %e, ip = %ip, "Failed to check IP reputation for blocked IP");
                    }
                }
            }
            Ok(false) => {
                // IP not blocked, proceed normally
            }
            Err(e) => {
                // Log error but allow request to proceed
                error!(error = %e, ip = %ip, "Failed to check if IP is blocked");
            }
        }
    } else {
        warn!("Could not extract client IP from request");
    }

    next.run(request).await
}

/// Extract client IP from request headers
fn extract_client_ip(request: &Request) -> Option<String> {
    // Check X-Forwarded-For header (for reverse proxy)
    if let Some(forwarded_for) = request.headers().get("x-forwarded-for") {
        if let Ok(forwarded_str) = forwarded_for.to_str() {
            // Take the first IP in case of multiple
            if let Some(ip) = forwarded_str.split(',').next().map(|s| s.trim()) {
                return Some(ip.to_string());
            }
        }
    }

    // Check X-Real-IP header
    if let Some(real_ip) = request.headers().get("x-real-ip") {
        if let Ok(ip_str) = real_ip.to_str() {
            return Some(ip_str.to_string());
        }
    }

    // Fallback to connection info
    if let Some(peer_addr) = request.extensions().get::<axum::extract::ConnectInfo<std::net::SocketAddr>>() {
        return Some(peer_addr.0.ip().to_string());
    }

    None
}

/// Marker type for shadow blocked requests
#[derive(Clone, Debug)]
pub struct ShadowBlocked;

/// Extension trait to check if request is shadow blocked
pub trait RequestExt {
    fn is_shadow_blocked(&self) -> bool;
}

impl RequestExt for Request {
    fn is_shadow_blocked(&self) -> bool {
        self.extensions().get::<ShadowBlocked>().is_some()
    }
}