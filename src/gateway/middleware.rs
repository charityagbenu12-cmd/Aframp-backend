//! Axum middleware layer that enforces all gateway security policies.

use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{Request, Response, StatusCode},
    middleware::Next,
    response::IntoResponse,
};
use serde_json::json;
use std::net::SocketAddr;

use crate::gateway::{
    config::hsts_max_age,
    cors::{evaluate_cors, inject_cors_headers},
    metrics::{record_rejection, record_request},
    prescreening::{prescreen, RejectionReason},
    rate_limit::{api_key_prefix, GatewayRateLimiter},
    transform::{
        inject_gateway_headers, inject_security_response_headers, normalise_path,
        strip_internal_response_headers, strip_spoofable_headers,
    },
};

/// Axum middleware state carrying the rate limiter.
#[derive(Clone)]
pub struct GatewayState {
    pub rate_limiter: GatewayRateLimiter,
}

impl GatewayState {
    pub fn new() -> Self {
        Self {
            rate_limiter: GatewayRateLimiter::new(
                crate::gateway::config::GATEWAY_RATE_LIMIT_PER_IP,
                crate::gateway::config::GATEWAY_RATE_LIMIT_PER_KEY_PREFIX,
            ),
        }
    }
}

/// Full gateway enforcement middleware.
pub async fn gateway_middleware(
    axum::extract::State(state): axum::extract::State<std::sync::Arc<GatewayState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    mut req: Request<Body>,
    next: Next,
) -> Response<Body> {
    let method = req.method().to_string();
    let raw_path = req.uri().path().to_string();

    // 1. Normalise path
    let normalised = normalise_path(&raw_path);
    if normalised != raw_path {
        // Rebuild URI with normalised path
        if let Ok(new_uri) = format!(
            "{}{}",
            normalised,
            req.uri()
                .query()
                .map(|q| format!("?{}", q))
                .unwrap_or_default()
        )
        .parse::<axum::http::Uri>()
        {
            *req.uri_mut() = new_uri;
        }
    }

    let path = req.uri().path().to_string();
    record_request(&method, &path);

    // 2. CORS evaluation (handles preflight, rejects bad origins)
    if let Some(cors_resp) = evaluate_cors(&req) {
        return cors_resp;
    }

    // 3. Pre-screening
    if let Err(reason) = prescreen(&req) {
        record_rejection(reason.as_str());
        tracing::warn!(
            reason = reason.as_str(),
            path = %path,
            ip = %addr.ip(),
            "Gateway rejected request"
        );
        return rejection_response(reason);
    }

    // 4. Gateway-level rate limiting
    let ip = req
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| addr.ip().to_string());

    if state.rate_limiter.check_ip(&ip).is_err() {
        record_rejection("gateway_rate_limit_ip");
        tracing::warn!(ip = %ip, "Gateway IP rate limit exceeded");
        return rate_limit_response();
    }

    if let Some(key) = req
        .headers()
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
    {
        let prefix = api_key_prefix(key).to_string();
        if state.rate_limiter.check_key_prefix(&prefix).is_err() {
            record_rejection("gateway_rate_limit_key");
            tracing::warn!(key_prefix = %prefix, "Gateway API key rate limit exceeded");
            return rate_limit_response();
        }
    }

    // 5. Strip consumer-spoofable headers before forwarding
    strip_spoofable_headers(req.headers_mut());

    // 6. Inject gateway-signed headers
    inject_gateway_headers(req.headers_mut(), &method, &path);

    // 7. Forward to upstream
    let origin = req
        .headers()
        .get("origin")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let mut resp = next.run(req).await;

    // 8. Inject security response headers
    inject_security_response_headers(resp.headers_mut(), hsts_max_age());

    // 9. Inject CORS headers on response
    if !origin.is_empty() {
        inject_cors_headers(&mut resp, &origin, &path);
    }

    // 10. Strip internal infrastructure headers
    strip_internal_response_headers(resp.headers_mut());

    resp
}

fn rejection_response(reason: RejectionReason) -> Response<Body> {
    let (status, code, message) = match reason {
        RejectionReason::MissingAuthHeader => (
            StatusCode::UNAUTHORIZED,
            "missing_auth_header",
            "Authentication required",
        ),
        RejectionReason::UnsupportedContentType => (
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported_content_type",
            "Content-Type must be application/json",
        ),
        RejectionReason::BodyTooLarge => (
            StatusCode::PAYLOAD_TOO_LARGE,
            "body_too_large",
            "Request body exceeds maximum allowed size",
        ),
        RejectionReason::MalformedUrl | RejectionReason::PathTraversal | RejectionReason::NullByteInPath => (
            StatusCode::BAD_REQUEST,
            "invalid_url",
            "Request URL is invalid",
        ),
        RejectionReason::UrlTooLong => (
            StatusCode::URI_TOO_LONG,
            "url_too_long",
            "Request URL exceeds maximum length",
        ),
        RejectionReason::MethodNotAllowed => (
            StatusCode::METHOD_NOT_ALLOWED,
            "method_not_allowed",
            "HTTP method not allowed for this endpoint",
        ),
    };

    let body = json!({"error": {"code": code, "message": message}}).to_string();
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap()
}

fn rate_limit_response() -> Response<Body> {
    let body = json!({"error": {"code": "gateway_rate_limit_exceeded", "message": "Too many requests"}}).to_string();
    Response::builder()
        .status(StatusCode::TOO_MANY_REQUESTS)
        .header("content-type", "application/json")
        .header("retry-after", "60")
        .body(Body::from(body))
        .unwrap()
}
