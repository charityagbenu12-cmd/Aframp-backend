/// Audit logging middleware.
///
/// Applied to all authenticated endpoints. Captures actor identity, request
/// context, response status, and latency. Writes asynchronously via AuditWriter.
/// Never logs raw request bodies — only SHA-256 hashes.
use crate::audit::{
    models::{AuditActorType, AuditEventCategory, AuditOutcome, PendingAuditEntry},
    redaction::sha256_hex,
    writer::AuditWriter,
};
use axum::{
    body::{to_bytes, Body},
    extract::{MatchedPath, Request},
    middleware::Next,
    response::Response,
};
use std::sync::Arc;
use std::time::Instant;
use tracing::warn;

/// Determine event type and category from method + path.
fn classify_event(method: &str, path: &str) -> (String, AuditEventCategory) {
    let p = path.to_lowercase();

    if p.contains("/auth/") || p.contains("/login") || p.contains("/mfa") {
        let event = format!("auth.{}", method.to_lowercase());
        return (event, AuditEventCategory::Authentication);
    }
    if p.contains("/api-keys") || p.contains("/keys") || p.contains("/credentials") {
        let event = format!("credential.{}", method.to_lowercase());
        return (event, AuditEventCategory::Credential);
    }
    if p.contains("/onramp") || p.contains("/offramp") || p.contains("/transactions")
        || p.contains("/payments") || p.contains("/transfer")
    {
        let event = format!("financial.{}", method.to_lowercase());
        return (event, AuditEventCategory::FinancialTransaction);
    }
    if p.contains("/admin/") {
        let event = format!("admin.{}", method.to_lowercase());
        return (event, AuditEventCategory::Admin);
    }
    if p.contains("/config") || p.contains("/settings") || p.contains("/system") {
        let event = format!("config.{}", method.to_lowercase());
        return (event, AuditEventCategory::Configuration);
    }
    if p.contains("/security") || p.contains("/ip-") || p.contains("/geo-") || p.contains("/ddos") {
        let event = format!("security.{}", method.to_lowercase());
        return (event, AuditEventCategory::Security);
    }

    let event = format!("data_access.{}", method.to_lowercase());
    (event, AuditEventCategory::DataAccess)
}

fn outcome_from_status(status: u16) -> AuditOutcome {
    if status < 400 {
        AuditOutcome::Success
    } else {
        AuditOutcome::Failure
    }
}

fn failure_reason(status: u16) -> Option<String> {
    match status {
        400 => Some("bad_request".to_string()),
        401 => Some("unauthorized".to_string()),
        403 => Some("forbidden".to_string()),
        404 => Some("not_found".to_string()),
        409 => Some("conflict".to_string()),
        422 => Some("unprocessable_entity".to_string()),
        429 => Some("rate_limited".to_string()),
        500..=599 => Some("server_error".to_string()),
        _ => None,
    }
}

/// Extract actor context from request extensions (set by auth middleware).
fn extract_actor(req: &Request) -> (AuditActorType, Option<String>, Option<String>, Option<String>) {
    // Try OAuth token claims first
    if let Some(claims) = req.extensions().get::<crate::auth::OAuthTokenClaims>() {
        let actor_type = match claims.consumer_type.as_str() {
            "admin" => AuditActorType::Admin,
            "microservice" => AuditActorType::Microservice,
            _ => AuditActorType::Consumer,
        };
        return (
            actor_type,
            Some(claims.sub.clone()),
            Some(claims.consumer_type.clone()),
            Some(claims.jti.clone()),
        );
    }

    // Try JWT token claims
    if let Some(claims) = req.extensions().get::<crate::auth::jwt::TokenClaims>() {
        return (
            AuditActorType::Consumer,
            Some(claims.sub.clone()),
            None,
            claims.jti.clone(),
        );
    }

    // Try API key
    if let Some(key) = req.extensions().get::<crate::middleware::api_key::AuthenticatedKey>() {
        let actor_type = match key.consumer_type.as_str() {
            "admin" => AuditActorType::Admin,
            "microservice" => AuditActorType::Microservice,
            _ => AuditActorType::Consumer,
        };
        return (
            actor_type,
            Some(key.consumer_id.to_string()),
            Some(key.consumer_type.clone()),
            None,
        );
    }

    // Try admin session context
    if let Some(ctx) = req.extensions().get::<crate::admin::middleware::AdminAuthContext>() {
        return (
            AuditActorType::Admin,
            Some(ctx.admin_id.to_string()),
            Some("admin".to_string()),
            Some(ctx.session_id.to_string()),
        );
    }

    (AuditActorType::System, None, None, None)
}

fn extract_ip(req: &Request) -> Option<String> {
    req.headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(|s| s.trim().to_string())
        .or_else(|| {
            req.headers()
                .get("x-real-ip")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
        })
}

fn environment_from_req(req: &Request) -> String {
    // Check OAuth claims for environment
    if let Some(claims) = req.extensions().get::<crate::auth::OAuthTokenClaims>() {
        return claims.environment.clone();
    }
    if let Some(key) = req.extensions().get::<crate::middleware::api_key::AuthenticatedKey>() {
        return key.environment.clone();
    }
    std::env::var("APP_ENV").unwrap_or_else(|_| "mainnet".to_string())
}

/// Paths that should be skipped (health checks, metrics, swagger).
fn should_skip(path: &str) -> bool {
    path.starts_with("/health")
        || path == "/metrics"
        || path.starts_with("/swagger")
        || path.starts_with("/api-docs")
}

pub async fn audit_middleware(
    writer: axum::extract::Extension<Arc<AuditWriter>>,
    req: Request,
    next: Next,
) -> Response {
    let path = req
        .extensions()
        .get::<MatchedPath>()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| req.uri().path().to_string());

    if should_skip(&path) {
        return next.run(req).await;
    }

    let method = req.method().to_string();
    let actor_ip = extract_ip(&req);
    let environment = environment_from_req(&req);
    let (actor_type, actor_id, actor_consumer_type, session_id) = extract_actor(&req);
    let (event_type, event_category) = classify_event(&method, &path);

    // Consume and hash the request body, then reconstruct the request.
    // We buffer the body to compute its hash — never store the raw bytes.
    let (parts, body) = req.into_parts();
    let body_bytes = match to_bytes(body, 10 * 1024 * 1024).await {
        Ok(b) => b,
        Err(_) => {
            warn!("Failed to buffer request body for audit hashing");
            axum::body::Bytes::new()
        }
    };

    let request_body_hash = if body_bytes.is_empty() {
        None
    } else {
        Some(sha256_hex(&body_bytes))
    };

    // Reconstruct request with the buffered body
    let req = Request::from_parts(parts, Body::from(body_bytes));

    let start = Instant::now();
    let response = next.run(req).await;
    let latency_ms = start.elapsed().as_millis() as i64;

    let status = response.status().as_u16();
    let outcome = outcome_from_status(status);
    let failure_reason = if outcome == AuditOutcome::Failure {
        failure_reason(status)
    } else {
        None
    };

    let pending = PendingAuditEntry {
        event_type,
        event_category,
        actor_type,
        actor_id,
        actor_ip,
        actor_consumer_type,
        session_id,
        target_resource_type: None, // handlers can enrich this via extensions if needed
        target_resource_id: None,
        request_method: method,
        request_path: path,
        request_body_hash,
        response_status: status as i32,
        response_latency_ms: latency_ms,
        outcome,
        failure_reason,
        environment,
    };

    // Fire-and-forget — does not block the response
    let w = writer.0.clone();
    tokio::spawn(async move {
        w.write(pending).await;
    });

    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_event() {
        let (et, cat) = classify_event("POST", "/api/auth/token");
        assert_eq!(cat, AuditEventCategory::Authentication);

        let (et, cat) = classify_event("POST", "/api/onramp/initiate");
        assert_eq!(cat, AuditEventCategory::FinancialTransaction);

        let (et, cat) = classify_event("GET", "/api/admin/accounts");
        assert_eq!(cat, AuditEventCategory::Admin);

        let (et, cat) = classify_event("GET", "/api/wallet/balance");
        assert_eq!(cat, AuditEventCategory::DataAccess);
    }

    #[test]
    fn test_outcome_from_status() {
        assert_eq!(outcome_from_status(200), AuditOutcome::Success);
        assert_eq!(outcome_from_status(201), AuditOutcome::Success);
        assert_eq!(outcome_from_status(401), AuditOutcome::Failure);
        assert_eq!(outcome_from_status(500), AuditOutcome::Failure);
    }

    #[test]
    fn test_should_skip() {
        assert!(should_skip("/health"));
        assert!(should_skip("/metrics"));
        assert!(!should_skip("/api/wallet/balance"));
    }
}
