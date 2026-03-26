//! Axum middleware that enforces DDoS protection on every request.
//!
//! Checks (in order):
//!   1. Emergency lockdown — reject unless allowlisted or high-priority
//!   2. Blocked IP check
//!   3. Connection limit per IP (tracked in Redis)
//!   4. Request fingerprint analysis
//!   5. Fair queue slot acquisition with WRED
//!   6. Challenge-response for high-suspicion sources

use axum::{
    body::Body,
    extract::{ConnectInfo, State},
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::warn;

use crate::cache::Cache;
use crate::ddos::{
    fingerprint::RequestFingerprint,
    queue::PriorityTier,
    state::DdosState,
};

/// Determine the priority tier for a request.
/// High: internal service header or in-flight transaction status check.
/// Standard: authenticated (has Authorization header).
/// Low: anonymous.
fn classify_tier(req: &Request<Body>) -> PriorityTier {
    let headers = req.headers();

    // Internal microservice marker
    if headers.get("x-internal-service").is_some() {
        return PriorityTier::High;
    }

    // In-flight transaction status/webhook — prioritise during attacks
    let path = req.uri().path();
    if path.contains("/onramp/status") || path.contains("/webhooks/") {
        if headers.get("authorization").is_some() {
            return PriorityTier::High;
        }
    }

    if headers.get("authorization").is_some() || headers.get("x-api-key").is_some() {
        PriorityTier::Standard
    } else {
        PriorityTier::Low
    }
}

fn client_ip(req: &Request<Body>, addr: &SocketAddr) -> String {
    req.headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| addr.ip().to_string())
}

fn reject(status: StatusCode, code: &str, message: &str, retry_after: Option<u64>) -> Response {
    let mut res = (
        status,
        Json(json!({ "error": { "code": code, "message": message } })),
    )
        .into_response();
    if let Some(secs) = retry_after {
        if let Ok(v) = secs.to_string().parse() {
            res.headers_mut().insert("Retry-After", v);
        }
    }
    res
}

pub async fn ddos_middleware(
    State(state): State<Arc<DdosState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let ip = client_ip(&req, &addr);
    let path = req.uri().path().to_string();

    // Health and metrics endpoints bypass DDoS checks
    if path.starts_with("/health") || path == "/metrics" {
        return next.run(req).await;
    }

    // 1. Lockdown check
    state.lockdown.check_auto_expire().await;
    if state.lockdown.is_active().await {
        let tier = classify_tier(&req);
        let allowlisted = state.lockdown.is_allowlisted(&ip);
        if !allowlisted && tier != PriorityTier::High {
            crate::ddos::metrics::dropped_requests()
                .with_label_values(&["lockdown"])
                .inc();
            return reject(
                StatusCode::SERVICE_UNAVAILABLE,
                "LOCKDOWN",
                "Service temporarily restricted. Please retry later.",
                Some(60),
            );
        }
    }

    // 2. Blocked IP check
    if state.is_blocked(&ip).await {
        crate::ddos::metrics::dropped_requests()
            .with_label_values(&["blocked_ip"])
            .inc();
        return reject(StatusCode::FORBIDDEN, "BLOCKED", "Access denied.", None);
    }

    // 3. Per-IP connection count (Redis INCR with TTL)
    let conn_key = format!("ddos:conn:{}", ip);
    let conn_count = <crate::cache::RedisCache as Cache<String>>::increment(
        &state.cache,
        &conn_key,
        1,
    )
    .await
    .unwrap_or(0);

    if conn_count == 1 {
        // Set TTL on first increment
        let _ = <crate::cache::RedisCache as Cache<String>>::expire(
            &state.cache,
            &conn_key,
            std::time::Duration::from_secs(60),
        )
        .await;
    }

    if conn_count > state.config.max_connections_per_ip as i64 {
        crate::ddos::metrics::dropped_requests()
            .with_label_values(&["conn_limit_ip"])
            .inc();
        let _ = <crate::cache::RedisCache as Cache<String>>::increment(
            &state.cache, &conn_key, -1,
        ).await;
        return reject(
            StatusCode::TOO_MANY_REQUESTS,
            "CONN_LIMIT",
            "Too many connections from your IP.",
            Some(10),
        );
    }

    // 4. Fingerprint analysis
    let fingerprint = RequestFingerprint::from_request(&req);
    let suspicion = fingerprint.suspicion_score();

    // Record request for attack detection
    state.detector.record_request(&path, &ip, &fingerprint).await;

    // Update global RPS metric
    crate::ddos::metrics::request_rate()
        .with_label_values(&[])
        .set(state.detector.current_rps().await);

    // 5. Challenge-response for high-suspicion sources
    if suspicion >= 0.5 {
        // Check if client already solved a challenge recently
        let solved_token = req
            .headers()
            .get("x-ddos-challenge-token")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        if !solved_token.is_empty() && state.challenge.is_already_solved(solved_token).await {
            // Client has a valid solved token — let through
        } else if suspicion >= 0.5 {
            // Issue a challenge
            let challenge = state.challenge.issue_challenge(suspicion);
            warn!(ip = %ip, suspicion = suspicion, "Challenge issued to suspected automated source");
            crate::ddos::metrics::dropped_requests()
                .with_label_values(&["challenge_required"])
                .inc();
            let _ = <crate::cache::RedisCache as Cache<String>>::increment(
                &state.cache, &conn_key, -1,
            ).await;
            return (
                StatusCode::FORBIDDEN,
                Json(json!({
                    "error": { "code": "CHALLENGE_REQUIRED", "message": "Proof-of-work challenge required." },
                    "challenge": challenge
                })),
            )
                .into_response();
        }
    }

    // 6. Fair queue slot acquisition with WRED
    let tier = classify_tier(&req);

    // WRED: probabilistic early drop before queue is full
    let drop_prob = state.queue.wred_drop_probability(tier);
    if drop_prob > 0.0 {
        // Simple deterministic approximation: drop if conn_count % 100 < drop_prob * 100
        let roll = (conn_count.unsigned_abs() % 100) as f64;
        if roll < drop_prob * 100.0 && tier == PriorityTier::Low {
            crate::ddos::metrics::dropped_requests()
                .with_label_values(&["wred"])
                .inc();
            let _ = <crate::cache::RedisCache as Cache<String>>::increment(
                &state.cache, &conn_key, -1,
            ).await;
            return reject(
                StatusCode::SERVICE_UNAVAILABLE,
                "OVERLOAD",
                "Server is under high load. Please retry.",
                Some(5),
            );
        }
    }

    if !state.queue.try_acquire(tier) {
        crate::ddos::metrics::dropped_requests()
            .with_label_values(&["queue_full"])
            .inc();
        let _ = <crate::cache::RedisCache as Cache<String>>::increment(
            &state.cache, &conn_key, -1,
        ).await;
        return reject(
            StatusCode::SERVICE_UNAVAILABLE,
            "OVERLOAD",
            "Server is under high load. Please retry.",
            Some(5),
        );
    }

    // Process the request
    let response = next.run(req).await;

    // Release slot and decrement connection count
    state.queue.release(tier);
    let _ = <crate::cache::RedisCache as Cache<String>>::increment(
        &state.cache, &conn_key, -1,
    ).await;

    response
}
