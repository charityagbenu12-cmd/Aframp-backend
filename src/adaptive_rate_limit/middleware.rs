//! Axum middleware that enforces adaptive rate limits on every request.
//!
//! Sits after the static rate limit middleware and applies the adaptive
//! multiplier on top. Also handles graceful degradation (503) for
//! non-essential endpoints in critical/emergency mode.

use axum::{
    body::Body,
    extract::{Request, State},
    http::{HeaderValue, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use std::sync::Arc;
use tracing::{info, warn};
use uuid::Uuid;

use crate::adaptive_rate_limit::{
    engine::AdaptiveRateLimitEngine,
    models::{AdaptationMode, ConsumerPriorityTier, EndpointCategory},
    queue::{service_unavailable_response, EmergencyQueue},
};
use crate::cache::RedisCache;
use crate::middleware::api_key::AuthenticatedKey;

/// State injected into the adaptive rate limit middleware.
#[derive(Clone)]
pub struct AdaptiveRateLimitState {
    pub engine: Arc<AdaptiveRateLimitEngine>,
    pub emergency_queue: Arc<EmergencyQueue>,
    pub cache: Arc<RedisCache>,
}

/// Axum middleware function for adaptive rate limiting.
pub async fn adaptive_rate_limit_middleware(
    State(state): State<AdaptiveRateLimitState>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let path = req.uri().path().to_string();

    // Health and metrics endpoints are always bypassed.
    if path.starts_with("/health") || path.starts_with("/ready") || path == "/metrics" {
        return next.run(req).await;
    }

    let mode = state.engine.current_mode().await;
    let (consumer_id, tier) = extract_consumer_info(&req);

    state.engine.signals.request_started();
    state.engine.record_request(consumer_id, tier).await;

    // ── Emergency mode ───────────────────────────────────────────────────────
    if mode == AdaptationMode::Emergency {
        match EndpointCategory::classify(&path) {
            EndpointCategory::NonEssential => {
                state.engine.signals.request_finished(false);
                warn!(
                    path = %path,
                    consumer_id = %consumer_id,
                    "non-essential endpoint blocked in emergency mode"
                );
                return service_unavailable_response(
                    "Service temporarily unavailable. Platform is in emergency mode.",
                    120,
                );
            }
            EndpointCategory::Essential => {
                let queue_depth = state.emergency_queue.depth().await;
                info!(
                    path = %path,
                    queue_depth = queue_depth,
                    "essential endpoint queued in emergency mode"
                );
                // Fall through — apply minimal limit below.
            }
        }
    }

    // ── Critical mode: throttle non-essential endpoints ──────────────────────
    if mode == AdaptationMode::Critical
        && EndpointCategory::classify(&path) == EndpointCategory::NonEssential
    {
        let multiplier = state.engine.effective_multiplier(consumer_id, tier).await;
        if let Some(resp) =
            check_adaptive_limit(&state, &path, consumer_id, tier, multiplier, mode).await
        {
            state.engine.signals.request_finished(true);
            return resp;
        }
    }

    // ── Elevated / Critical: apply multiplier to all consumers ───────────────
    if matches!(mode, AdaptationMode::Elevated | AdaptationMode::Critical) {
        let multiplier = state.engine.effective_multiplier(consumer_id, tier).await;
        if multiplier < 1.0 {
            if let Some(resp) =
                check_adaptive_limit(&state, &path, consumer_id, tier, multiplier, mode).await
            {
                state.engine.signals.request_finished(true);
                return resp;
            }
        }
    }

    let response = next.run(req).await;
    let is_error = response.status().is_server_error();
    state.engine.signals.request_finished(is_error);
    response
}

// ---------------------------------------------------------------------------
// Adaptive limit check
// ---------------------------------------------------------------------------

/// Returns `Some(response)` if the request should be rejected, `None` to allow.
async fn check_adaptive_limit(
    state: &AdaptiveRateLimitState,
    path: &str,
    consumer_id: Uuid,
    tier: ConsumerPriorityTier,
    multiplier: f64,
    mode: AdaptationMode,
) -> Option<Response> {
    let prefix = &state.engine.config.redis_key_prefix;
    let tier_str = tier.as_str();

    let mut conn = match state.cache.get_connection().await {
        Ok(c) => c,
        Err(_) => return None, // fail open on Redis error
    };

    // Read the authoritative multiplier from Redis (set by the engine sync).
    let redis_multiplier: Option<String> = redis::cmd("GET")
        .arg(format!("{prefix}:multiplier:{tier_str}"))
        .query_async(&mut *conn)
        .await
        .ok()
        .flatten();

    let effective_multiplier = redis_multiplier
        .and_then(|s| s.parse::<f64>().ok())
        .unwrap_or(multiplier);

    // Emergency: enforce the minimal per-consumer limit.
    if mode == AdaptationMode::Emergency {
        let minimal = state.engine.config.emergency_minimal_limit;
        let key = format!("adaptive_rl:emergency:{consumer_id}:{path}");
        let now_ms = chrono::Utc::now().timestamp_millis();
        let window_start = now_ms - 60_000i64;

        let count: i64 = redis::pipe()
            .atomic()
            .cmd("ZREMRANGEBYSCORE")
            .arg(&key)
            .arg("-inf")
            .arg(window_start)
            .cmd("ZCARD")
            .arg(&key)
            .query_async::<(i64, i64)>(&mut *conn)
            .await
            .map(|(_, c)| c)
            .unwrap_or(0);

        if count >= minimal {
            return Some(too_many_requests_response(mode, effective_multiplier, 60));
        }

        let req_id = Uuid::new_v4().to_string();
        let _: () = redis::pipe()
            .atomic()
            .cmd("ZADD")
            .arg(&key)
            .arg(now_ms)
            .arg(&req_id)
            .cmd("EXPIRE")
            .arg(&key)
            .arg(120u64)
            .query_async(&mut *conn)
            .await
            .unwrap_or(());

        return None;
    }

    // Elevated / Critical: enforce the tightened limit.
    let key = format!("adaptive_rl:consumer:{consumer_id}:{path}");
    let now_ms = chrono::Utc::now().timestamp_millis();
    let window_start = now_ms - 60_000i64;

    let static_limit: i64 = 100; // conservative default
    let adaptive_limit = ((static_limit as f64) * effective_multiplier).max(1.0) as i64;

    let count: i64 = redis::pipe()
        .atomic()
        .cmd("ZREMRANGEBYSCORE")
        .arg(&key)
        .arg("-inf")
        .arg(window_start)
        .cmd("ZCARD")
        .arg(&key)
        .query_async::<(i64, i64)>(&mut *conn)
        .await
        .map(|(_, c)| c)
        .unwrap_or(0);

    if count >= adaptive_limit {
        warn!(
            consumer_id = %consumer_id,
            path = %path,
            mode = %mode,
            multiplier = effective_multiplier,
            count = count,
            limit = adaptive_limit,
            "adaptive rate limit exceeded"
        );
        return Some(too_many_requests_response(mode, effective_multiplier, 60));
    }

    let req_id = Uuid::new_v4().to_string();
    let _: () = redis::pipe()
        .atomic()
        .cmd("ZADD")
        .arg(&key)
        .arg(now_ms)
        .arg(&req_id)
        .cmd("EXPIRE")
        .arg(&key)
        .arg(120u64)
        .query_async(&mut *conn)
        .await
        .unwrap_or(());

    None
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn extract_consumer_info(req: &Request<Body>) -> (Uuid, ConsumerPriorityTier) {
    if let Some(auth) = req.extensions().get::<AuthenticatedKey>() {
        let tier = ConsumerPriorityTier::from_consumer_type(&auth.consumer_type);
        return (auth.consumer_id, tier);
    }
    (Uuid::nil(), ConsumerPriorityTier::Standard)
}

fn too_many_requests_response(
    mode: AdaptationMode,
    multiplier: f64,
    retry_after: u64,
) -> Response {
    let mut res = (
        StatusCode::TOO_MANY_REQUESTS,
        Json(json!({
            "error": {
                "code": "ADAPTIVE_RATE_LIMIT_EXCEEDED",
                "message": format!(
                    "Rate limit tightened due to platform load (mode: {}, multiplier: {:.2}). \
                     Please retry later.",
                    mode, multiplier
                ),
                "mode": mode.as_str(),
                "retry_after": retry_after
            }
        })),
    )
        .into_response();
    res.headers_mut().insert(
        "Retry-After",
        HeaderValue::from_str(&retry_after.to_string()).unwrap(),
    );
    res.headers_mut().insert(
        "X-Adaptive-Mode",
        HeaderValue::from_str(mode.as_str()).unwrap(),
    );
    res
}
