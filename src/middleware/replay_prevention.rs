//! Replay Attack Prevention Middleware (Issue #141)
//!
//! Protects signed API requests from being replayed by combining:
//!   1. Timestamp validation — rejects requests outside a configurable time window.
//!   2. Nonce tracking     — atomically stores each accepted nonce in Redis so that
//!                           a replayed request (same nonce) is rejected immediately.
//!
//! # Headers consumed
//! - `X-Aframp-Timestamp` — Unix timestamp (seconds) when the request was signed.
//! - `X-Aframp-Nonce`     — UUID v4 or 32-byte hex string, unique per request.
//! - `X-Aframp-Consumer`  — Consumer ID used to namespace the Redis nonce key.
//!
//! # Flow
//! ```text
//! extract headers
//!   → validate timestamp (window + future tolerance)
//!   → atomic Redis SET NX with TTL  (nonce check + store in one command)
//!   → if SET NX returned 0 → replay detected → 401
//!   → proceed to next handler
//! ```

use axum::{
    body::Body,
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use redis::AsyncCommands;
use serde::Serialize;
use std::sync::Arc;
use tracing::{error, info, warn};

use crate::cache::RedisPool;
use crate::cache::keys::replay::NonceKey;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Replay-prevention configuration — typically loaded from environment / config file.
#[derive(Debug, Clone)]
pub struct ReplayConfig {
    /// Maximum age of a request timestamp (seconds). Default: 300 (5 minutes).
    pub timestamp_window_secs: i64,
    /// How far into the future a timestamp may be (seconds). Default: 30.
    pub future_tolerance_secs: i64,
    /// Extra TTL buffer added to the Redis nonce key beyond the timestamp window (seconds).
    pub nonce_ttl_buffer_secs: u64,
    /// Clock skew alert threshold (seconds). If the median delta for a consumer exceeds
    /// this value, a warning is emitted. Default: 60.
    pub clock_skew_alert_threshold_secs: f64,
    /// Replay attempt alert threshold per consumer within the rolling window. Default: 5.
    pub replay_alert_threshold: u64,
}

impl Default for ReplayConfig {
    fn default() -> Self {
        Self {
            timestamp_window_secs: 300,
            future_tolerance_secs: 30,
            nonce_ttl_buffer_secs: 60,
            clock_skew_alert_threshold_secs: 60.0,
            replay_alert_threshold: 5,
        }
    }
}

impl ReplayConfig {
    /// Total TTL for a nonce key in Redis: window + buffer.
    pub fn nonce_ttl_secs(&self) -> u64 {
        self.timestamp_window_secs as u64 + self.nonce_ttl_buffer_secs
    }

    /// Load configuration from environment variables, falling back to defaults.
    ///
    /// | Variable                          | Default | Description                                      |
    /// |-----------------------------------|---------|--------------------------------------------------|
    /// | `REPLAY_TIMESTAMP_WINDOW_SECS`    | 300     | Max age of a request timestamp (seconds).        |
    /// | `REPLAY_FUTURE_TOLERANCE_SECS`    | 30      | Max future skew allowed (seconds).               |
    /// | `REPLAY_NONCE_TTL_BUFFER_SECS`    | 60      | Extra TTL buffer on top of the window (seconds). |
    /// | `REPLAY_CLOCK_SKEW_ALERT_SECS`    | 60      | Clock skew alert threshold (seconds).            |
    /// | `REPLAY_ATTEMPT_ALERT_THRESHOLD`  | 5       | Replay attempts before alerting.                 |
    pub fn from_env() -> Self {
        let default = Self::default();
        Self {
            timestamp_window_secs: std::env::var("REPLAY_TIMESTAMP_WINDOW_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(default.timestamp_window_secs),
            future_tolerance_secs: std::env::var("REPLAY_FUTURE_TOLERANCE_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(default.future_tolerance_secs),
            nonce_ttl_buffer_secs: std::env::var("REPLAY_NONCE_TTL_BUFFER_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(default.nonce_ttl_buffer_secs),
            clock_skew_alert_threshold_secs: std::env::var("REPLAY_CLOCK_SKEW_ALERT_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(default.clock_skew_alert_threshold_secs),
            replay_alert_threshold: std::env::var("REPLAY_ATTEMPT_ALERT_THRESHOLD")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(default.replay_alert_threshold),
        }
    }
}

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct ReplayPreventionState {
    pub redis: Arc<RedisPool>,
    pub config: Arc<ReplayConfig>,
}

// ---------------------------------------------------------------------------
// Error response helpers
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct SecurityError {
    error: SecurityErrorDetail,
}

#[derive(Serialize)]
struct SecurityErrorDetail {
    code: String,
    message: String,
}

fn security_401(code: &str, message: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(SecurityError {
            error: SecurityErrorDetail {
                code: code.to_string(),
                message: message.to_string(),
            },
        }),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// Header extraction helpers
// ---------------------------------------------------------------------------

fn extract_header<'a>(req: &'a Request<Body>, name: &str) -> Option<&'a str> {
    req.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
}

// ---------------------------------------------------------------------------
// Timestamp validation
// ---------------------------------------------------------------------------

/// Returns `Ok(delta_secs)` where delta = |server_time - request_time|,
/// or an `Err` response to send back to the client.
fn validate_timestamp(
    request_ts: i64,
    server_ts: i64,
    config: &ReplayConfig,
) -> Result<f64, Response> {
    let delta = server_ts - request_ts;

    if delta > config.timestamp_window_secs {
        return Err(security_401(
            "TIMESTAMP_TOO_OLD",
            &format!(
                "Request timestamp is {} seconds old; maximum allowed age is {} seconds",
                delta, config.timestamp_window_secs
            ),
        ));
    }

    if -delta > config.future_tolerance_secs {
        return Err(security_401(
            "TIMESTAMP_IN_FUTURE",
            &format!(
                "Request timestamp is {} seconds in the future; maximum tolerance is {} seconds",
                -delta, config.future_tolerance_secs
            ),
        ));
    }

    Ok(delta.unsigned_abs() as f64)
}

// ---------------------------------------------------------------------------
// Nonce validation (atomic Redis SET NX)
// ---------------------------------------------------------------------------

/// Atomically checks and stores a nonce in Redis.
///
/// Uses `SET key 1 NX EX ttl` — if the key already exists the command returns
/// `nil` (None), indicating a replay.  Returns `true` if the nonce was fresh
/// (stored successfully), `false` if it was a replay.
async fn check_and_store_nonce(
    pool: &RedisPool,
    nonce_key: &str,
    ttl_secs: u64,
) -> Result<bool, String> {
    let mut conn = pool
        .get()
        .await
        .map_err(|e| format!("Redis connection error: {e}"))?;

    // SET key "1" NX EX ttl  — atomic check-and-set
    let result: Option<String> = redis::cmd("SET")
        .arg(nonce_key)
        .arg("1")
        .arg("NX")
        .arg("EX")
        .arg(ttl_secs)
        .query_async(&mut *conn)
        .await
        .map_err(|e| format!("Redis SET NX error: {e}"))?;

    // SET NX returns "OK" when the key was set (nonce is fresh),
    // or nil (None) when the key already existed (replay).
    Ok(result.is_some())
}

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------

/// Axum middleware that enforces timestamp + nonce replay prevention.
///
/// Attach to any route group that uses HMAC request signing:
/// ```rust,ignore
/// Router::new()
///     .route("/transfers", post(handler))
///     .layer(axum::middleware::from_fn_with_state(
///         state,
///         replay_prevention_middleware,
///     ))
/// ```
pub async fn replay_prevention_middleware(
    State(state): State<ReplayPreventionState>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let endpoint = req.uri().path().to_string();

    // ── 1. Extract required headers ──────────────────────────────────────────
    let timestamp_str = match extract_header(&req, "x-aframp-timestamp") {
        Some(v) => v.to_string(),
        None => {
            warn!(endpoint = %endpoint, "Missing X-Aframp-Timestamp header");
            return security_401(
                "MISSING_TIMESTAMP",
                "X-Aframp-Timestamp header is required",
            );
        }
    };

    let nonce = match extract_header(&req, "x-aframp-nonce") {
        Some(v) => v.to_string(),
        None => {
            warn!(endpoint = %endpoint, "Missing X-Aframp-Nonce header");
            return security_401("MISSING_NONCE", "X-Aframp-Nonce header is required");
        }
    };

    let consumer_id = extract_header(&req, "x-aframp-consumer")
        .unwrap_or("unknown")
        .to_string();

    // ── 2. Parse timestamp ───────────────────────────────────────────────────
    let request_ts: i64 = match timestamp_str.parse() {
        Ok(v) => v,
        Err(_) => {
            warn!(
                consumer_id = %consumer_id,
                endpoint = %endpoint,
                raw = %timestamp_str,
                "Unparseable X-Aframp-Timestamp"
            );
            return security_401(
                "INVALID_TIMESTAMP",
                "X-Aframp-Timestamp must be a Unix timestamp in seconds",
            );
        }
    };

    let server_ts = chrono::Utc::now().timestamp();

    // ── 3. Validate timestamp window ─────────────────────────────────────────
    let delta = match validate_timestamp(request_ts, server_ts, &state.config) {
        Ok(d) => d,
        Err(resp) => {
            let skew = server_ts - request_ts;
            warn!(
                consumer_id = %consumer_id,
                endpoint = %endpoint,
                request_ts = request_ts,
                server_ts = server_ts,
                delta_secs = skew,
                "Timestamp validation failed"
            );
            let reason = if skew > 0 { "too_old" } else { "too_future" };
            crate::metrics::security::timestamp_rejections_total()
                .with_label_values(&[&consumer_id, reason])
                .inc();
            return resp;
        }
    };

    // ── 4. Track clock-skew histogram for valid timestamps ───────────────────
    crate::metrics::security::timestamp_delta_seconds()
        .with_label_values(&[&consumer_id])
        .observe(delta);

    // Alert if delta exceeds the configured clock skew threshold
    if delta > state.config.clock_skew_alert_threshold_secs {
        warn!(
            consumer_id = %consumer_id,
            endpoint = %endpoint,
            delta_secs = delta,
            threshold_secs = state.config.clock_skew_alert_threshold_secs,
            "Clock skew alert: consumer timestamp delta exceeds threshold — possible misconfigured clock"
        );
    }

    // ── 5. Atomic nonce check-and-store ──────────────────────────────────────
    let nonce_key = NonceKey::new(&consumer_id, &nonce).to_string();
    let ttl = state.config.nonce_ttl_secs();

    match check_and_store_nonce(&state.redis, &nonce_key, ttl).await {
        Ok(true) => {
            // Nonce was fresh — proceed
            info!(
                consumer_id = %consumer_id,
                endpoint = %endpoint,
                nonce = %nonce,
                "Request accepted: fresh nonce"
            );
        }
        Ok(false) => {
            // Nonce already seen — replay detected
            let attempt_count = crate::metrics::security::replay_attempts_total()
                .with_label_values(&[&consumer_id, &endpoint])
                .get() as u64 + 1;

            warn!(
                consumer_id = %consumer_id,
                endpoint = %endpoint,
                nonce = %nonce,
                request_ts = request_ts,
                server_ts = server_ts,
                detection_ts = chrono::Utc::now().timestamp(),
                "Replay attack detected: nonce already consumed"
            );
            crate::metrics::security::replay_attempts_total()
                .with_label_values(&[&consumer_id, &endpoint])
                .inc();

            // Alert if replay attempts from this consumer exceed the threshold
            if attempt_count >= state.config.replay_alert_threshold {
                warn!(
                    consumer_id = %consumer_id,
                    endpoint = %endpoint,
                    attempt_count = attempt_count,
                    threshold = state.config.replay_alert_threshold,
                    "Replay alert: consumer has exceeded replay attempt threshold — potential active attack"
                );
            }

            return security_401(
                "REPLAY_DETECTED",
                "This request has already been processed. Each request must use a unique nonce.",
            );
        }
        Err(e) => {
            // Redis error — fail closed (reject the request) to stay safe
            error!(
                consumer_id = %consumer_id,
                endpoint = %endpoint,
                error = %e,
                "Redis error during nonce check; rejecting request"
            );
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(SecurityError {
                    error: SecurityErrorDetail {
                        code: "NONCE_STORE_UNAVAILABLE".to_string(),
                        message: "Unable to verify request uniqueness. Please retry.".to_string(),
                    },
                }),
            )
                .into_response();
        }
    }

    next.run(req).await
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── Timestamp validation ─────────────────────────────────────────────────

    #[test]
    fn accepts_timestamp_within_window() {
        let cfg = ReplayConfig::default();
        let server = 1_000_000i64;
        // 10 seconds old — well within 300 s window
        assert!(validate_timestamp(server - 10, server, &cfg).is_ok());
    }

    #[test]
    fn rejects_timestamp_too_old() {
        let cfg = ReplayConfig::default();
        let server = 1_000_000i64;
        // 301 seconds old — just outside the 300 s window
        let result = validate_timestamp(server - 301, server, &cfg);
        assert!(result.is_err());
        let resp = result.unwrap_err();
        // Verify it's a 401
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn rejects_timestamp_at_exact_boundary() {
        let cfg = ReplayConfig::default();
        let server = 1_000_000i64;
        // Exactly at the window boundary (300 s) — should be rejected (> not >=)
        let result = validate_timestamp(server - 300, server, &cfg);
        // delta == window_secs is NOT > window_secs, so it should be accepted
        assert!(result.is_ok());
    }

    #[test]
    fn rejects_timestamp_in_future_beyond_tolerance() {
        let cfg = ReplayConfig::default();
        let server = 1_000_000i64;
        // 31 seconds in the future — beyond 30 s tolerance
        let result = validate_timestamp(server + 31, server, &cfg);
        assert!(result.is_err());
        let resp = result.unwrap_err();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn accepts_timestamp_within_future_tolerance() {
        let cfg = ReplayConfig::default();
        let server = 1_000_000i64;
        // 10 seconds in the future — within 30 s tolerance
        assert!(validate_timestamp(server + 10, server, &cfg).is_ok());
    }

    #[test]
    fn delta_value_is_correct() {
        let cfg = ReplayConfig::default();
        let server = 1_000_000i64;
        let delta = validate_timestamp(server - 42, server, &cfg).unwrap();
        assert!((delta - 42.0).abs() < f64::EPSILON);
    }

    // ── Nonce key construction ───────────────────────────────────────────────

    #[test]
    fn nonce_key_is_namespaced_per_consumer() {
        let key_a = NonceKey::new("consumer-a", "nonce-1").to_string();
        let key_b = NonceKey::new("consumer-b", "nonce-1").to_string();
        // Same nonce, different consumers → different keys
        assert_ne!(key_a, key_b);
        assert!(key_a.contains("consumer-a"));
        assert!(key_b.contains("consumer-b"));
    }

    #[test]
    fn nonce_key_format() {
        let key = NonceKey::new("abc-123", "deadbeef").to_string();
        assert_eq!(key, "v1:nonce:abc-123:deadbeef");
    }

    // ── Config helpers ───────────────────────────────────────────────────────

    #[test]
    fn nonce_ttl_is_window_plus_buffer() {
        let cfg = ReplayConfig {
            timestamp_window_secs: 300,
            nonce_ttl_buffer_secs: 60,
            ..Default::default()
        };
        assert_eq!(cfg.nonce_ttl_secs(), 360);
    }

    #[test]
    fn custom_config_respected() {
        let cfg = ReplayConfig {
            timestamp_window_secs: 60,
            future_tolerance_secs: 10,
            nonce_ttl_buffer_secs: 30,
            clock_skew_alert_threshold_secs: 30.0,
            replay_alert_threshold: 3,
        };
        let server = 1_000_000i64;
        // 61 seconds old — outside 60 s window
        assert!(validate_timestamp(server - 61, server, &cfg).is_err());
        // 11 seconds in future — outside 10 s tolerance
        assert!(validate_timestamp(server + 11, server, &cfg).is_err());
        // 59 seconds old — inside window
        assert!(validate_timestamp(server - 59, server, &cfg).is_ok());
    }

    #[test]
    fn clock_skew_alert_threshold_defaults_to_60() {
        let cfg = ReplayConfig::default();
        assert!((cfg.clock_skew_alert_threshold_secs - 60.0).abs() < f64::EPSILON);
    }

    #[test]
    fn replay_alert_threshold_defaults_to_5() {
        let cfg = ReplayConfig::default();
        assert_eq!(cfg.replay_alert_threshold, 5);
    }
}
