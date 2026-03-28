//! Request Signature Verification Middleware — Issue #140
//!
//! Server-side HMAC signature verification that mirrors the consumer-side
//! signing scheme defined in issue #139 / `hmac_signing`.
//!
//! # Flow
//! ```text
//! extract X-Aframp-Signature  →  parse algorithm / timestamp / signature
//! extract X-Aframp-Key-Id     →  look up key record (DB)
//! validate timestamp window   →  reject expired / future requests early
//! buffer body (≤ max_size)    →  reconstruct canonical request
//! check algorithm allowlist   →  enforce HMAC-SHA512 on high-value endpoints
//! try Redis signing-key cache →  derive via HKDF on cache miss
//! recompute expected HMAC     →  constant-time compare
//! 401 on any failure          →  generic error to consumer, detail in logs
//! ```

pub mod errors;

use std::sync::Arc;
use std::time::Instant;

use axum::{
    body::{to_bytes, Body},
    extract::{Request, State},
    middleware::Next,
    response::Response,
};
use redis::AsyncCommands;
use sqlx::PgPool;
use tracing::{debug, error, warn};

use crate::cache::keys::signing::DerivedKeyCache;
use crate::cache::RedisPool;
use crate::middleware::hmac_signing::{
    build_canonical_request, compute_signature, derive_signing_key, parse_signature_header_pub,
    sha256_hex, HmacAlgorithm,
};
use errors::{sig_401, sig_401_weak_algorithm, VerifyFailReason};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum body size buffered for verification (1 MiB — matches signing side).
const MAX_BODY_BYTES: usize = 1024 * 1024;

/// TTL for the cached derived signing key in Redis (seconds).
const SIGNING_KEY_CACHE_TTL_SECS: u64 = 300;

/// Replay-prevention window (seconds). Requests older than this are rejected.
const TIMESTAMP_WINDOW_SECS: i64 = 300;

/// Future-tolerance (seconds). Requests this far ahead of server time are rejected.
const FUTURE_TOLERANCE_SECS: i64 = 30;

// ---------------------------------------------------------------------------
// Algorithm policy
// ---------------------------------------------------------------------------

const ALLOWED_ALGORITHMS: &[HmacAlgorithm] = &[HmacAlgorithm::Sha256, HmacAlgorithm::Sha512];

/// Endpoint path prefixes that require HMAC-SHA512 as the minimum algorithm.
const HIGH_VALUE_PREFIXES: &[&str] = &[
    "/api/onramp/initiate",
    "/api/offramp/initiate",
    "/api/batch",
];

pub(crate) fn is_high_value(path: &str) -> bool {
    HIGH_VALUE_PREFIXES
        .iter()
        .any(|prefix| path.starts_with(prefix))
}

fn algorithm_allowed(alg: HmacAlgorithm) -> bool {
    ALLOWED_ALGORITHMS.contains(&alg)
}

// ---------------------------------------------------------------------------
// Endpoint signing policy
// ---------------------------------------------------------------------------

/// Whether an endpoint requires a signature or merely accepts one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningPolicy {
    /// Signature is mandatory — unsigned requests are rejected with 401.
    Mandatory,
    /// Signature is optional — unsigned requests pass through unchanged.
    Optional,
}

// ---------------------------------------------------------------------------
// Middleware state
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct SignatureVerificationState {
    pub db: Arc<PgPool>,
    pub redis: Arc<RedisPool>,
    pub policy: SigningPolicy,
}

// ---------------------------------------------------------------------------
// Key lookup (DB)
// ---------------------------------------------------------------------------

async fn fetch_api_secret(pool: &PgPool, key_id: &str) -> Option<String> {
    let key_id_uuid = uuid::Uuid::parse_str(key_id).ok()?;

    let row = sqlx::query!(
        r#"
        SELECT ak.key_hash
        FROM api_keys ak
        JOIN consumers c ON c.id = ak.consumer_id
        WHERE ak.id = $1
          AND ak.is_active = TRUE
          AND c.is_active  = TRUE
          AND (ak.expires_at IS NULL OR ak.expires_at > now())
        "#,
        key_id_uuid
    )
    .fetch_optional(pool)
    .await
    .ok()??;

    Some(row.key_hash)
}

// ---------------------------------------------------------------------------
// Signing key cache (Redis)
// ---------------------------------------------------------------------------

async fn get_cached_signing_key(redis: &RedisPool, key_id: &str) -> Option<Vec<u8>> {
    let cache_key = DerivedKeyCache::new(key_id).to_string();
    let mut conn = redis.get().await.ok()?;
    let bytes: Option<Vec<u8>> = conn.get(&cache_key).await.ok()?;
    bytes
}

async fn cache_signing_key(redis: &RedisPool, key_id: &str, signing_key: &[u8]) {
    let cache_key = DerivedKeyCache::new(key_id).to_string();
    if let Ok(mut conn) = redis.get().await {
        let _: Result<(), _> = redis::cmd("SET")
            .arg(&cache_key)
            .arg(signing_key)
            .arg("EX")
            .arg(SIGNING_KEY_CACHE_TTL_SECS)
            .query_async(&mut *conn)
            .await;
    }
}

// ---------------------------------------------------------------------------
// Timestamp validation
// ---------------------------------------------------------------------------

pub(crate) fn validate_timestamp(request_ts: i64, server_ts: i64) -> Result<(), VerifyFailReason> {
    let delta = server_ts - request_ts;
    if delta > TIMESTAMP_WINDOW_SECS {
        return Err(VerifyFailReason::ExpiredTimestamp);
    }
    if -delta > FUTURE_TOLERANCE_SECS {
        return Err(VerifyFailReason::ExpiredTimestamp);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Constant-time comparison
// ---------------------------------------------------------------------------

pub(crate) fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes()
        .zip(b.bytes())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

// ---------------------------------------------------------------------------
// Core verification
// ---------------------------------------------------------------------------

async fn verify_signature(
    state: &SignatureVerificationState,
    method: &str,
    path: &str,
    query: &str,
    headers: &axum::http::HeaderMap,
    body_bytes: &[u8],
    algorithm: HmacAlgorithm,
    timestamp: i64,
    provided_signature: &str,
    key_id: &str,
) -> Result<(), VerifyFailReason> {
    // Algorithm allowlist
    if !algorithm_allowed(algorithm) {
        return Err(VerifyFailReason::UnsupportedAlgorithm);
    }

    // High-value endpoints require SHA-512
    if is_high_value(path) && algorithm != HmacAlgorithm::Sha512 {
        return Err(VerifyFailReason::AlgorithmTooWeak);
    }

    // Timestamp window
    let server_ts = chrono::Utc::now().timestamp();
    validate_timestamp(timestamp, server_ts)?;

    // Resolve API secret from DB
    let api_secret_hash = fetch_api_secret(&state.db, key_id)
        .await
        .ok_or(VerifyFailReason::KeyNotFound)?;

    // Derive signing key — try Redis cache first
    let signing_key = if let Some(cached) = get_cached_signing_key(&state.redis, key_id).await {
        cached
    } else {
        let derived = derive_signing_key(api_secret_hash.as_bytes());
        cache_signing_key(&state.redis, key_id, &derived).await;
        derived
    };

    // Reconstruct canonical request (identical to consumer-side construction)
    let body_hash = sha256_hex(body_bytes);
    let canonical = build_canonical_request(method, path, query, headers, &body_hash)
        .map_err(|_| VerifyFailReason::MalformedHeader)?;

    // Recompute and constant-time compare
    let expected = compute_signature(algorithm, &signing_key, &canonical);
    if !constant_time_eq(&expected, provided_signature) {
        return Err(VerifyFailReason::SignatureMismatch);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------

/// Axum middleware that verifies HMAC request signatures (Issue #140).
///
/// Apply to all state-mutating and financial transaction endpoints:
/// ```rust,ignore
/// Router::new()
///     .route("/api/onramp/initiate", post(handler))
///     .layer(axum::middleware::from_fn_with_state(
///         SignatureVerificationState {
///             db,
///             redis,
///             policy: SigningPolicy::Mandatory,
///         },
///         signature_verification_middleware,
///     ))
/// ```
pub async fn signature_verification_middleware(
    State(state): State<SignatureVerificationState>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let start = Instant::now();
    let endpoint = req.uri().path().to_string();

    // 1. Extract X-Aframp-Signature
    let sig_header = match req
        .headers()
        .get("x-aframp-signature")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
    {
        Some(v) => v,
        None => {
            if state.policy == SigningPolicy::Optional {
                debug!(endpoint = %endpoint, "No signature on optional endpoint — passing through");
                return next.run(req).await;
            }
            return emit_failure("unknown", &endpoint, VerifyFailReason::MissingSignature, start);
        }
    };

    // 2. Extract X-Aframp-Key-Id
    let key_id = match req
        .headers()
        .get("x-aframp-key-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
    {
        Some(v) => v,
        None => {
            return emit_failure("unknown", &endpoint, VerifyFailReason::MissingKeyId, start);
        }
    };

    // 3. Parse signature header
    let parsed = match parse_signature_header_pub(&sig_header) {
        Some(p) => p,
        None => {
            return emit_failure(&key_id, &endpoint, VerifyFailReason::MalformedHeader, start);
        }
    };

    // 4. Early timestamp check (before body buffering — fast reject)
    let server_ts = chrono::Utc::now().timestamp();
    if let Err(reason) = validate_timestamp(parsed.timestamp, server_ts) {
        return emit_failure(&key_id, &endpoint, reason, start);
    }

    // 5. Buffer body (configurable max size, body still available downstream)
    let (parts, body) = req.into_parts();
    let body_bytes = match to_bytes(body, MAX_BODY_BYTES + 1).await {
        Ok(b) if b.len() <= MAX_BODY_BYTES => b,
        Ok(_) => {
            return emit_failure(&key_id, &endpoint, VerifyFailReason::MalformedHeader, start);
        }
        Err(e) => {
            error!(
                key_id = %key_id,
                endpoint = %endpoint,
                error = %e,
                "Failed to buffer body for signature verification"
            );
            return emit_failure(&key_id, &endpoint, VerifyFailReason::MalformedHeader, start);
        }
    };

    // 6. Full verification
    let query = parts.uri.query().unwrap_or("").to_string();
    let result = verify_signature(
        &state,
        parts.method.as_str(),
        parts.uri.path(),
        &query,
        &parts.headers,
        &body_bytes,
        parsed.algorithm,
        parsed.timestamp,
        &parsed.signature,
        &key_id,
    )
    .await;

    match result {
        Ok(()) => {
            let elapsed = start.elapsed().as_secs_f64();
            crate::metrics::signature::verifications_total()
                .with_label_values(&["success"])
                .inc();
            crate::metrics::signature::verification_duration_seconds()
                .with_label_values(&["success"])
                .observe(elapsed);
            debug!(
                key_id = %key_id,
                endpoint = %endpoint,
                algorithm = ?parsed.algorithm,
                elapsed_ms = elapsed * 1000.0,
                "Signature verified"
            );
            // Reconstruct request with buffered body so downstream handler can read it
            let req = Request::from_parts(parts, Body::from(body_bytes));
            next.run(req).await
        }
        Err(VerifyFailReason::AlgorithmTooWeak) => {
            emit_failure_weak_alg(&key_id, &endpoint, start)
        }
        Err(reason) => emit_failure(&key_id, &endpoint, reason, start),
    }
}

// ---------------------------------------------------------------------------
// Failure helpers — log internally, return generic 401 to consumer
// ---------------------------------------------------------------------------

fn emit_failure(
    consumer_id: &str,
    endpoint: &str,
    reason: VerifyFailReason,
    start: Instant,
) -> Response {
    let elapsed = start.elapsed().as_secs_f64();
    warn!(
        consumer_id = %consumer_id,
        endpoint    = %endpoint,
        reason      = reason.as_str(),
        elapsed_ms  = elapsed * 1000.0,
        "Signature verification failure"
    );
    crate::metrics::signature::failures_total()
        .with_label_values(&[consumer_id, endpoint, reason.as_str()])
        .inc();
    crate::metrics::signature::verifications_total()
        .with_label_values(&["failure"])
        .inc();
    crate::metrics::signature::verification_duration_seconds()
        .with_label_values(&["failure"])
        .observe(elapsed);
    sig_401()
}

fn emit_failure_weak_alg(consumer_id: &str, endpoint: &str, start: Instant) -> Response {
    let elapsed = start.elapsed().as_secs_f64();
    warn!(
        consumer_id = %consumer_id,
        endpoint    = %endpoint,
        reason      = VerifyFailReason::AlgorithmTooWeak.as_str(),
        elapsed_ms  = elapsed * 1000.0,
        "Signature verification failure — algorithm too weak for high-value endpoint"
    );
    crate::metrics::signature::failures_total()
        .with_label_values(&[consumer_id, endpoint, VerifyFailReason::AlgorithmTooWeak.as_str()])
        .inc();
    crate::metrics::signature::verifications_total()
        .with_label_values(&["failure"])
        .inc();
    crate::metrics::signature::verification_duration_seconds()
        .with_label_values(&["failure"])
        .observe(elapsed);
    sig_401_weak_algorithm("HMAC-SHA512")
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::middleware::hmac_signing::{sign_request, HmacAlgorithm};

    // ── Timestamp validation ─────────────────────────────────────────────────

    #[test]
    fn accepts_timestamp_within_window() {
        let server = 1_000_000i64;
        assert!(validate_timestamp(server - 10, server).is_ok());
    }

    #[test]
    fn rejects_timestamp_too_old() {
        let server = 1_000_000i64;
        assert_eq!(
            validate_timestamp(server - (TIMESTAMP_WINDOW_SECS + 1), server),
            Err(VerifyFailReason::ExpiredTimestamp)
        );
    }

    #[test]
    fn accepts_timestamp_at_exact_boundary() {
        let server = 1_000_000i64;
        assert!(validate_timestamp(server - TIMESTAMP_WINDOW_SECS, server).is_ok());
    }

    #[test]
    fn rejects_timestamp_too_far_in_future() {
        let server = 1_000_000i64;
        assert_eq!(
            validate_timestamp(server + FUTURE_TOLERANCE_SECS + 1, server),
            Err(VerifyFailReason::ExpiredTimestamp)
        );
    }

    #[test]
    fn accepts_timestamp_within_future_tolerance() {
        let server = 1_000_000i64;
        assert!(validate_timestamp(server + FUTURE_TOLERANCE_SECS, server).is_ok());
    }

    // ── Constant-time comparison ─────────────────────────────────────────────

    #[test]
    fn constant_time_eq_identical() {
        assert!(constant_time_eq("abcdef1234", "abcdef1234"));
    }

    #[test]
    fn constant_time_eq_different_content() {
        assert!(!constant_time_eq("abcdef1234", "abcdef1235"));
    }

    #[test]
    fn constant_time_eq_different_length() {
        assert!(!constant_time_eq("abc", "abcd"));
    }

    #[test]
    fn constant_time_eq_empty_strings() {
        assert!(constant_time_eq("", ""));
    }

    #[test]
    fn constant_time_eq_one_empty() {
        assert!(!constant_time_eq("", "a"));
    }

    // ── Algorithm enforcement ────────────────────────────────────────────────

    #[test]
    fn sha256_allowed_globally() {
        assert!(algorithm_allowed(HmacAlgorithm::Sha256));
    }

    #[test]
    fn sha512_allowed_globally() {
        assert!(algorithm_allowed(HmacAlgorithm::Sha512));
    }

    #[test]
    fn onramp_initiate_is_high_value() {
        assert!(is_high_value("/api/onramp/initiate"));
    }

    #[test]
    fn offramp_initiate_is_high_value() {
        assert!(is_high_value("/api/offramp/initiate"));
    }

    #[test]
    fn batch_is_high_value() {
        assert!(is_high_value("/api/batch/transfers"));
    }

    #[test]
    fn rates_endpoint_is_not_high_value() {
        assert!(!is_high_value("/api/rates"));
    }

    #[test]
    fn wallet_balance_is_not_high_value() {
        assert!(!is_high_value("/api/wallet/balance"));
    }

    // ── Signing key derivation ───────────────────────────────────────────────

    #[test]
    fn derived_key_is_deterministic() {
        let k1 = derive_signing_key(b"my-api-secret");
        let k2 = derive_signing_key(b"my-api-secret");
        assert_eq!(k1, k2);
    }

    #[test]
    fn different_secrets_produce_different_keys() {
        let k1 = derive_signing_key(b"secret-a");
        let k2 = derive_signing_key(b"secret-b");
        assert_ne!(k1, k2);
    }

    // ── Canonical request + signature round-trip ─────────────────────────────

    #[test]
    fn verify_round_trip_sha256() {
        let secret = b"round-trip-secret";
        let headers_slice = &[
            ("content-type", "application/json"),
            ("x-aframp-key-id", "key_rt"),
            ("x-aframp-timestamp", "1700000000"),
        ];
        let body = br#"{"amount":"500"}"#;

        let sig_header = sign_request(
            HmacAlgorithm::Sha256,
            "POST",
            "/api/onramp/quote",
            "",
            headers_slice,
            body,
            secret,
        );
        let parsed = parse_signature_header_pub(&sig_header).unwrap();

        let signing_key = derive_signing_key(secret);
        let mut hmap = axum::http::HeaderMap::new();
        for (k, v) in headers_slice {
            hmap.insert(
                axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                axum::http::HeaderValue::from_str(v).unwrap(),
            );
        }
        let body_hash = sha256_hex(body);
        let canonical =
            build_canonical_request("POST", "/api/onramp/quote", "", &hmap, &body_hash).unwrap();
        let expected = compute_signature(HmacAlgorithm::Sha256, &signing_key, &canonical);

        assert!(constant_time_eq(&expected, &parsed.signature));
    }

    #[test]
    fn tampered_body_fails_verification() {
        let secret = b"tamper-test-secret";
        let headers_slice = &[
            ("content-type", "application/json"),
            ("x-aframp-key-id", "key_t"),
            ("x-aframp-timestamp", "1700000000"),
        ];
        let original_body = br#"{"amount":"100"}"#;
        let tampered_body = br#"{"amount":"9999"}"#;

        let sig_header = sign_request(
            HmacAlgorithm::Sha256,
            "POST",
            "/api/onramp/quote",
            "",
            headers_slice,
            original_body,
            secret,
        );
        let parsed = parse_signature_header_pub(&sig_header).unwrap();

        let signing_key = derive_signing_key(secret);
        let mut hmap = axum::http::HeaderMap::new();
        for (k, v) in headers_slice {
            hmap.insert(
                axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                axum::http::HeaderValue::from_str(v).unwrap(),
            );
        }
        let body_hash = sha256_hex(tampered_body);
        let canonical =
            build_canonical_request("POST", "/api/onramp/quote", "", &hmap, &body_hash).unwrap();
        let recomputed = compute_signature(HmacAlgorithm::Sha256, &signing_key, &canonical);

        assert!(!constant_time_eq(&recomputed, &parsed.signature));
    }

    // ── VerifyFailReason ─────────────────────────────────────────────────────

    #[test]
    fn all_failure_reasons_have_non_empty_str() {
        let reasons = [
            VerifyFailReason::MissingSignature,
            VerifyFailReason::MissingKeyId,
            VerifyFailReason::MalformedHeader,
            VerifyFailReason::ExpiredTimestamp,
            VerifyFailReason::UnsupportedAlgorithm,
            VerifyFailReason::AlgorithmTooWeak,
            VerifyFailReason::KeyNotFound,
            VerifyFailReason::SignatureMismatch,
        ];
        for r in &reasons {
            assert!(!r.as_str().is_empty());
        }
    }

    #[test]
    fn all_failure_reasons_have_unique_str() {
        let reasons = [
            VerifyFailReason::MissingSignature,
            VerifyFailReason::MissingKeyId,
            VerifyFailReason::MalformedHeader,
            VerifyFailReason::ExpiredTimestamp,
            VerifyFailReason::UnsupportedAlgorithm,
            VerifyFailReason::AlgorithmTooWeak,
            VerifyFailReason::KeyNotFound,
            VerifyFailReason::SignatureMismatch,
        ];
        let strs: Vec<&str> = reasons.iter().map(|r| r.as_str()).collect();
        let unique: std::collections::HashSet<&str> = strs.iter().copied().collect();
        assert_eq!(strs.len(), unique.len());
    }
}
