//! HMAC Request Signing — Issue #139
//!
//! Implements HMAC-based request signing that binds the HTTP method, path,
//! query string, selected headers, body hash, and timestamp into a canonical
//! string that is signed with a key derived from the consumer's API secret.
//!
//! # Canonical request format
//! ```text
//! {METHOD}\n
//! {lowercase_path}\n
//! {sorted_query_string}\n
//! content-type:{value}\n
//! x-aframp-key-id:{value}\n
//! x-aframp-timestamp:{value}\n
//! {sha256_hex_of_body}
//! ```
//!
//! # Signature header
//! `X-Aframp-Signature: algorithm=HMAC-SHA256,timestamp=<ts>,signature=<hex>`
//!
//! # Signing key derivation
//! HKDF-SHA256(ikm=api_secret, salt=AFRAMP_SIGNING_SALT, info=b"aframp-request-signing-v1")
//! The derived key is never stored — it is re-derived on every verification.

pub mod errors;

use axum::{
    body::{to_bytes, Body},
    extract::{Request, State},
    middleware::Next,
    response::Response,
};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};
use std::sync::Arc;
use tracing::{debug, warn};

use errors::signing_401;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// HKDF salt — platform-defined, never changes.
const HKDF_SALT: &[u8] = b"aframp-hmac-salt-v1";
/// HKDF info string — binds the derived key to this specific purpose.
const HKDF_INFO: &[u8] = b"aframp-request-signing-v1";
/// Headers that MUST be present and are included in the canonical request.
const REQUIRED_HEADERS: &[&str] = &["content-type", "x-aframp-key-id", "x-aframp-timestamp"];
/// Maximum body size buffered for signing (1 MiB).
const MAX_BODY_BYTES: usize = 1024 * 1024;

// ---------------------------------------------------------------------------
// Algorithm
// ---------------------------------------------------------------------------

/// Supported HMAC algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HmacAlgorithm {
    Sha256,
    Sha512,
}

impl HmacAlgorithm {
    fn as_str(self) -> &'static str {
        match self {
            Self::Sha256 => "HMAC-SHA256",
            Self::Sha512 => "HMAC-SHA512",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        match s.to_uppercase().as_str() {
            "HMAC-SHA256" => Some(Self::Sha256),
            "HMAC-SHA512" => Some(Self::Sha512),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Middleware state
// ---------------------------------------------------------------------------

/// Shared state for the HMAC signing middleware.
///
/// `key_resolver` is a function that, given a `key_id`, returns the raw API
/// secret bytes (or `None` if the key is unknown).  In production this calls
/// the database; in tests it can be a simple closure over a HashMap.
#[derive(Clone)]
pub struct HmacSigningState {
    pub key_resolver: Arc<dyn Fn(&str) -> Option<Vec<u8>> + Send + Sync>,
    /// When `true`, the middleware enforces signing on every request.
    /// Set to `false` only in development to allow unsigned requests through
    /// with a warning.
    pub enforce: bool,
}

// ---------------------------------------------------------------------------
// HKDF key derivation
// ---------------------------------------------------------------------------

/// Derive a signing key from the raw API secret using HKDF-SHA256.
///
/// The derivation is deterministic: the same `api_secret` always produces the
/// same signing key.  The derived key is never stored — callers re-derive it
/// on every verification.
pub fn derive_signing_key(api_secret: &[u8]) -> Vec<u8> {
    // HKDF extract: PRK = HMAC-SHA256(salt, ikm)
    type HmacSha256 = Hmac<Sha256>;
    let mut extract_mac = HmacSha256::new_from_slice(HKDF_SALT)
        .expect("HMAC accepts any key length");
    extract_mac.update(api_secret);
    let prk = extract_mac.finalize().into_bytes();

    // HKDF expand: OKM = T(1) where T(1) = HMAC-SHA256(PRK, info || 0x01)
    let mut expand_mac = HmacSha256::new_from_slice(&prk)
        .expect("HMAC accepts any key length");
    expand_mac.update(HKDF_INFO);
    expand_mac.update(&[0x01u8]);
    expand_mac.finalize().into_bytes().to_vec()
}

// ---------------------------------------------------------------------------
// Canonical request construction
// ---------------------------------------------------------------------------

/// Build the canonical request string that is signed.
///
/// Components (newline-delimited):
/// 1. HTTP method — uppercase
/// 2. Request path — lowercase, trailing slash stripped (except root "/"),
///    percent-encoded consistently
/// 3. Sorted query string — `key=value` pairs sorted alphabetically by key,
///    joined with `&`; empty string when no query parameters
/// 4. Required headers — `{lowercase_name}:{trimmed_value}` for each of
///    `content-type`, `x-aframp-key-id`, `x-aframp-timestamp`
/// 5. SHA-256 hex digest of the raw request body
pub fn build_canonical_request(
    method: &str,
    path: &str,
    query: &str,
    headers: &axum::http::HeaderMap,
    body_hash: &str,
) -> Result<String, &'static str> {
    // 1. Method
    let method_upper = method.to_uppercase();

    // 2. Path — lowercase, strip trailing slash (keep root "/")
    let normalised_path = {
        let lower = path.to_lowercase();
        if lower.len() > 1 && lower.ends_with('/') {
            lower.trim_end_matches('/').to_string()
        } else {
            lower
        }
    };

    // 3. Query string — sort parameters alphabetically
    let sorted_query = {
        let mut pairs: Vec<&str> = query.split('&').filter(|s| !s.is_empty()).collect();
        pairs.sort_unstable();
        pairs.join("&")
    };

    // 4. Required headers
    let mut header_lines = Vec::with_capacity(REQUIRED_HEADERS.len());
    for &name in REQUIRED_HEADERS {
        let value = headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .ok_or("missing required header")?;
        header_lines.push(format!("{}:{}", name, value.trim()));
    }

    // 5. Assemble
    let mut parts = vec![method_upper, normalised_path, sorted_query];
    parts.extend(header_lines);
    parts.push(body_hash.to_string());

    Ok(parts.join("\n"))
}

// ---------------------------------------------------------------------------
// Body hashing
// ---------------------------------------------------------------------------

/// Compute the SHA-256 hex digest of a byte slice.
pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

// ---------------------------------------------------------------------------
// Signature computation
// ---------------------------------------------------------------------------

/// Compute HMAC over `canonical_request` using the derived signing key.
pub fn compute_signature(
    algorithm: HmacAlgorithm,
    signing_key: &[u8],
    canonical_request: &str,
) -> String {
    match algorithm {
        HmacAlgorithm::Sha256 => {
            type HmacSha256 = Hmac<Sha256>;
            let mut mac = HmacSha256::new_from_slice(signing_key)
                .expect("HMAC accepts any key length");
            mac.update(canonical_request.as_bytes());
            hex::encode(mac.finalize().into_bytes())
        }
        HmacAlgorithm::Sha512 => {
            type HmacSha512 = Hmac<Sha512>;
            let mut mac = HmacSha512::new_from_slice(signing_key)
                .expect("HMAC accepts any key length");
            mac.update(canonical_request.as_bytes());
            hex::encode(mac.finalize().into_bytes())
        }
    }
}

// ---------------------------------------------------------------------------
// Signature header parsing
// ---------------------------------------------------------------------------

/// Parsed components of the `X-Aframp-Signature` header.
///
/// Format: `algorithm=HMAC-SHA256,timestamp=<unix_ts>,signature=<hex>`
#[derive(Debug)]
pub struct ParsedSignature {
    pub algorithm: HmacAlgorithm,
    pub timestamp: i64,
    pub signature: String,
}

fn parse_signature_header(header: &str) -> Option<ParsedSignature> {
    let mut algorithm = None;
    let mut timestamp = None;
    let mut signature = None;

    for part in header.split(',') {
        let mut kv = part.splitn(2, '=');
        let key = kv.next()?.trim();
        let val = kv.next()?.trim();
        match key {
            "algorithm" => algorithm = HmacAlgorithm::parse(val),
            "timestamp" => timestamp = val.parse::<i64>().ok(),
            "signature" => signature = Some(val.to_string()),
            _ => {}
        }
    }

    Some(ParsedSignature {
        algorithm: algorithm?,
        timestamp: timestamp?,
        signature: signature?,
    })
}

// ---------------------------------------------------------------------------
// Constant-time comparison
// ---------------------------------------------------------------------------

/// Compare two hex signature strings in constant time to prevent timing attacks.
fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes()
        .zip(b.bytes())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------

/// Axum middleware that verifies HMAC request signatures.
///
/// Attach to any route group that requires signed requests:
/// ```rust,ignore
/// Router::new()
///     .route("/onramp/initiate", post(handler))
///     .layer(axum::middleware::from_fn_with_state(
///         hmac_state,
///         hmac_signing_middleware,
///     ))
/// ```
pub async fn hmac_signing_middleware(
    State(state): State<HmacSigningState>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let endpoint = req.uri().path().to_string();

    // ── 1. Extract X-Aframp-Signature header ─────────────────────────────────
    let sig_header = match req.headers().get("x-aframp-signature").and_then(|v| v.to_str().ok()) {
        Some(v) => v.to_string(),
        None => {
            if !state.enforce {
                warn!(endpoint = %endpoint, "HMAC signature missing — enforcement disabled, passing through");
                return next.run(req).await;
            }
            return signing_401("MISSING_SIGNATURE", "X-Aframp-Signature header is required");
        }
    };

    // ── 2. Parse signature header ─────────────────────────────────────────────
    let parsed = match parse_signature_header(&sig_header) {
        Some(p) => p,
        None => {
            return signing_401(
                "INVALID_SIGNATURE_FORMAT",
                "X-Aframp-Signature must be: algorithm=HMAC-SHA256,timestamp=<ts>,signature=<hex>",
            );
        }
    };

    // ── 3. Extract key-id ─────────────────────────────────────────────────────
    let key_id = match req.headers().get("x-aframp-key-id").and_then(|v| v.to_str().ok()) {
        Some(v) => v.to_string(),
        None => return signing_401("MISSING_KEY_ID", "X-Aframp-Key-Id header is required"),
    };

    // ── 4. Resolve API secret ─────────────────────────────────────────────────
    let api_secret = match (state.key_resolver)(&key_id) {
        Some(s) => s,
        None => {
            warn!(key_id = %key_id, endpoint = %endpoint, "Unknown key-id in HMAC verification");
            return signing_401("UNKNOWN_KEY_ID", "The provided X-Aframp-Key-Id is not recognised");
        }
    };

    // ── 5. Buffer body ────────────────────────────────────────────────────────
    let (parts, body) = req.into_parts();
    let body_bytes = match to_bytes(body, MAX_BODY_BYTES + 1).await {
        Ok(b) => b,
        Err(_) => return signing_401("BODY_READ_ERROR", "Failed to read request body for signing"),
    };
    if body_bytes.len() > MAX_BODY_BYTES {
        return signing_401("BODY_TOO_LARGE", "Request body exceeds the 1 MiB signing limit");
    }

    // ── 6. Build canonical request ────────────────────────────────────────────
    let body_hash = sha256_hex(&body_bytes);
    let query = parts.uri.query().unwrap_or("");
    let canonical = match build_canonical_request(
        parts.method.as_str(),
        parts.uri.path(),
        query,
        &parts.headers,
        &body_hash,
    ) {
        Ok(c) => c,
        Err(_) => {
            return signing_401(
                "MISSING_REQUIRED_HEADER",
                &format!(
                    "Canonical request requires headers: {}",
                    REQUIRED_HEADERS.join(", ")
                ),
            );
        }
    };

    // ── 7. Derive signing key and verify ──────────────────────────────────────
    let signing_key = derive_signing_key(&api_secret);
    let expected = compute_signature(parsed.algorithm, &signing_key, &canonical);

    if !constant_time_eq(&expected, &parsed.signature) {
        warn!(
            key_id = %key_id,
            endpoint = %endpoint,
            algorithm = parsed.algorithm.as_str(),
            "HMAC signature mismatch"
        );
        return signing_401("SIGNATURE_MISMATCH", "Request signature verification failed");
    }

    debug!(
        key_id = %key_id,
        endpoint = %endpoint,
        algorithm = parsed.algorithm.as_str(),
        "HMAC signature verified"
    );

    let req = Request::from_parts(parts, Body::from(body_bytes));
    next.run(req).await
}

// ---------------------------------------------------------------------------
// Public signing helper (reference implementation for internal consumers)
// ---------------------------------------------------------------------------

/// Sign a request and return the value to place in `X-Aframp-Signature`.
///
/// This is the Rust reference implementation.  Consumers can call this
/// directly or use it as a guide for other languages.
///
/// ```rust
/// use Bitmesh_backend::middleware::hmac_signing::{sign_request, HmacAlgorithm};
///
/// let header_value = sign_request(
///     HmacAlgorithm::Sha256,
///     "POST",
///     "/api/onramp/initiate",
///     "",
///     &[("content-type", "application/json"),
///       ("x-aframp-key-id", "key_abc"),
///       ("x-aframp-timestamp", "1700000000")],
///     br#"{"amount":"100"}"#,
///     b"my-api-secret",
/// );
/// // header_value == "algorithm=HMAC-SHA256,timestamp=1700000000,signature=<hex>"
/// ```
pub fn sign_request(
    algorithm: HmacAlgorithm,
    method: &str,
    path: &str,
    query: &str,
    headers: &[(&str, &str)],
    body: &[u8],
    api_secret: &[u8],
) -> String {
    let mut header_map = axum::http::HeaderMap::new();
    for (name, value) in headers {
        if let (Ok(n), Ok(v)) = (
            axum::http::HeaderName::from_bytes(name.as_bytes()),
            axum::http::HeaderValue::from_str(value),
        ) {
            header_map.insert(n, v);
        }
    }

    let body_hash = sha256_hex(body);
    let canonical = build_canonical_request(method, path, query, &header_map, &body_hash)
        .expect("all required headers provided");

    let signing_key = derive_signing_key(api_secret);
    let signature = compute_signature(algorithm, &signing_key, &canonical);

    let timestamp = header_map
        .get("x-aframp-timestamp")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("0");

    format!(
        "algorithm={},timestamp={},signature={}",
        algorithm.as_str(),
        timestamp,
        signature
    )
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"test-api-secret-for-aframp";

    fn make_headers(ts: &str) -> axum::http::HeaderMap {
        let mut m = axum::http::HeaderMap::new();
        m.insert("content-type", "application/json".parse().unwrap());
        m.insert("x-aframp-key-id", "key_test".parse().unwrap());
        m.insert("x-aframp-timestamp", ts.parse().unwrap());
        m
    }

    // ── Canonical request ────────────────────────────────────────────────────

    #[test]
    fn canonical_method_is_uppercased() {
        let h = make_headers("1700000000");
        let c = build_canonical_request("post", "/api/test", "", &h, "abc123").unwrap();
        assert!(c.starts_with("POST\n"));
    }

    #[test]
    fn canonical_path_is_lowercased_and_trailing_slash_stripped() {
        let h = make_headers("1700000000");
        let c = build_canonical_request("GET", "/API/Onramp/", "", &h, "abc").unwrap();
        let lines: Vec<&str> = c.lines().collect();
        assert_eq!(lines[1], "/api/onramp");
    }

    #[test]
    fn canonical_root_path_not_stripped() {
        let h = make_headers("1700000000");
        let c = build_canonical_request("GET", "/", "", &h, "abc").unwrap();
        let lines: Vec<&str> = c.lines().collect();
        assert_eq!(lines[1], "/");
    }

    #[test]
    fn canonical_query_params_sorted() {
        let h = make_headers("1700000000");
        let c = build_canonical_request("GET", "/rates", "to=CNGN&from=KES", &h, "abc").unwrap();
        let lines: Vec<&str> = c.lines().collect();
        assert_eq!(lines[2], "from=KES&to=CNGN");
    }

    #[test]
    fn canonical_empty_query_is_empty_line() {
        let h = make_headers("1700000000");
        let c = build_canonical_request("POST", "/transfer", "", &h, "abc").unwrap();
        let lines: Vec<&str> = c.lines().collect();
        assert_eq!(lines[2], "");
    }

    #[test]
    fn canonical_missing_required_header_returns_err() {
        let mut h = axum::http::HeaderMap::new();
        h.insert("content-type", "application/json".parse().unwrap());
        // x-aframp-key-id and x-aframp-timestamp missing
        let result = build_canonical_request("POST", "/test", "", &h, "abc");
        assert!(result.is_err());
    }

    #[test]
    fn canonical_includes_all_required_headers() {
        let h = make_headers("1700000000");
        let c = build_canonical_request("POST", "/test", "", &h, "deadbeef").unwrap();
        assert!(c.contains("content-type:application/json"));
        assert!(c.contains("x-aframp-key-id:key_test"));
        assert!(c.contains("x-aframp-timestamp:1700000000"));
    }

    #[test]
    fn canonical_body_hash_is_last_line() {
        let h = make_headers("1700000000");
        let hash = "cafebabe";
        let c = build_canonical_request("POST", "/test", "", &h, hash).unwrap();
        assert!(c.ends_with(hash));
    }

    // ── Body hashing ─────────────────────────────────────────────────────────

    #[test]
    fn sha256_hex_of_empty_body_is_known_value() {
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let h = sha256_hex(b"");
        assert_eq!(h, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }

    #[test]
    fn sha256_hex_is_deterministic() {
        assert_eq!(sha256_hex(b"hello"), sha256_hex(b"hello"));
    }

    // ── HKDF key derivation ──────────────────────────────────────────────────

    #[test]
    fn derive_signing_key_is_deterministic() {
        let k1 = derive_signing_key(SECRET);
        let k2 = derive_signing_key(SECRET);
        assert_eq!(k1, k2);
    }

    #[test]
    fn derive_signing_key_differs_for_different_secrets() {
        let k1 = derive_signing_key(b"secret-a");
        let k2 = derive_signing_key(b"secret-b");
        assert_ne!(k1, k2);
    }

    #[test]
    fn derived_key_is_not_equal_to_raw_secret() {
        let k = derive_signing_key(SECRET);
        assert_ne!(k, SECRET);
    }

    // ── Signature computation ────────────────────────────────────────────────

    #[test]
    fn sha256_and_sha512_produce_different_signatures() {
        let key = derive_signing_key(SECRET);
        let canonical = "POST\n/test\n\ncontent-type:application/json\nx-aframp-key-id:k\nx-aframp-timestamp:1\nabc";
        let s256 = compute_signature(HmacAlgorithm::Sha256, &key, canonical);
        let s512 = compute_signature(HmacAlgorithm::Sha512, &key, canonical);
        assert_ne!(s256, s512);
    }

    #[test]
    fn signature_is_deterministic_for_same_inputs() {
        let key = derive_signing_key(SECRET);
        let canonical = "POST\n/test\n\ncontent-type:application/json\nx-aframp-key-id:k\nx-aframp-timestamp:1\nabc";
        assert_eq!(
            compute_signature(HmacAlgorithm::Sha256, &key, canonical),
            compute_signature(HmacAlgorithm::Sha256, &key, canonical),
        );
    }

    #[test]
    fn signature_changes_when_canonical_changes() {
        let key = derive_signing_key(SECRET);
        let c1 = "POST\n/test\n\ncontent-type:application/json\nx-aframp-key-id:k\nx-aframp-timestamp:1\nabc";
        let c2 = "POST\n/test\n\ncontent-type:application/json\nx-aframp-key-id:k\nx-aframp-timestamp:1\nxyz";
        assert_ne!(
            compute_signature(HmacAlgorithm::Sha256, &key, c1),
            compute_signature(HmacAlgorithm::Sha256, &key, c2),
        );
    }

    // ── Signature header parsing ─────────────────────────────────────────────

    #[test]
    fn parse_valid_sha256_header() {
        let h = "algorithm=HMAC-SHA256,timestamp=1700000000,signature=deadbeef";
        let p = parse_signature_header(h).unwrap();
        assert_eq!(p.algorithm, HmacAlgorithm::Sha256);
        assert_eq!(p.timestamp, 1700000000);
        assert_eq!(p.signature, "deadbeef");
    }

    #[test]
    fn parse_valid_sha512_header() {
        let h = "algorithm=HMAC-SHA512,timestamp=1700000001,signature=cafebabe";
        let p = parse_signature_header(h).unwrap();
        assert_eq!(p.algorithm, HmacAlgorithm::Sha512);
    }

    #[test]
    fn parse_missing_algorithm_returns_none() {
        let h = "timestamp=1700000000,signature=deadbeef";
        assert!(parse_signature_header(h).is_none());
    }

    #[test]
    fn parse_unknown_algorithm_returns_none() {
        let h = "algorithm=HMAC-MD5,timestamp=1700000000,signature=deadbeef";
        assert!(parse_signature_header(h).is_none());
    }

    // ── Constant-time comparison ─────────────────────────────────────────────

    #[test]
    fn constant_time_eq_same_strings() {
        assert!(constant_time_eq("abcdef", "abcdef"));
    }

    #[test]
    fn constant_time_eq_different_strings() {
        assert!(!constant_time_eq("abcdef", "abcxyz"));
    }

    #[test]
    fn constant_time_eq_different_lengths() {
        assert!(!constant_time_eq("abc", "abcd"));
    }

    // ── sign_request helper ──────────────────────────────────────────────────

    #[test]
    fn sign_request_produces_parseable_header() {
        let hdr = sign_request(
            HmacAlgorithm::Sha256,
            "POST",
            "/api/onramp/initiate",
            "",
            &[
                ("content-type", "application/json"),
                ("x-aframp-key-id", "key_abc"),
                ("x-aframp-timestamp", "1700000000"),
            ],
            br#"{"amount":"100"}"#,
            SECRET,
        );
        let parsed = parse_signature_header(&hdr).unwrap();
        assert_eq!(parsed.algorithm, HmacAlgorithm::Sha256);
        assert_eq!(parsed.timestamp, 1700000000);
        assert!(!parsed.signature.is_empty());
    }

    #[test]
    fn sign_request_sha256_and_sha512_differ() {
        let headers = &[
            ("content-type", "application/json"),
            ("x-aframp-key-id", "key_abc"),
            ("x-aframp-timestamp", "1700000000"),
        ];
        let body = br#"{"amount":"100"}"#;
        let h256 = sign_request(HmacAlgorithm::Sha256, "POST", "/test", "", headers, body, SECRET);
        let h512 = sign_request(HmacAlgorithm::Sha512, "POST", "/test", "", headers, body, SECRET);
        assert_ne!(h256, h512);
    }

    #[test]
    fn tampered_body_produces_different_signature() {
        let headers = &[
            ("content-type", "application/json"),
            ("x-aframp-key-id", "key_abc"),
            ("x-aframp-timestamp", "1700000000"),
        ];
        let original = sign_request(
            HmacAlgorithm::Sha256, "POST", "/test", "", headers,
            br#"{"amount":"100"}"#, SECRET,
        );
        let tampered = sign_request(
            HmacAlgorithm::Sha256, "POST", "/test", "", headers,
            br#"{"amount":"9999"}"#, SECRET,
        );
        assert_ne!(original, tampered);
    }

    #[test]
    fn tampered_header_produces_different_signature() {
        let headers_original = &[
            ("content-type", "application/json"),
            ("x-aframp-key-id", "key_abc"),
            ("x-aframp-timestamp", "1700000000"),
        ];
        let headers_tampered = &[
            ("content-type", "application/json"),
            ("x-aframp-key-id", "key_EVIL"),
            ("x-aframp-timestamp", "1700000000"),
        ];
        let body = br#"{"amount":"100"}"#;
        let s1 = sign_request(HmacAlgorithm::Sha256, "POST", "/test", "", headers_original, body, SECRET);
        let s2 = sign_request(HmacAlgorithm::Sha256, "POST", "/test", "", headers_tampered, body, SECRET);
        assert_ne!(s1, s2);
    }
}
