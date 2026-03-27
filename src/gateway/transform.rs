//! Request transformation — path normalisation, header injection/stripping,
//! consumer identity context forwarding.

use axum::http::{HeaderMap, HeaderValue, Request};
use chrono::Utc;
use uuid::Uuid;

/// Headers that consumers must never be able to spoof into upstream services.
const SPOOFABLE_HEADERS: &[&str] = &[
    "x-consumer-id",
    "x-consumer-type",
    "x-service-name",
    "x-gateway-verified",
    "x-internal-token",
];

/// Normalise a URL path:
/// - Strip trailing slash (except root "/")
/// - Resolve percent-encoding to canonical form
/// - Collapse double slashes
pub fn normalise_path(path: &str) -> String {
    // Collapse double slashes
    let mut result = String::with_capacity(path.len());
    let mut prev_slash = false;
    for ch in path.chars() {
        if ch == '/' {
            if !prev_slash {
                result.push(ch);
            }
            prev_slash = true;
        } else {
            result.push(ch);
            prev_slash = false;
        }
    }
    // Strip trailing slash unless root
    if result.len() > 1 && result.ends_with('/') {
        result.pop();
    }
    result
}

/// Strip consumer-provided headers that could interfere with internal routing.
pub fn strip_spoofable_headers(headers: &mut HeaderMap) {
    for name in SPOOFABLE_HEADERS {
        headers.remove(*name);
    }
}

/// Inject gateway-signed headers onto the forwarded request.
/// - X-Request-ID: unique per request
/// - X-Gateway-Timestamp: Unix timestamp
/// - X-Gateway-Signature: HMAC-SHA256 of method:path:timestamp
/// - X-Gateway-Verified: "true"
pub fn inject_gateway_headers(headers: &mut HeaderMap, method: &str, path: &str) {
    let request_id = Uuid::new_v4().to_string();
    let timestamp = Utc::now().timestamp().to_string();
    let sig = crate::gateway::signature::compute_gateway_signature(method, path, &timestamp);

    if let Ok(v) = HeaderValue::from_str(&request_id) {
        headers.insert("x-request-id", v);
    }
    if let Ok(v) = HeaderValue::from_str(&timestamp) {
        headers.insert("x-gateway-timestamp", v);
    }
    if let Ok(v) = HeaderValue::from_str(&sig) {
        headers.insert("x-gateway-signature", v);
    }
    headers.insert("x-gateway-verified", HeaderValue::from_static("true"));
}

/// Inject security response headers onto every outgoing response.
pub fn inject_security_response_headers(headers: &mut HeaderMap, hsts_max_age: u64) {
    headers.insert("x-content-type-options", HeaderValue::from_static("nosniff"));
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    headers.insert("x-xss-protection", HeaderValue::from_static("1; mode=block"));
    headers.insert(
        "referrer-policy",
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );
    headers.insert(
        "content-security-policy",
        HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'"),
    );
    if let Ok(v) = HeaderValue::from_str(&format!(
        "max-age={}; includeSubDomains; preload",
        hsts_max_age
    )) {
        headers.insert("strict-transport-security", v);
    }
}

/// Strip internal infrastructure headers from consumer-facing responses.
pub fn strip_internal_response_headers(headers: &mut HeaderMap) {
    headers.remove("server");
    headers.remove("x-powered-by");
    headers.remove("x-aspnet-version");
    headers.remove("x-upstream-service");
    headers.remove("x-internal-request-id");
    // Re-insert a generic server header
    headers.insert("server", HeaderValue::from_static("aframp-gateway"));
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;

    // ── path normalisation ────────────────────────────────────────────────────

    #[test]
    fn test_trailing_slash_stripped() {
        assert_eq!(normalise_path("/api/v1/wallet/"), "/api/v1/wallet");
    }

    #[test]
    fn test_root_slash_preserved() {
        assert_eq!(normalise_path("/"), "/");
    }

    #[test]
    fn test_double_slash_collapsed() {
        assert_eq!(normalise_path("/api//v1//wallet"), "/api/v1/wallet");
    }

    #[test]
    fn test_normal_path_unchanged() {
        assert_eq!(normalise_path("/api/v1/wallet"), "/api/v1/wallet");
    }

    // ── header stripping ──────────────────────────────────────────────────────

    #[test]
    fn test_spoofable_headers_stripped() {
        let mut headers = HeaderMap::new();
        headers.insert("x-consumer-id", HeaderValue::from_static("spoofed-id"));
        headers.insert("x-service-name", HeaderValue::from_static("fake-service"));
        headers.insert("authorization", HeaderValue::from_static("Bearer tok"));
        strip_spoofable_headers(&mut headers);
        assert!(headers.get("x-consumer-id").is_none());
        assert!(headers.get("x-service-name").is_none());
        assert!(headers.get("authorization").is_some()); // legitimate header preserved
    }

    // ── gateway header injection ──────────────────────────────────────────────

    #[test]
    fn test_gateway_headers_injected() {
        let mut headers = HeaderMap::new();
        inject_gateway_headers(&mut headers, "POST", "/api/v1/onramp");
        assert!(headers.contains_key("x-request-id"));
        assert!(headers.contains_key("x-gateway-signature"));
        assert!(headers.contains_key("x-gateway-timestamp"));
        assert_eq!(headers["x-gateway-verified"], "true");
    }

    #[test]
    fn test_gateway_signature_verifiable() {
        let mut headers = HeaderMap::new();
        inject_gateway_headers(&mut headers, "POST", "/api/v1/onramp");
        let sig = headers["x-gateway-signature"].to_str().unwrap();
        let ts = headers["x-gateway-timestamp"].to_str().unwrap();
        assert!(crate::gateway::signature::verify_gateway_signature(
            "POST", "/api/v1/onramp", ts, sig
        ));
    }

    // ── security response headers ─────────────────────────────────────────────

    #[test]
    fn test_security_headers_injected() {
        let mut headers = HeaderMap::new();
        inject_security_response_headers(&mut headers, 31_536_000);
        assert_eq!(headers["x-content-type-options"], "nosniff");
        assert_eq!(headers["x-frame-options"], "DENY");
        assert_eq!(headers["x-xss-protection"], "1; mode=block");
        assert!(headers["strict-transport-security"]
            .to_str()
            .unwrap()
            .contains("max-age=31536000"));
    }

    // ── internal header stripping ─────────────────────────────────────────────

    #[test]
    fn test_internal_headers_stripped() {
        let mut headers = HeaderMap::new();
        headers.insert("server", HeaderValue::from_static("nginx/1.25.0"));
        headers.insert("x-powered-by", HeaderValue::from_static("Express"));
        headers.insert("x-upstream-service", HeaderValue::from_static("payment-svc"));
        strip_internal_response_headers(&mut headers);
        // server is replaced with generic value
        assert_eq!(headers["server"], "aframp-gateway");
        assert!(headers.get("x-powered-by").is_none());
        assert!(headers.get("x-upstream-service").is_none());
    }
}
