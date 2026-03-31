//! Request pre-screening — validates inbound requests before forwarding.
//! All checks are pure functions so they can be unit-tested without a running server.

use axum::http::{Method, Request};

#[derive(Debug, PartialEq, Eq)]
pub enum RejectionReason {
    MissingAuthHeader,
    UnsupportedContentType,
    BodyTooLarge,
    MalformedUrl,
    PathTraversal,
    NullByteInPath,
    UrlTooLong,
    MethodNotAllowed,
}

impl RejectionReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::MissingAuthHeader => "missing_auth_header",
            Self::UnsupportedContentType => "unsupported_content_type",
            Self::BodyTooLarge => "body_too_large",
            Self::MalformedUrl => "malformed_url",
            Self::PathTraversal => "path_traversal",
            Self::NullByteInPath => "null_byte_in_path",
            Self::UrlTooLong => "url_too_long",
            Self::MethodNotAllowed => "method_not_allowed",
        }
    }
}

/// Validate that the request carries an auth header (Authorization or X-API-Key).
/// Health/readiness endpoints are exempt.
pub fn check_auth_header<B>(req: &Request<B>) -> Result<(), RejectionReason> {
    let path = req.uri().path();
    if path == "/health" || path == "/ready" || path == "/metrics" {
        return Ok(());
    }
    let has_auth = req.headers().contains_key("authorization")
        || req.headers().contains_key("x-api-key");
    if has_auth { Ok(()) } else { Err(RejectionReason::MissingAuthHeader) }
}

/// Validate Content-Type on mutating methods.
pub fn check_content_type<B>(req: &Request<B>) -> Result<(), RejectionReason> {
    let method = req.method();
    if method == Method::POST || method == Method::PUT || method == Method::PATCH {
        let ct = req
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let ok = ct.starts_with("application/json")
            || ct.starts_with("multipart/form-data")
            || ct.starts_with("application/x-www-form-urlencoded");
        if !ok {
            return Err(RejectionReason::UnsupportedContentType);
        }
    }
    Ok(())
}

/// Validate URL length and path safety.
pub fn check_url<B>(req: &Request<B>) -> Result<(), RejectionReason> {
    let uri = req.uri();
    let full = uri.to_string();

    if full.len() > crate::gateway::config::MAX_URL_LENGTH {
        return Err(RejectionReason::UrlTooLong);
    }

    let path = uri.path();

    if path.contains('\0') {
        return Err(RejectionReason::NullByteInPath);
    }

    // Detect path traversal sequences
    if path.contains("../") || path.contains("/..") || path.contains("..\\") {
        return Err(RejectionReason::PathTraversal);
    }

    // Detect percent-encoded traversal: %2e%2e or %2E%2E
    let lower = path.to_lowercase();
    if lower.contains("%2e%2e") || lower.contains("%2f..") || lower.contains("..%2f") {
        return Err(RejectionReason::PathTraversal);
    }

    Ok(())
}

/// Validate HTTP method is in the allowlist for this path.
pub fn check_method<B>(req: &Request<B>) -> Result<(), RejectionReason> {
    let method = req.method().as_str();
    let path = req.uri().path();
    let allowed = crate::gateway::config::allowed_methods_for(path);
    if allowed.contains(&method) {
        Ok(())
    } else {
        Err(RejectionReason::MethodNotAllowed)
    }
}

/// Run all pre-screening checks in order.
pub fn prescreen<B>(req: &Request<B>) -> Result<(), RejectionReason> {
    check_url(req)?;
    check_method(req)?;
    check_auth_header(req)?;
    check_content_type(req)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;

    fn req(method: &str, path: &str, headers: &[(&str, &str)]) -> Request<Body> {
        let mut b = Request::builder().method(method).uri(path);
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        b.body(Body::empty()).unwrap()
    }

    // ── auth header ──────────────────────────────────────────────────────────

    #[test]
    fn test_missing_auth_rejected() {
        let r = req("GET", "/api/v1/wallet", &[]);
        assert_eq!(check_auth_header(&r), Err(RejectionReason::MissingAuthHeader));
    }

    #[test]
    fn test_authorization_header_accepted() {
        let r = req("GET", "/api/v1/wallet", &[("authorization", "Bearer tok")]);
        assert_eq!(check_auth_header(&r), Ok(()));
    }

    #[test]
    fn test_api_key_header_accepted() {
        let r = req("GET", "/api/v1/wallet", &[("x-api-key", "key123")]);
        assert_eq!(check_auth_header(&r), Ok(()));
    }

    #[test]
    fn test_health_exempt_from_auth() {
        let r = req("GET", "/health", &[]);
        assert_eq!(check_auth_header(&r), Ok(()));
    }

    // ── content-type ─────────────────────────────────────────────────────────

    #[test]
    fn test_post_without_content_type_rejected() {
        let r = req("POST", "/api/v1/onramp", &[("authorization", "Bearer tok")]);
        assert_eq!(check_content_type(&r), Err(RejectionReason::UnsupportedContentType));
    }

    #[test]
    fn test_post_with_json_accepted() {
        let r = req("POST", "/api/v1/onramp", &[
            ("authorization", "Bearer tok"),
            ("content-type", "application/json"),
        ]);
        assert_eq!(check_content_type(&r), Ok(()));
    }

    #[test]
    fn test_get_without_content_type_accepted() {
        let r = req("GET", "/api/v1/wallet", &[("authorization", "Bearer tok")]);
        assert_eq!(check_content_type(&r), Ok(()));
    }

    // ── URL validation ────────────────────────────────────────────────────────

    #[test]
    fn test_path_traversal_rejected() {
        let r = req("GET", "/api/v1/../admin/secret", &[("authorization", "Bearer tok")]);
        assert_eq!(check_url(&r), Err(RejectionReason::PathTraversal));
    }

    #[test]
    fn test_encoded_path_traversal_rejected() {
        let r = req("GET", "/api/v1/%2e%2e/admin", &[("authorization", "Bearer tok")]);
        assert_eq!(check_url(&r), Err(RejectionReason::PathTraversal));
    }

    #[test]
    fn test_normal_path_accepted() {
        let r = req("GET", "/api/v1/wallet/balance", &[("authorization", "Bearer tok")]);
        assert_eq!(check_url(&r), Ok(()));
    }

    #[test]
    fn test_url_too_long_rejected() {
        let long_path = format!("/api/v1/{}", "a".repeat(3000));
        let r = req("GET", &long_path, &[("authorization", "Bearer tok")]);
        assert_eq!(check_url(&r), Err(RejectionReason::UrlTooLong));
    }

    // ── method allowlist ──────────────────────────────────────────────────────

    #[test]
    fn test_disallowed_method_rejected() {
        let r = req("TRACE", "/api/v1/wallet", &[("authorization", "Bearer tok")]);
        assert_eq!(check_method(&r), Err(RejectionReason::MethodNotAllowed));
    }

    #[test]
    fn test_allowed_method_accepted() {
        let r = req("GET", "/api/v1/wallet", &[("authorization", "Bearer tok")]);
        assert_eq!(check_method(&r), Ok(()));
    }
}
