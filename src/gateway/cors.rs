//! Gateway CORS policy — per-endpoint-category allowlist, no wildcard on auth endpoints.

use axum::http::{HeaderValue, Method, Request, Response, StatusCode};
use axum::body::Body;

use crate::gateway::config::cors_origins_for;

/// Evaluate CORS for a request. Returns None if the request should proceed,
/// or Some(Response) for a preflight reply or a CORS rejection.
pub fn evaluate_cors<B>(req: &Request<B>) -> Option<Response<Body>> {
    let origin = req
        .headers()
        .get("origin")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if origin.is_empty() {
        return None; // Not a CORS request
    }

    let path = req.uri().path();
    let allowed = cors_origins_for(path);
    let origin_ok = allowed.iter().any(|o| o == origin);

    if req.method() == Method::OPTIONS {
        // Preflight — handle at gateway, never forward
        let mut builder = Response::builder().status(StatusCode::NO_CONTENT);
        if origin_ok {
            builder = builder
                .header("Access-Control-Allow-Origin", origin)
                .header("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
                .header("Access-Control-Allow-Headers", "Authorization, X-API-Key, Content-Type, X-Request-ID")
                .header("Access-Control-Allow-Credentials", "true")
                .header("Access-Control-Max-Age", "86400")
                .header("Vary", "Origin");
        }
        return Some(builder.body(Body::empty()).unwrap());
    }

    if !origin_ok {
        tracing::warn!(origin = %origin, path = %path, "CORS: origin not in allowlist");
        crate::gateway::metrics::record_rejection("cors_origin_rejected");
        let resp = Response::builder()
            .status(StatusCode::FORBIDDEN)
            .header("Content-Type", "application/json")
            .body(Body::from(r#"{"error":"cors_origin_not_allowed"}"#))
            .unwrap();
        return Some(resp);
    }

    None // Origin allowed — continue
}

/// Inject CORS headers onto an outgoing response for an allowed origin.
pub fn inject_cors_headers(resp: &mut Response<Body>, origin: &str, path: &str) {
    let allowed = cors_origins_for(path);
    if allowed.iter().any(|o| o == origin) {
        let h = resp.headers_mut();
        if let Ok(v) = HeaderValue::from_str(origin) {
            h.insert("Access-Control-Allow-Origin", v);
        }
        h.insert("Access-Control-Allow-Credentials", HeaderValue::from_static("true"));
        h.insert("Vary", HeaderValue::from_static("Origin"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;

    fn req_with_origin(method: &str, path: &str, origin: &str) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(path)
            .header("origin", origin)
            .body(Body::empty())
            .unwrap()
    }

    #[test]
    fn test_no_origin_passes_through() {
        let r = Request::builder().method("GET").uri("/api/v1/wallet").body(Body::empty()).unwrap();
        assert!(evaluate_cors(&r).is_none());
    }

    #[test]
    fn test_disallowed_origin_rejected() {
        std::env::set_var("APP_ENV", "production");
        let r = req_with_origin("GET", "/api/v1/wallet", "https://evil.com");
        let resp = evaluate_cors(&r);
        assert!(resp.is_some());
        assert_eq!(resp.unwrap().status(), StatusCode::FORBIDDEN);
        std::env::remove_var("APP_ENV");
    }

    #[test]
    fn test_preflight_handled_at_gateway() {
        std::env::set_var("APP_ENV", "development");
        let r = req_with_origin("OPTIONS", "/api/v1/wallet", "http://localhost:3000");
        let resp = evaluate_cors(&r);
        assert!(resp.is_some());
        assert_eq!(resp.unwrap().status(), StatusCode::NO_CONTENT);
        std::env::remove_var("APP_ENV");
    }

    #[test]
    fn test_allowed_origin_passes_through() {
        std::env::set_var("APP_ENV", "development");
        let r = req_with_origin("GET", "/api/v1/wallet", "http://localhost:3000");
        assert!(evaluate_cors(&r).is_none());
        std::env::remove_var("APP_ENV");
    }

    #[test]
    fn test_no_wildcard_on_admin() {
        // Admin endpoint must never allow wildcard — only specific origin
        std::env::set_var("APP_ENV", "production");
        let origins = crate::gateway::config::cors_origins_for("/api/admin/accounts");
        assert!(!origins.contains(&"*".to_string()));
        std::env::remove_var("APP_ENV");
    }
}
