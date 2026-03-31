//! Integration tests — API gateway security policy enforcement.

#[cfg(feature = "database")]
mod gateway_integration {
    use axum::body::Body;
    use axum::http::{HeaderMap, HeaderValue, Request, StatusCode};

    use aframp::gateway::{
        config::{cors_origins_for, MAX_URL_LENGTH},
        cors::evaluate_cors,
        prescreening::{check_auth_header, check_content_type, check_method, check_url, prescreen, RejectionReason},
        rate_limit::GatewayRateLimiter,
        signature::{compute_gateway_signature, verify_gateway_signature},
        transform::{
            inject_gateway_headers, inject_security_response_headers,
            normalise_path, strip_internal_response_headers, strip_spoofable_headers,
        },
    };

    fn req(method: &str, path: &str, headers: &[(&str, &str)]) -> Request<Body> {
        let mut b = Request::builder().method(method).uri(path);
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        b.body(Body::empty()).unwrap()
    }

    // ── TLS enforcement (nginx config) ────────────────────────────────────────

    #[test]
    fn test_tls_config_rejects_weak_protocols() {
        let conf = include_str!("../config/nginx/nginx.conf");
        assert!(conf.contains("ssl_protocols TLSv1.2 TLSv1.3"));
        assert!(!conf.contains("TLSv1.0"));
        assert!(!conf.contains("TLSv1.1"));
    }

    #[test]
    fn test_tls_config_no_weak_ciphers() {
        let conf = include_str!("../config/nginx/nginx.conf");
        assert!(!conf.contains("RC4"));
        assert!(!conf.contains(":DES"));
        assert!(!conf.contains("NULL"));
    }

    // ── Pre-screening rejection scenarios ─────────────────────────────────────

    #[test]
    fn test_missing_auth_header_rejected() {
        let r = req("GET", "/api/v1/wallet", &[]);
        assert_eq!(check_auth_header(&r), Err(RejectionReason::MissingAuthHeader));
    }

    #[test]
    fn test_path_traversal_rejected() {
        let r = req("GET", "/api/v1/../admin", &[("authorization", "Bearer tok")]);
        assert_eq!(check_url(&r), Err(RejectionReason::PathTraversal));
    }

    #[test]
    fn test_oversized_url_rejected() {
        let long = format!("/api/v1/{}", "x".repeat(MAX_URL_LENGTH + 1));
        let r = req("GET", &long, &[("authorization", "Bearer tok")]);
        assert_eq!(check_url(&r), Err(RejectionReason::UrlTooLong));
    }

    #[test]
    fn test_disallowed_method_rejected() {
        let r = req("TRACE", "/api/v1/wallet", &[("authorization", "Bearer tok")]);
        assert_eq!(check_method(&r), Err(RejectionReason::MethodNotAllowed));
    }

    #[test]
    fn test_post_missing_content_type_rejected() {
        let r = req("POST", "/api/v1/onramp", &[("authorization", "Bearer tok")]);
        assert_eq!(check_content_type(&r), Err(RejectionReason::UnsupportedContentType));
    }

    #[test]
    fn test_valid_request_passes_prescreening() {
        let r = req("POST", "/api/v1/onramp", &[
            ("authorization", "Bearer tok"),
            ("content-type", "application/json"),
        ]);
        assert_eq!(prescreen(&r), Ok(()));
    }

    // ── Security headers on all responses ─────────────────────────────────────

    #[test]
    fn test_security_headers_present_on_response() {
        let mut headers = HeaderMap::new();
        inject_security_response_headers(&mut headers, 31_536_000);
        assert!(headers.contains_key("x-content-type-options"));
        assert!(headers.contains_key("x-frame-options"));
        assert!(headers.contains_key("x-xss-protection"));
        assert!(headers.contains_key("referrer-policy"));
        assert!(headers.contains_key("content-security-policy"));
        assert!(headers.contains_key("strict-transport-security"));
    }

    // ── CORS enforcement ──────────────────────────────────────────────────────

    #[test]
    fn test_cors_disallowed_origin_rejected() {
        std::env::set_var("APP_ENV", "production");
        let r = req("GET", "/api/v1/wallet", &[
            ("authorization", "Bearer tok"),
            ("origin", "https://attacker.com"),
        ]);
        let resp = evaluate_cors(&r);
        assert!(resp.is_some());
        assert_eq!(resp.unwrap().status(), StatusCode::FORBIDDEN);
        std::env::remove_var("APP_ENV");
    }

    #[test]
    fn test_cors_preflight_handled_at_gateway() {
        std::env::set_var("APP_ENV", "development");
        let r = req("OPTIONS", "/api/v1/wallet", &[("origin", "http://localhost:3000")]);
        let resp = evaluate_cors(&r);
        assert!(resp.is_some());
        assert_eq!(resp.unwrap().status(), StatusCode::NO_CONTENT);
        std::env::remove_var("APP_ENV");
    }

    #[test]
    fn test_no_wildcard_cors_on_authenticated_endpoints() {
        for path in &["/api/admin/accounts", "/api/v1/wallet", "/api/developer/apps"] {
            let origins = cors_origins_for(path);
            assert!(!origins.contains(&"*".to_string()), "wildcard CORS on {}", path);
        }
    }

    // ── Path normalisation ────────────────────────────────────────────────────

    #[test]
    fn test_path_normalisation_trailing_slash() {
        assert_eq!(normalise_path("/api/v1/wallet/"), "/api/v1/wallet");
    }

    #[test]
    fn test_path_normalisation_double_slash() {
        assert_eq!(normalise_path("/api//v1//wallet"), "/api/v1/wallet");
    }

    // ── Consumer identity header spoofing stripped ────────────────────────────

    #[test]
    fn test_consumer_id_spoofing_stripped_before_forwarding() {
        let mut headers = HeaderMap::new();
        headers.insert("x-consumer-id", HeaderValue::from_static("spoofed-id"));
        headers.insert("x-service-name", HeaderValue::from_static("fake-svc"));
        headers.insert("authorization", HeaderValue::from_static("Bearer tok"));
        strip_spoofable_headers(&mut headers);
        assert!(headers.get("x-consumer-id").is_none());
        assert!(headers.get("x-service-name").is_none());
        assert!(headers.get("authorization").is_some());
    }

    // ── Gateway signature verification ────────────────────────────────────────

    #[test]
    fn test_gateway_signature_injected_and_verifiable() {
        let mut headers = HeaderMap::new();
        inject_gateway_headers(&mut headers, "POST", "/api/v1/onramp");
        let sig = headers["x-gateway-signature"].to_str().unwrap();
        let ts = headers["x-gateway-timestamp"].to_str().unwrap();
        assert!(verify_gateway_signature("POST", "/api/v1/onramp", ts, sig));
    }

    // ── Gateway-level rate limiting ───────────────────────────────────────────

    #[test]
    fn test_gateway_rate_limit_blocks_egregious_abuse() {
        let limiter = GatewayRateLimiter::new(5, 100);
        for _ in 0..5 {
            assert!(limiter.check_ip("10.0.0.1").is_ok());
        }
        assert!(limiter.check_ip("10.0.0.1").is_err());
    }

    // ── Configuration drift detection ─────────────────────────────────────────

    #[test]
    fn test_gateway_config_drift_detection() {
        let conf = include_str!("../config/nginx/nginx.conf");
        let required = [
            "ssl_protocols TLSv1.2 TLSv1.3",
            "ssl_stapling on",
            "Strict-Transport-Security",
            "return 301 https://",
            "server_tokens off",
            "X-Frame-Options",
            "X-Content-Type-Options",
        ];
        for directive in &required {
            assert!(conf.contains(directive), "Config drift: missing '{}'", directive);
        }
    }
}
