//! Integration tests for the gateway enforcement layer.

#[cfg(test)]
mod integration {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};

    use crate::gateway::{
        config::{cors_origins_for, hsts_max_age, MAX_URL_LENGTH},
        cors::evaluate_cors,
        prescreening::{check_auth_header, check_content_type, check_method, check_url, prescreen, RejectionReason},
        rate_limit::GatewayRateLimiter,
        signature::{compute_gateway_signature, verify_gateway_signature},
        transform::{
            inject_gateway_headers, inject_security_response_headers, normalise_path,
            strip_internal_response_headers, strip_spoofable_headers,
        },
    };
    use axum::http::{HeaderMap, HeaderValue, Response};

    fn req(method: &str, path: &str, headers: &[(&str, &str)]) -> Request<Body> {
        let mut b = Request::builder().method(method).uri(path);
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        b.body(Body::empty()).unwrap()
    }

    // ── TLS enforcement (nginx config validation) ─────────────────────────────
    // TLS 1.0/1.1 rejection is enforced at the nginx layer (config/nginx/nginx.conf).
    // We verify the config contains the correct directives.
    #[test]
    fn test_nginx_config_enforces_tls_12_minimum() {
        let conf = include_str!("../../config/nginx/nginx.conf");
        assert!(conf.contains("ssl_protocols TLSv1.2 TLSv1.3"), "nginx must only allow TLS 1.2+");
        assert!(!conf.contains("TLSv1.0"), "TLS 1.0 must not be listed");
        assert!(!conf.contains("TLSv1.1"), "TLS 1.1 must not be listed");
    }

    #[test]
    fn test_nginx_config_has_strong_ciphers() {
        let conf = include_str!("../../config/nginx/nginx.conf");
        assert!(conf.contains("ssl_ciphers"), "nginx must define cipher suite");
        assert!(conf.contains("ECDHE"), "must include ECDHE ciphers");
        assert!(!conf.contains("RC4"), "RC4 must not be in cipher suite");
        assert!(!conf.contains("DES"), "DES must not be in cipher suite");
    }

    #[test]
    fn test_nginx_config_has_hsts() {
        let conf = include_str!("../../config/nginx/nginx.conf");
        assert!(conf.contains("Strict-Transport-Security"), "HSTS header must be configured");
        assert!(conf.contains("includeSubDomains"), "HSTS must include subdomains");
    }

    #[test]
    fn test_nginx_config_http_to_https_redirect() {
        let conf = include_str!("../../config/nginx/nginx.conf");
        assert!(conf.contains("return 301 https://"), "HTTP must redirect to HTTPS with 301");
    }

    #[test]
    fn test_nginx_config_ocsp_stapling() {
        let conf = include_str!("../../config/nginx/nginx.conf");
        assert!(conf.contains("ssl_stapling on"), "OCSP stapling must be enabled");
        assert!(conf.contains("ssl_stapling_verify on"), "OCSP stapling verify must be on");
    }

    // ── Pre-screening rejection scenarios ─────────────────────────────────────

    #[test]
    fn test_missing_auth_rejected() {
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
    fn test_post_without_content_type_rejected() {
        let r = req("POST", "/api/v1/onramp", &[("authorization", "Bearer tok")]);
        assert_eq!(check_content_type(&r), Err(RejectionReason::UnsupportedContentType));
    }

    #[test]
    fn test_valid_request_passes_all_checks() {
        let r = req("POST", "/api/v1/onramp", &[
            ("authorization", "Bearer tok"),
            ("content-type", "application/json"),
        ]);
        assert_eq!(prescreen(&r), Ok(()));
    }

    // ── Security headers on all responses ─────────────────────────────────────

    #[test]
    fn test_all_security_headers_present() {
        let mut headers = HeaderMap::new();
        inject_security_response_headers(&mut headers, 31_536_000);
        assert!(headers.contains_key("x-content-type-options"));
        assert!(headers.contains_key("x-frame-options"));
        assert!(headers.contains_key("x-xss-protection"));
        assert!(headers.contains_key("referrer-policy"));
        assert!(headers.contains_key("content-security-policy"));
        assert!(headers.contains_key("strict-transport-security"));
    }

    #[test]
    fn test_hsts_includes_subdomains() {
        let mut headers = HeaderMap::new();
        inject_security_response_headers(&mut headers, 31_536_000);
        let hsts = headers["strict-transport-security"].to_str().unwrap();
        assert!(hsts.contains("includeSubDomains"));
        assert!(hsts.contains("max-age=31536000"));
    }

    // ── Internal header stripping ─────────────────────────────────────────────

    #[test]
    fn test_internal_headers_stripped_from_response() {
        let mut headers = HeaderMap::new();
        headers.insert("server", HeaderValue::from_static("nginx/1.25.3"));
        headers.insert("x-powered-by", HeaderValue::from_static("Rust"));
        headers.insert("x-upstream-service", HeaderValue::from_static("wallet-svc"));
        strip_internal_response_headers(&mut headers);
        assert_eq!(headers["server"], "aframp-gateway");
        assert!(headers.get("x-powered-by").is_none());
        assert!(headers.get("x-upstream-service").is_none());
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
    fn test_cors_preflight_handled_without_forwarding() {
        std::env::set_var("APP_ENV", "development");
        let r = req("OPTIONS", "/api/v1/wallet", &[("origin", "http://localhost:3000")]);
        let resp = evaluate_cors(&r);
        assert!(resp.is_some());
        assert_eq!(resp.unwrap().status(), StatusCode::NO_CONTENT);
        std::env::remove_var("APP_ENV");
    }

    #[test]
    fn test_no_wildcard_cors_on_any_endpoint() {
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
    fn test_consumer_id_spoofing_stripped() {
        let mut headers = HeaderMap::new();
        headers.insert("x-consumer-id", HeaderValue::from_static("spoofed"));
        headers.insert("x-service-name", HeaderValue::from_static("fake"));
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

    #[test]
    fn test_tampered_gateway_signature_rejected() {
        let sig = compute_gateway_signature("POST", "/api/v1/onramp", "1700000000");
        assert!(!verify_gateway_signature("GET", "/api/v1/onramp", "1700000000", &sig));
    }

    // ── Gateway-level rate limiting ───────────────────────────────────────────

    #[test]
    fn test_gateway_rate_limit_blocks_after_threshold() {
        let limiter = GatewayRateLimiter::new(5, 100);
        for _ in 0..5 {
            assert!(limiter.check_ip("192.168.1.1").is_ok());
        }
        assert!(limiter.check_ip("192.168.1.1").is_err());
    }

    #[test]
    fn test_gateway_rate_limit_per_key_prefix() {
        let limiter = GatewayRateLimiter::new(1000, 3);
        for _ in 0..3 {
            let _ = limiter.check_key_prefix("ak_test_");
        }
        assert!(limiter.check_key_prefix("ak_test_").is_err());
    }

    // ── Configuration drift detection (config-as-code validation) ────────────

    #[test]
    fn test_gateway_config_has_required_security_directives() {
        let conf = include_str!("../../config/nginx/nginx.conf");
        // All required security directives must be present in version-controlled config
        let required = [
            "ssl_protocols TLSv1.2 TLSv1.3",
            "ssl_stapling on",
            "Strict-Transport-Security",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "return 301 https://",
            "server_tokens off",
        ];
        for directive in &required {
            assert!(conf.contains(directive), "Missing required directive: {}", directive);
        }
    }
}
