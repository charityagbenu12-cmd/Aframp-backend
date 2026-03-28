//! Unit and integration tests for the OAuth 2.0 authorization server.
//!
//! Integration tests that require a live database/Redis are marked `#[ignore]`
//! and can be run with: `cargo test --features database -- --ignored`

#[cfg(test)]
mod unit {
    use crate::oauth::{
        pkce::{compute_s256_challenge, validate_challenge_method, validate_code_verifier, verify_pkce_s256},
        token::{IntrospectionResponse, OAuthClaims, ACCESS_TOKEN_TTL_SECS},
        types::{
            is_supported_scope, parse_scope_string, scope_vec_to_string, ClientType, GrantType,
            OAuthClient, OAuthError, SUPPORTED_SCOPES,
        },
    };
    use chrono::Utc;
    use uuid::Uuid;

    // ── PKCE tests ────────────────────────────────────────────────────────────

    #[test]
    fn pkce_s256_rfc_test_vector() {
        // RFC 7636 Appendix B
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let expected = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert_eq!(compute_s256_challenge(verifier), expected);
    }

    #[test]
    fn pkce_verify_correct_verifier() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = compute_s256_challenge(verifier);
        assert!(verify_pkce_s256(verifier, &challenge).is_ok());
    }

    #[test]
    fn pkce_verify_wrong_verifier_rejected() {
        let challenge = compute_s256_challenge("correct_verifier_long_enough_here_abcdefgh");
        let result = verify_pkce_s256("wrong_verifier_long_enough_here_abcdefghij", &challenge);
        assert!(matches!(result, Err(OAuthError::InvalidGrant(_))));
    }

    #[test]
    fn pkce_plain_method_rejected() {
        assert!(validate_challenge_method("plain").is_err());
    }

    #[test]
    fn pkce_s256_method_accepted() {
        assert!(validate_challenge_method("S256").is_ok());
    }

    #[test]
    fn pkce_verifier_too_short_rejected() {
        assert!(validate_code_verifier("short").is_err());
    }

    #[test]
    fn pkce_verifier_too_long_rejected() {
        assert!(validate_code_verifier(&"a".repeat(129)).is_err());
    }

    #[test]
    fn pkce_verifier_invalid_chars_rejected() {
        let bad = format!("{}@", "a".repeat(43));
        assert!(validate_code_verifier(&bad).is_err());
    }

    #[test]
    fn pkce_verifier_valid_min_length() {
        let verifier = "a".repeat(43);
        assert!(validate_code_verifier(&verifier).is_ok());
    }

    #[test]
    fn pkce_verifier_valid_max_length() {
        let verifier = "a".repeat(128);
        assert!(validate_code_verifier(&verifier).is_ok());
    }

    // ── Client validation tests ───────────────────────────────────────────────

    fn make_client(client_type: ClientType, grants: Vec<&str>, scopes: Vec<&str>) -> OAuthClient {
        OAuthClient {
            id: Uuid::new_v4(),
            client_id: "test-client".to_string(),
            client_secret_hash: None,
            client_name: "Test Client".to_string(),
            client_type,
            allowed_grant_types: grants.into_iter().map(String::from).collect(),
            allowed_scopes: scopes.into_iter().map(String::from).collect(),
            redirect_uris: vec!["https://example.com/callback".to_string()],
            status: "active".to_string(),
            created_by: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn client_supports_grant_true() {
        let client = make_client(
            ClientType::Confidential,
            vec!["client_credentials"],
            vec!["wallet:read"],
        );
        assert!(client.supports_grant(&GrantType::ClientCredentials));
    }

    #[test]
    fn client_supports_grant_false() {
        let client = make_client(
            ClientType::Public,
            vec!["authorization_code"],
            vec!["wallet:read"],
        );
        assert!(!client.supports_grant(&GrantType::ClientCredentials));
    }

    #[test]
    fn client_validate_scopes_valid() {
        let client = make_client(
            ClientType::Public,
            vec!["authorization_code"],
            vec!["wallet:read", "transactions:read"],
        );
        assert!(client
            .validate_scopes(&["wallet:read".to_string()])
            .is_ok());
    }

    #[test]
    fn client_validate_scopes_invalid() {
        let client = make_client(
            ClientType::Public,
            vec!["authorization_code"],
            vec!["wallet:read"],
        );
        let result = client.validate_scopes(&["admin".to_string()]);
        assert!(matches!(result, Err(OAuthError::InvalidScope(_))));
    }

    #[test]
    fn client_has_redirect_uri_true() {
        let client = make_client(ClientType::Public, vec![], vec![]);
        assert!(client.has_redirect_uri("https://example.com/callback"));
    }

    #[test]
    fn client_has_redirect_uri_false() {
        let client = make_client(ClientType::Public, vec![], vec![]);
        assert!(!client.has_redirect_uri("https://evil.com/callback"));
    }

    // ── Scope helpers ─────────────────────────────────────────────────────────

    #[test]
    fn parse_scope_string_splits_on_whitespace() {
        let scopes = parse_scope_string("wallet:read transactions:read");
        assert_eq!(scopes, vec!["wallet:read", "transactions:read"]);
    }

    #[test]
    fn parse_scope_string_empty() {
        assert!(parse_scope_string("").is_empty());
    }

    #[test]
    fn scope_vec_to_string_joins_with_space() {
        let scopes = vec!["wallet:read".to_string(), "transactions:read".to_string()];
        assert_eq!(scope_vec_to_string(&scopes), "wallet:read transactions:read");
    }

    #[test]
    fn supported_scopes_contains_expected() {
        assert!(is_supported_scope("wallet:read"));
        assert!(is_supported_scope("admin"));
        assert!(!is_supported_scope("unknown:scope"));
    }

    // ── Grant type parsing ────────────────────────────────────────────────────

    #[test]
    fn grant_type_from_str_valid() {
        use std::str::FromStr;
        assert_eq!(
            GrantType::from_str("authorization_code").unwrap(),
            GrantType::AuthorizationCode
        );
        assert_eq!(
            GrantType::from_str("client_credentials").unwrap(),
            GrantType::ClientCredentials
        );
        assert_eq!(
            GrantType::from_str("refresh_token").unwrap(),
            GrantType::RefreshToken
        );
    }

    #[test]
    fn grant_type_from_str_invalid() {
        use std::str::FromStr;
        assert!(matches!(
            GrantType::from_str("password"),
            Err(OAuthError::UnsupportedGrantType(_))
        ));
    }

    // ── JWT claim construction ────────────────────────────────────────────────

    #[test]
    fn oauth_claims_expiry_in_future() {
        let now = Utc::now().timestamp();
        let claims = OAuthClaims {
            iss: "https://aframp.com".to_string(),
            sub: "GWALLET".to_string(),
            aud: vec!["aframp-api".to_string()],
            exp: now + ACCESS_TOKEN_TTL_SECS as i64,
            iat: now,
            jti: Uuid::new_v4().to_string(),
            scope: "wallet:read".to_string(),
            client_id: "client-abc".to_string(),
            consumer_type: "user".to_string(),
        };
        assert!(claims.exp > now);
        assert_eq!(claims.exp - claims.iat, ACCESS_TOKEN_TTL_SECS as i64);
    }

    #[test]
    fn introspection_inactive_has_no_fields() {
        let resp = IntrospectionResponse::inactive();
        assert!(!resp.active);
        assert!(resp.scope.is_none());
        assert!(resp.client_id.is_none());
    }

    #[test]
    fn introspection_from_claims_is_active() {
        let now = Utc::now().timestamp();
        let claims = OAuthClaims {
            iss: "https://aframp.com".to_string(),
            sub: "GWALLET".to_string(),
            aud: vec!["aframp-api".to_string()],
            exp: now + 3600,
            iat: now,
            jti: "jti-123".to_string(),
            scope: "wallet:read".to_string(),
            client_id: "client-abc".to_string(),
            consumer_type: "user".to_string(),
        };
        let resp = IntrospectionResponse::from_claims(claims);
        assert!(resp.active);
        assert_eq!(resp.scope.as_deref(), Some("wallet:read"));
        assert_eq!(resp.jti.as_deref(), Some("jti-123"));
    }

    // ── Authorization code expiry ─────────────────────────────────────────────

    #[test]
    fn auth_code_expired_when_past_expiry() {
        use crate::oauth::types::AuthorizationCode;
        let code = AuthorizationCode {
            id: Uuid::new_v4(),
            code: "test".to_string(),
            client_id: "c".to_string(),
            subject: "s".to_string(),
            scope: vec![],
            redirect_uri: "https://example.com".to_string(),
            code_challenge: "challenge".to_string(),
            used: false,
            expires_at: Utc::now() - chrono::Duration::seconds(1),
            created_at: Utc::now(),
        };
        assert!(code.is_expired());
    }

    #[test]
    fn auth_code_not_expired_when_future() {
        use crate::oauth::types::AuthorizationCode;
        let code = AuthorizationCode {
            id: Uuid::new_v4(),
            code: "test".to_string(),
            client_id: "c".to_string(),
            subject: "s".to_string(),
            scope: vec![],
            redirect_uri: "https://example.com".to_string(),
            code_challenge: "challenge".to_string(),
            used: false,
            expires_at: Utc::now() + chrono::Duration::seconds(600),
            created_at: Utc::now(),
        };
        assert!(!code.is_expired());
    }

    // ── OAuthError HTTP status mapping ────────────────────────────────────────

    #[test]
    fn oauth_error_http_status_invalid_client_is_401() {
        assert_eq!(OAuthError::InvalidClient.http_status(), 401);
    }

    #[test]
    fn oauth_error_http_status_access_denied_is_403() {
        assert_eq!(OAuthError::AccessDenied.http_status(), 403);
    }

    #[test]
    fn oauth_error_http_status_invalid_request_is_400() {
        assert_eq!(OAuthError::InvalidRequest("x".to_string()).http_status(), 400);
    }

    #[test]
    fn oauth_error_codes_are_rfc_compliant() {
        assert_eq!(OAuthError::InvalidClient.error_code(), "invalid_client");
        assert_eq!(OAuthError::InvalidRequest("".to_string()).error_code(), "invalid_request");
        assert_eq!(OAuthError::UnsupportedGrantType("".to_string()).error_code(), "unsupported_grant_type");
        assert_eq!(OAuthError::InvalidScope("".to_string()).error_code(), "invalid_scope");
        assert_eq!(OAuthError::AccessDenied.error_code(), "access_denied");
    }
}
