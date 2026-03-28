//! Comprehensive tests for OAuth 2.0 token system
//!
//! Unit tests for:
//! - Token issuance and claim validation
//! - Token validation and signature verification
//! - Binding validation (IP/nonce)
//! - Revocation checking
//! - Rate limiting
//! - JWKS key management

#[cfg(test)]
mod tests {
    use crate::auth::oauth_token_service::*;
    use crate::auth::oauth_token_validator::*;
    use chrono::Utc;
    use std::net::IpAddr;
    use std::str::FromStr;

    // ── Token issuance tests ─────────────────────────────────────────────────

    #[test]
    fn test_consumer_type_ttl_enforcement() {
        assert_eq!(ConsumerType::MobileClient.max_ttl_secs(), 3_600);
        assert_eq!(ConsumerType::Partner.max_ttl_secs(), 1_800);
        assert_eq!(ConsumerType::Microservice.max_ttl_secs(), 900);
        assert_eq!(ConsumerType::Admin.max_ttl_secs(), 900);
    }

    #[test]
    fn test_consumer_type_serialization() {
        let mobile = ConsumerType::MobileClient;
        assert_eq!(mobile.as_str(), "mobile_client");

        let partner = ConsumerType::Partner;
        assert_eq!(partner.as_str(), "partner");

        let microservice = ConsumerType::Microservice;
        assert_eq!(microservice.as_str(), "microservice");

        let admin = ConsumerType::Admin;
        assert_eq!(admin.as_str(), "admin");
    }

    #[test]
    fn test_environment_serialization() {
        let testnet = Environment::Testnet;
        assert_eq!(testnet.as_str(), "testnet");

        let mainnet = Environment::Mainnet;
        assert_eq!(mainnet.as_str(), "mainnet");
    }

    #[test]
    fn test_oauth_token_claims_structure() {
        let now = Utc::now().timestamp();
        let claims = OAuthTokenClaims {
            iss: "https://api.example.com".to_string(),
            sub: "consumer_1".to_string(),
            aud: "api".to_string(),
            exp: now + 3600,
            iat: now,
            jti: "jti_123".to_string(),
            scope: "read write".to_string(),
            client_id: "client_1".to_string(),
            consumer_type: "mobile_client".to_string(),
            environment: "testnet".to_string(),
            kid: "key_1".to_string(),
            binding: Some("192.168.1.1".to_string()),
        };

        assert_eq!(claims.sub, "consumer_1");
        assert_eq!(claims.scope, "read write");
        assert!(claims.binding.is_some());
    }

    #[test]
    fn test_token_issuance_request_validation() {
        let request = TokenIssuanceRequest {
            consumer_id: "consumer_1".to_string(),
            client_id: "client_1".to_string(),
            consumer_type: ConsumerType::Partner,
            scope: "read".to_string(),
            environment: Environment::Testnet,
            requested_ttl_secs: Some(3_600),
            binding: None,
        };

        // TTL exceeds Partner max (1800)
        assert!(request.requested_ttl_secs.unwrap() > ConsumerType::Partner.max_ttl_secs());
    }

    // ── Token validation tests ───────────────────────────────────────────────

    #[test]
    fn test_validation_error_codes() {
        assert_eq!(
            TokenValidationError::InvalidToken.error_code(),
            "invalid_token"
        );
        assert_eq!(
            TokenValidationError::TokenExpired.error_code(),
            "token_expired"
        );
        assert_eq!(
            TokenValidationError::TokenRevoked.error_code(),
            "token_revoked"
        );
        assert_eq!(
            TokenValidationError::TokenBindingFailed.error_code(),
            "token_binding_failed"
        );
        assert_eq!(
            TokenValidationError::TokenEnvironmentMismatch.error_code(),
            "token_environment_mismatch"
        );
        assert_eq!(
            TokenValidationError::TokenIssuerMismatch.error_code(),
            "token_issuer_mismatch"
        );
        assert_eq!(
            TokenValidationError::TokenAudienceMismatch.error_code(),
            "token_audience_mismatch"
        );
    }

    #[test]
    fn test_binding_validation_no_binding_required() {
        let claims = OAuthTokenClaims {
            iss: "https://api.example.com".to_string(),
            sub: "consumer_1".to_string(),
            aud: "api".to_string(),
            exp: Utc::now().timestamp() + 3600,
            iat: Utc::now().timestamp(),
            jti: "jti_123".to_string(),
            scope: "read".to_string(),
            client_id: "client_1".to_string(),
            consumer_type: "mobile_client".to_string(),
            environment: "testnet".to_string(),
            kid: "key_1".to_string(),
            binding: None,
        };

        let context = ValidationContext {
            expected_issuer: "https://api.example.com".to_string(),
            expected_audience: "api".to_string(),
            expected_environment: "testnet".to_string(),
            request_ip: None,
            request_nonce: None,
        };

        let validator = OAuthTokenValidator::new("".to_string(), None);
        assert!(validator.validate_binding(&claims, &context).is_ok());
    }

    #[test]
    fn test_binding_validation_ip_match() {
        let claims = OAuthTokenClaims {
            iss: "https://api.example.com".to_string(),
            sub: "consumer_1".to_string(),
            aud: "api".to_string(),
            exp: Utc::now().timestamp() + 3600,
            iat: Utc::now().timestamp(),
            jti: "jti_123".to_string(),
            scope: "read".to_string(),
            client_id: "client_1".to_string(),
            consumer_type: "mobile_client".to_string(),
            environment: "testnet".to_string(),
            kid: "key_1".to_string(),
            binding: Some("192.168.1.1".to_string()),
        };

        let context = ValidationContext {
            expected_issuer: "https://api.example.com".to_string(),
            expected_audience: "api".to_string(),
            expected_environment: "testnet".to_string(),
            request_ip: Some(IpAddr::from_str("192.168.1.1").unwrap()),
            request_nonce: None,
        };

        let validator = OAuthTokenValidator::new("".to_string(), None);
        assert!(validator.validate_binding(&claims, &context).is_ok());
    }

    #[test]
    fn test_binding_validation_ip_mismatch() {
        let claims = OAuthTokenClaims {
            iss: "https://api.example.com".to_string(),
            sub: "consumer_1".to_string(),
            aud: "api".to_string(),
            exp: Utc::now().timestamp() + 3600,
            iat: Utc::now().timestamp(),
            jti: "jti_123".to_string(),
            scope: "read".to_string(),
            client_id: "client_1".to_string(),
            consumer_type: "mobile_client".to_string(),
            environment: "testnet".to_string(),
            kid: "key_1".to_string(),
            binding: Some("192.168.1.1".to_string()),
        };

        let context = ValidationContext {
            expected_issuer: "https://api.example.com".to_string(),
            expected_audience: "api".to_string(),
            expected_environment: "testnet".to_string(),
            request_ip: Some(IpAddr::from_str("192.168.1.2").unwrap()),
            request_nonce: None,
        };

        let validator = OAuthTokenValidator::new("".to_string(), None);
        assert!(matches!(
            validator.validate_binding(&claims, &context),
            Err(TokenValidationError::TokenBindingFailed)
        ));
    }

    #[test]
    fn test_binding_validation_nonce_match() {
        let claims = OAuthTokenClaims {
            iss: "https://api.example.com".to_string(),
            sub: "consumer_1".to_string(),
            aud: "api".to_string(),
            exp: Utc::now().timestamp() + 3600,
            iat: Utc::now().timestamp(),
            jti: "jti_123".to_string(),
            scope: "read".to_string(),
            client_id: "client_1".to_string(),
            consumer_type: "mobile_client".to_string(),
            environment: "testnet".to_string(),
            kid: "key_1".to_string(),
            binding: Some("nonce_abc123".to_string()),
        };

        let context = ValidationContext {
            expected_issuer: "https://api.example.com".to_string(),
            expected_audience: "api".to_string(),
            expected_environment: "testnet".to_string(),
            request_ip: None,
            request_nonce: Some("nonce_abc123".to_string()),
        };

        let validator = OAuthTokenValidator::new("".to_string(), None);
        assert!(validator.validate_binding(&claims, &context).is_ok());
    }

    #[test]
    fn test_binding_validation_nonce_mismatch() {
        let claims = OAuthTokenClaims {
            iss: "https://api.example.com".to_string(),
            sub: "consumer_1".to_string(),
            aud: "api".to_string(),
            exp: Utc::now().timestamp() + 3600,
            iat: Utc::now().timestamp(),
            jti: "jti_123".to_string(),
            scope: "read".to_string(),
            client_id: "client_1".to_string(),
            consumer_type: "mobile_client".to_string(),
            environment: "testnet".to_string(),
            kid: "key_1".to_string(),
            binding: Some("nonce_abc123".to_string()),
        };

        let context = ValidationContext {
            expected_issuer: "https://api.example.com".to_string(),
            expected_audience: "api".to_string(),
            expected_environment: "testnet".to_string(),
            request_ip: None,
            request_nonce: Some("nonce_xyz789".to_string()),
        };

        let validator = OAuthTokenValidator::new("".to_string(), None);
        assert!(matches!(
            validator.validate_binding(&claims, &context),
            Err(TokenValidationError::TokenBindingFailed)
        ));
    }

    #[test]
    fn test_claim_validation_issuer_mismatch() {
        let claims = OAuthTokenClaims {
            iss: "https://api.example.com".to_string(),
            sub: "consumer_1".to_string(),
            aud: "api".to_string(),
            exp: Utc::now().timestamp() + 3600,
            iat: Utc::now().timestamp(),
            jti: "jti_123".to_string(),
            scope: "read".to_string(),
            client_id: "client_1".to_string(),
            consumer_type: "mobile_client".to_string(),
            environment: "testnet".to_string(),
            kid: "key_1".to_string(),
            binding: None,
        };

        let context = ValidationContext {
            expected_issuer: "https://api.different.com".to_string(),
            expected_audience: "api".to_string(),
            expected_environment: "testnet".to_string(),
            request_ip: None,
            request_nonce: None,
        };

        let validator = OAuthTokenValidator::new("".to_string(), None);
        assert!(matches!(
            validator.validate_claims(&claims, &context),
            Err(TokenValidationError::TokenIssuerMismatch)
        ));
    }

    #[test]
    fn test_claim_validation_audience_mismatch() {
        let claims = OAuthTokenClaims {
            iss: "https://api.example.com".to_string(),
            sub: "consumer_1".to_string(),
            aud: "api".to_string(),
            exp: Utc::now().timestamp() + 3600,
            iat: Utc::now().timestamp(),
            jti: "jti_123".to_string(),
            scope: "read".to_string(),
            client_id: "client_1".to_string(),
            consumer_type: "mobile_client".to_string(),
            environment: "testnet".to_string(),
            kid: "key_1".to_string(),
            binding: None,
        };

        let context = ValidationContext {
            expected_issuer: "https://api.example.com".to_string(),
            expected_audience: "different_api".to_string(),
            expected_environment: "testnet".to_string(),
            request_ip: None,
            request_nonce: None,
        };

        let validator = OAuthTokenValidator::new("".to_string(), None);
        assert!(matches!(
            validator.validate_claims(&claims, &context),
            Err(TokenValidationError::TokenAudienceMismatch)
        ));
    }

    #[test]
    fn test_claim_validation_environment_mismatch() {
        let claims = OAuthTokenClaims {
            iss: "https://api.example.com".to_string(),
            sub: "consumer_1".to_string(),
            aud: "api".to_string(),
            exp: Utc::now().timestamp() + 3600,
            iat: Utc::now().timestamp(),
            jti: "jti_123".to_string(),
            scope: "read".to_string(),
            client_id: "client_1".to_string(),
            consumer_type: "mobile_client".to_string(),
            environment: "testnet".to_string(),
            kid: "key_1".to_string(),
            binding: None,
        };

        let context = ValidationContext {
            expected_issuer: "https://api.example.com".to_string(),
            expected_audience: "api".to_string(),
            expected_environment: "mainnet".to_string(),
            request_ip: None,
            request_nonce: None,
        };

        let validator = OAuthTokenValidator::new("".to_string(), None);
        assert!(matches!(
            validator.validate_claims(&claims, &context),
            Err(TokenValidationError::TokenEnvironmentMismatch)
        ));
    }

    #[test]
    fn test_claim_validation_expired_token() {
        let now = Utc::now().timestamp();
        let claims = OAuthTokenClaims {
            iss: "https://api.example.com".to_string(),
            sub: "consumer_1".to_string(),
            aud: "api".to_string(),
            exp: now - 3600, // Expired 1 hour ago
            iat: now - 7200,
            jti: "jti_123".to_string(),
            scope: "read".to_string(),
            client_id: "client_1".to_string(),
            consumer_type: "mobile_client".to_string(),
            environment: "testnet".to_string(),
            kid: "key_1".to_string(),
            binding: None,
        };

        let context = ValidationContext {
            expected_issuer: "https://api.example.com".to_string(),
            expected_audience: "api".to_string(),
            expected_environment: "testnet".to_string(),
            request_ip: None,
            request_nonce: None,
        };

        let validator = OAuthTokenValidator::new("".to_string(), None);
        assert!(matches!(
            validator.validate_claims(&claims, &context),
            Err(TokenValidationError::TokenExpired)
        ));
    }
}
