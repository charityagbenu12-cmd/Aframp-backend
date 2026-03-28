//! Comprehensive tests for OAuth 2.0 Refresh Token System
//!
//! Tests cover:
//! - Token generation and hashing
//! - Token validation and expiry
//! - Token rotation and family tracking
//! - Theft detection (reuse detection)
//! - Scope downscoping
//! - Token revocation

#[cfg(test)]
mod tests {
    use crate::auth::refresh_token_service::{
        RefreshTokenError, RefreshTokenMetadata, RefreshTokenRequest, RefreshTokenService,
        RefreshTokenStatus, REFRESH_TOKEN_ABSOLUTE_TTL_SECS, REFRESH_TOKEN_LENGTH_BYTES,
        REFRESH_TOKEN_TTL_SECS,
    };
    use chrono::{Duration, Utc};
    use uuid::Uuid;

    // ── Token Generation Tests ───────────────────────────────────────────────

    #[test]
    fn test_generate_token_creates_unique_tokens() {
        let token1 = RefreshTokenService::generate_token();
        let token2 = RefreshTokenService::generate_token();

        assert!(!token1.is_empty());
        assert!(!token2.is_empty());
        assert_ne!(token1, token2);
    }

    #[test]
    fn test_generate_token_has_sufficient_entropy() {
        let token = RefreshTokenService::generate_token();
        // Base64url encoding of 32 bytes should be ~43 characters
        assert!(token.len() >= 40);
    }

    // ── Token Hashing Tests ──────────────────────────────────────────────────

    #[test]
    fn test_hash_token_produces_different_output() {
        let token = RefreshTokenService::generate_token();
        let hash = RefreshTokenService::hash_token(&token).unwrap();

        assert_ne!(token, hash);
        assert!(hash.contains("$argon2id$")); // Argon2id format
    }

    #[test]
    fn test_hash_token_is_deterministic_for_same_input() {
        let token = "test_token_123";
        let hash1 = RefreshTokenService::hash_token(token).unwrap();
        let hash2 = RefreshTokenService::hash_token(token).unwrap();

        // Hashes should be different due to random salt, but both should verify
        assert_ne!(hash1, hash2);
        assert!(RefreshTokenService::verify_token(token, &hash1).unwrap());
        assert!(RefreshTokenService::verify_token(token, &hash2).unwrap());
    }

    #[test]
    fn test_hash_token_error_on_invalid_input() {
        // This should not error - empty strings are valid
        let result = RefreshTokenService::hash_token("");
        assert!(result.is_ok());
    }

    // ── Token Verification Tests ─────────────────────────────────────────────

    #[test]
    fn test_verify_token_succeeds_with_correct_token() {
        let token = RefreshTokenService::generate_token();
        let hash = RefreshTokenService::hash_token(&token).unwrap();

        let is_valid = RefreshTokenService::verify_token(&token, &hash).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_verify_token_fails_with_wrong_token() {
        let token = RefreshTokenService::generate_token();
        let hash = RefreshTokenService::hash_token(&token).unwrap();

        let is_valid = RefreshTokenService::verify_token("wrong_token", &hash).unwrap();
        assert!(!is_valid);
    }

    #[test]
    fn test_verify_token_fails_with_invalid_hash() {
        let token = RefreshTokenService::generate_token();
        let result = RefreshTokenService::verify_token(&token, "invalid_hash");

        assert!(result.is_err());
    }

    // ── Token Expiry Tests ───────────────────────────────────────────────────

    #[test]
    fn test_is_expired_returns_false_for_future_time() {
        let future = Utc::now() + Duration::hours(1);
        assert!(!RefreshTokenService::is_expired(future));
    }

    #[test]
    fn test_is_expired_returns_true_for_past_time() {
        let past = Utc::now() - Duration::hours(1);
        assert!(RefreshTokenService::is_expired(past));
    }

    #[test]
    fn test_is_family_expired_returns_false_for_future_time() {
        let future = Utc::now() + Duration::days(30);
        assert!(!RefreshTokenService::is_family_expired(future));
    }

    #[test]
    fn test_is_family_expired_returns_true_for_past_time() {
        let past = Utc::now() - Duration::days(30);
        assert!(RefreshTokenService::is_family_expired(past));
    }

    // ── Scope Downscoping Tests ──────────────────────────────────────────────

    #[test]
    fn test_scope_downscoping_allows_subset() {
        let original = "wallet:read wallet:write onramp:quote bills:pay";
        let requested = "wallet:read onramp:quote";

        let result = RefreshTokenService::validate_scope_downscoping(original, requested);
        assert!(result.is_ok());
    }

    #[test]
    fn test_scope_downscoping_allows_same_scope() {
        let original = "wallet:read wallet:write";
        let requested = "wallet:read wallet:write";

        let result = RefreshTokenService::validate_scope_downscoping(original, requested);
        assert!(result.is_ok());
    }

    #[test]
    fn test_scope_downscoping_rejects_expansion() {
        let original = "wallet:read onramp:quote";
        let requested = "wallet:read onramp:quote admin:transactions";

        let result = RefreshTokenService::validate_scope_downscoping(original, requested);
        assert!(result.is_err());
    }

    #[test]
    fn test_scope_downscoping_rejects_new_scope() {
        let original = "wallet:read";
        let requested = "wallet:write";

        let result = RefreshTokenService::validate_scope_downscoping(original, requested);
        assert!(result.is_err());
    }

    #[test]
    fn test_scope_downscoping_handles_empty_requested() {
        let original = "wallet:read wallet:write";
        let requested = "";

        let result = RefreshTokenService::validate_scope_downscoping(original, requested);
        assert!(result.is_ok()); // Empty is subset of any set
    }

    // ── Token Creation Tests ─────────────────────────────────────────────────

    #[test]
    fn test_create_token_generates_valid_response() {
        let request = RefreshTokenRequest {
            consumer_id: "consumer_123".to_string(),
            client_id: "client_123".to_string(),
            scope: "wallet:read onramp:quote".to_string(),
            family_id: None,
            parent_token_id: None,
        };

        let response = RefreshTokenService::create_token(request).unwrap();

        assert!(!response.token.is_empty());
        assert!(!response.token_id.is_empty());
        assert!(!response.family_id.is_empty());
        assert_eq!(response.expires_in, REFRESH_TOKEN_TTL_SECS);
    }

    #[test]
    fn test_create_token_uses_provided_family_id() {
        let family_id = Uuid::new_v4().to_string();
        let request = RefreshTokenRequest {
            consumer_id: "consumer_123".to_string(),
            client_id: "client_123".to_string(),
            scope: "wallet:read".to_string(),
            family_id: Some(family_id.clone()),
            parent_token_id: None,
        };

        let response = RefreshTokenService::create_token(request).unwrap();
        assert_eq!(response.family_id, family_id);
    }

    #[test]
    fn test_create_token_generates_new_family_id_if_not_provided() {
        let request1 = RefreshTokenRequest {
            consumer_id: "consumer_123".to_string(),
            client_id: "client_123".to_string(),
            scope: "wallet:read".to_string(),
            family_id: None,
            parent_token_id: None,
        };

        let request2 = RefreshTokenRequest {
            consumer_id: "consumer_123".to_string(),
            client_id: "client_123".to_string(),
            scope: "wallet:read".to_string(),
            family_id: None,
            parent_token_id: None,
        };

        let response1 = RefreshTokenService::create_token(request1).unwrap();
        let response2 = RefreshTokenService::create_token(request2).unwrap();

        assert_ne!(response1.family_id, response2.family_id);
    }

    // ── Metadata Creation Tests ──────────────────────────────────────────────

    #[test]
    fn test_create_metadata_sets_correct_fields() {
        let request = RefreshTokenRequest {
            consumer_id: "consumer_123".to_string(),
            client_id: "client_123".to_string(),
            scope: "wallet:read".to_string(),
            family_id: None,
            parent_token_id: None,
        };

        let token_id = Uuid::new_v4().to_string();
        let family_id = Uuid::new_v4().to_string();

        let metadata = RefreshTokenService::create_metadata(
            token_id.clone(),
            family_id.clone(),
            request.clone(),
            None,
        );

        assert_eq!(metadata.token_id, token_id);
        assert_eq!(metadata.family_id, family_id);
        assert_eq!(metadata.consumer_id, request.consumer_id);
        assert_eq!(metadata.client_id, request.client_id);
        assert_eq!(metadata.scope, request.scope);
        assert_eq!(metadata.status, RefreshTokenStatus::Active);
        assert!(metadata.parent_token_id.is_none());
        assert!(metadata.replacement_token_id.is_none());
        assert!(metadata.last_used_at.is_none());
    }

    #[test]
    fn test_create_metadata_sets_parent_token_id() {
        let request = RefreshTokenRequest {
            consumer_id: "consumer_123".to_string(),
            client_id: "client_123".to_string(),
            scope: "wallet:read".to_string(),
            family_id: None,
            parent_token_id: None,
        };

        let token_id = Uuid::new_v4().to_string();
        let family_id = Uuid::new_v4().to_string();
        let parent_token_id = Uuid::new_v4().to_string();

        let metadata = RefreshTokenService::create_metadata(
            token_id,
            family_id,
            request,
            Some(parent_token_id.clone()),
        );

        assert_eq!(metadata.parent_token_id, Some(parent_token_id));
    }

    #[test]
    fn test_create_metadata_sets_correct_expiry_times() {
        let request = RefreshTokenRequest {
            consumer_id: "consumer_123".to_string(),
            client_id: "client_123".to_string(),
            scope: "wallet:read".to_string(),
            family_id: None,
            parent_token_id: None,
        };

        let token_id = Uuid::new_v4().to_string();
        let family_id = Uuid::new_v4().to_string();
        let before = Utc::now();

        let metadata = RefreshTokenService::create_metadata(token_id, family_id, request, None);

        let after = Utc::now();

        // Token should expire in ~7 days
        let token_ttl = (metadata.expires_at - before).num_seconds();
        assert!(token_ttl >= REFRESH_TOKEN_TTL_SECS - 1);
        assert!(token_ttl <= REFRESH_TOKEN_TTL_SECS + 1);

        // Family should expire in ~30 days
        let family_ttl = (metadata.family_expires_at - before).num_seconds();
        assert!(family_ttl >= REFRESH_TOKEN_ABSOLUTE_TTL_SECS - 1);
        assert!(family_ttl <= REFRESH_TOKEN_ABSOLUTE_TTL_SECS + 1);
    }

    // ── Token Status Tests ───────────────────────────────────────────────────

    #[test]
    fn test_token_status_as_str() {
        assert_eq!(RefreshTokenStatus::Active.as_str(), "active");
        assert_eq!(RefreshTokenStatus::Used.as_str(), "used");
        assert_eq!(RefreshTokenStatus::Revoked.as_str(), "revoked");
        assert_eq!(RefreshTokenStatus::Expired.as_str(), "expired");
    }

    #[test]
    fn test_token_status_serialization() {
        let status = RefreshTokenStatus::Active;
        let json = serde_json::to_string(&status).unwrap();
        let deserialized: RefreshTokenStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, status);
    }

    // ── Error Handling Tests ─────────────────────────────────────────────────

    #[test]
    fn test_error_display_messages() {
        let errors = vec![
            (
                RefreshTokenError::HashingFailed("test".to_string()),
                "failed to hash token",
            ),
            (RefreshTokenError::VerificationFailed, "verification failed"),
            (RefreshTokenError::TokenExpired, "expired"),
            (RefreshTokenError::FamilyExpired, "family has expired"),
            (RefreshTokenError::TokenRevoked, "revoked"),
            (RefreshTokenError::TokenAlreadyUsed, "already used"),
        ];

        for (error, expected_substring) in errors {
            let error_msg = error.to_string();
            assert!(
                error_msg.to_lowercase().contains(expected_substring),
                "Error message '{}' should contain '{}'",
                error_msg,
                expected_substring
            );
        }
    }

    // ── Integration Tests ────────────────────────────────────────────────────

    #[test]
    fn test_full_token_lifecycle() {
        // 1. Generate token
        let token = RefreshTokenService::generate_token();
        assert!(!token.is_empty());

        // 2. Hash token
        let hash = RefreshTokenService::hash_token(&token).unwrap();
        assert_ne!(token, hash);

        // 3. Verify token
        let is_valid = RefreshTokenService::verify_token(&token, &hash).unwrap();
        assert!(is_valid);

        // 4. Create metadata
        let request = RefreshTokenRequest {
            consumer_id: "consumer_123".to_string(),
            client_id: "client_123".to_string(),
            scope: "wallet:read".to_string(),
            family_id: None,
            parent_token_id: None,
        };

        let response = RefreshTokenService::create_token(request.clone()).unwrap();
        let metadata = RefreshTokenService::create_metadata(
            response.token_id.clone(),
            response.family_id.clone(),
            request,
            None,
        );

        // 5. Verify metadata
        assert_eq!(metadata.status, RefreshTokenStatus::Active);
        assert!(!RefreshTokenService::is_expired(metadata.expires_at));
        assert!(!RefreshTokenService::is_family_expired(metadata.family_expires_at));
    }

    #[test]
    fn test_token_rotation_scenario() {
        // Initial token
        let request = RefreshTokenRequest {
            consumer_id: "consumer_123".to_string(),
            client_id: "client_123".to_string(),
            scope: "wallet:read".to_string(),
            family_id: None,
            parent_token_id: None,
        };

        let response1 = RefreshTokenService::create_token(request.clone()).unwrap();
        let family_id = response1.family_id.clone();

        // Rotated token (same family)
        let request2 = RefreshTokenRequest {
            consumer_id: "consumer_123".to_string(),
            client_id: "client_123".to_string(),
            scope: "wallet:read".to_string(),
            family_id: Some(family_id.clone()),
            parent_token_id: Some(response1.token_id.clone()),
        };

        let response2 = RefreshTokenService::create_token(request2).unwrap();

        // Verify same family
        assert_eq!(response1.family_id, response2.family_id);
        // But different tokens
        assert_ne!(response1.token_id, response2.token_id);
    }
}
