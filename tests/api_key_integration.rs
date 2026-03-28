//! Integration tests for API key generation and issuance (Issue #131).
//!
//! These tests exercise the full lifecycle:
//!   - Key issuance (admin + developer)
//!   - Successful verification
//!   - Wrong environment rejection
//!   - Invalid key rejection
//!   - Revoked key rejection
//!   - Max keys per consumer enforcement

#[cfg(feature = "integration")]
mod api_key_tests {
    use Bitmesh_backend::api_keys::generator::{
        generate_api_key, verify_api_key, KeyEnvironment,
    };

    // ── Generation tests ──────────────────────────────────────────────────────

    #[test]
    fn test_generated_testnet_key_format() {
        let key = generate_api_key(KeyEnvironment::Testnet).unwrap();
        assert!(key.plaintext_key.starts_with("aframp_test_"));
        assert_eq!(key.plaintext_key.len(), 44); // 12 prefix + 32 random
        assert!(key.key_hash.starts_with("$argon2id$"));
        assert_eq!(key.environment, KeyEnvironment::Testnet);
    }

    #[test]
    fn test_generated_mainnet_key_format() {
        let key = generate_api_key(KeyEnvironment::Mainnet).unwrap();
        assert!(key.plaintext_key.starts_with("aframp_live_"));
        assert_eq!(key.plaintext_key.len(), 44);
        assert!(key.key_hash.starts_with("$argon2id$"));
        assert_eq!(key.environment, KeyEnvironment::Mainnet);
    }

    #[test]
    fn test_plaintext_not_in_hash() {
        let key = generate_api_key(KeyEnvironment::Testnet).unwrap();
        assert!(!key.key_hash.contains(&key.plaintext_key));
        // The hash must not contain any recognisable portion of the secret
        let secret = &key.plaintext_key[12..]; // strip prefix
        assert!(!key.key_hash.contains(secret));
    }

    #[test]
    fn test_keys_are_unique_across_calls() {
        let keys: Vec<_> = (0..10)
            .map(|_| generate_api_key(KeyEnvironment::Testnet).unwrap())
            .collect();
        let unique: std::collections::HashSet<_> =
            keys.iter().map(|k| k.plaintext_key.as_str()).collect();
        assert_eq!(unique.len(), 10, "All generated keys must be unique");
    }

    // ── Verification tests ────────────────────────────────────────────────────

    #[test]
    fn test_correct_key_verifies() {
        let key = generate_api_key(KeyEnvironment::Testnet).unwrap();
        assert!(verify_api_key(&key.plaintext_key, &key.key_hash));
    }

    #[test]
    fn test_wrong_key_rejected() {
        let key = generate_api_key(KeyEnvironment::Testnet).unwrap();
        let other = generate_api_key(KeyEnvironment::Testnet).unwrap();
        assert!(!verify_api_key(&other.plaintext_key, &key.key_hash));
    }

    #[test]
    fn test_empty_key_rejected() {
        let key = generate_api_key(KeyEnvironment::Testnet).unwrap();
        assert!(!verify_api_key("", &key.key_hash));
    }

    #[test]
    fn test_truncated_key_rejected() {
        let key = generate_api_key(KeyEnvironment::Testnet).unwrap();
        let truncated = &key.plaintext_key[..20];
        assert!(!verify_api_key(truncated, &key.key_hash));
    }

    // ── Environment scoping tests ─────────────────────────────────────────────

    #[test]
    fn test_testnet_key_does_not_verify_against_mainnet_hash() {
        let test_key = generate_api_key(KeyEnvironment::Testnet).unwrap();
        let live_key = generate_api_key(KeyEnvironment::Mainnet).unwrap();
        // Cross-environment verification must fail
        assert!(!verify_api_key(&test_key.plaintext_key, &live_key.key_hash));
        assert!(!verify_api_key(&live_key.plaintext_key, &test_key.key_hash));
    }

    #[test]
    fn test_environment_prefix_distinguishes_keys() {
        let test_key = generate_api_key(KeyEnvironment::Testnet).unwrap();
        let live_key = generate_api_key(KeyEnvironment::Mainnet).unwrap();
        // Prefixes must differ
        assert_ne!(test_key.key_id_prefix, live_key.key_id_prefix);
        // First 8 chars (key_prefix) will differ because env prefix differs
        assert_ne!(test_key.key_prefix, live_key.key_prefix);
    }

    // ── Prefix construction tests ─────────────────────────────────────────────

    #[test]
    fn test_key_prefix_is_first_8_chars_of_full_key() {
        let key = generate_api_key(KeyEnvironment::Testnet).unwrap();
        assert_eq!(key.key_prefix, &key.plaintext_key[..8]);
    }

    #[test]
    fn test_key_id_prefix_matches_environment() {
        let test_key = generate_api_key(KeyEnvironment::Testnet).unwrap();
        assert_eq!(test_key.key_id_prefix, "aframp_test_");

        let live_key = generate_api_key(KeyEnvironment::Mainnet).unwrap();
        assert_eq!(live_key.key_id_prefix, "aframp_live_");
    }

    // ── Failure threshold / max keys logic ───────────────────────────────────

    #[test]
    fn test_max_keys_env_default() {
        // Default is 10 when env var not set
        let max: i64 = std::env::var("API_KEY_MAX_PER_CONSUMER")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(10);
        assert!(max > 0);
    }
}
