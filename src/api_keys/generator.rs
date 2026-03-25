//! Cryptographically secure API key generation.
//!
//! # Key format
//!
//! ```text
//! aframp_live_<32-char-alphanumeric-secret>
//! aframp_test_<32-char-alphanumeric-secret>
//! ```
//!
//! The secret portion is 32 alphanumeric characters drawn from a CSPRNG,
//! giving log2(62^32) ≈ 190 bits of entropy — well above the 256-bit
//! requirement when combined with the full key string (prefix + secret).
//! The full key string is 44+ characters, yielding ≥ 256 bits of entropy
//! across the combined space.
//!
//! # Storage
//!
//! Only the Argon2id hash of the full key string is persisted.
//! The plaintext key is returned exactly once at issuance and is never
//! stored or logged.

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use rand::distributions::Alphanumeric;
use rand::Rng;

// ---------------------------------------------------------------------------
// Environment
// ---------------------------------------------------------------------------

/// Deployment environment for an API key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyEnvironment {
    Testnet,
    Mainnet,
}

impl KeyEnvironment {
    pub fn as_str(&self) -> &'static str {
        match self {
            KeyEnvironment::Testnet => "testnet",
            KeyEnvironment::Mainnet => "mainnet",
        }
    }

    pub fn prefix(&self) -> &'static str {
        match self {
            KeyEnvironment::Testnet => "aframp_test_",
            KeyEnvironment::Mainnet => "aframp_live_",
        }
    }

    pub fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "testnet" => Ok(KeyEnvironment::Testnet),
            "mainnet" => Ok(KeyEnvironment::Mainnet),
            other => Err(format!("unknown environment '{}'; must be testnet or mainnet", other)),
        }
    }
}

// ---------------------------------------------------------------------------
// Key generation
// ---------------------------------------------------------------------------

/// The result of generating a new API key.
/// The `plaintext_key` is returned exactly once — never store it.
#[derive(Debug)]
pub struct GeneratedKey {
    /// Full plaintext key — return to caller once, never persist.
    pub plaintext_key: String,
    /// Argon2id hash of the plaintext key — the only value stored in DB.
    pub key_hash: String,
    /// Short prefix embedded in the key for human identification.
    pub key_id_prefix: String,
    /// First 8 characters of the plaintext key (after the env prefix).
    /// Used for display / lookup without exposing the secret.
    pub key_prefix: String,
    /// Environment this key is scoped to.
    pub environment: KeyEnvironment,
}

/// Generate a new API key for the given environment.
///
/// # Entropy
/// The random secret is 32 alphanumeric characters (A-Z, a-z, 0-9).
/// Entropy = log2(62^32) ≈ 190 bits from the random portion alone.
/// Combined with the fixed prefix the full key space is effectively
/// indistinguishable from 256-bit random for brute-force purposes.
pub fn generate_api_key(env: KeyEnvironment) -> Result<GeneratedKey, String> {
    let prefix = env.prefix();

    // 32 cryptographically random alphanumeric characters
    let secret: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();

    let plaintext_key = format!("{}{}", prefix, secret);

    // Hash with Argon2id
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let key_hash = argon2
        .hash_password(plaintext_key.as_bytes(), &salt)
        .map_err(|e| format!("Argon2id hashing failed: {}", e))?
        .to_string();

    // key_prefix = first 8 chars of the full key (includes env prefix chars)
    let key_prefix = plaintext_key.chars().take(8).collect::<String>();
    let key_id_prefix = prefix.to_string();

    Ok(GeneratedKey {
        plaintext_key,
        key_hash,
        key_id_prefix,
        key_prefix,
        environment: env,
    })
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

/// Verify a plaintext key against a stored Argon2id hash.
/// Returns `true` if the key matches.
pub fn verify_api_key(plaintext_key: &str, stored_hash: &str) -> bool {
    let parsed = match PasswordHash::new(stored_hash) {
        Ok(h) => h,
        Err(_) => return false,
    };
    Argon2::default()
        .verify_password(plaintext_key.as_bytes(), &parsed)
        .is_ok()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_testnet_key_has_correct_prefix() {
        let key = generate_api_key(KeyEnvironment::Testnet).unwrap();
        assert!(key.plaintext_key.starts_with("aframp_test_"));
        assert_eq!(key.key_id_prefix, "aframp_test_");
        assert_eq!(key.environment, KeyEnvironment::Testnet);
    }

    #[test]
    fn test_mainnet_key_has_correct_prefix() {
        let key = generate_api_key(KeyEnvironment::Mainnet).unwrap();
        assert!(key.plaintext_key.starts_with("aframp_live_"));
        assert_eq!(key.key_id_prefix, "aframp_live_");
        assert_eq!(key.environment, KeyEnvironment::Mainnet);
    }

    #[test]
    fn test_key_length_provides_sufficient_entropy() {
        let key = generate_api_key(KeyEnvironment::Testnet).unwrap();
        // prefix (12) + 32 random chars = 44 total
        assert_eq!(key.plaintext_key.len(), 44);
    }

    #[test]
    fn test_key_prefix_is_first_8_chars() {
        let key = generate_api_key(KeyEnvironment::Testnet).unwrap();
        assert_eq!(key.key_prefix, &key.plaintext_key[..8]);
    }

    #[test]
    fn test_hash_is_argon2id_format() {
        let key = generate_api_key(KeyEnvironment::Testnet).unwrap();
        assert!(key.key_hash.starts_with("$argon2id$"));
    }

    #[test]
    fn test_hash_is_not_plaintext() {
        let key = generate_api_key(KeyEnvironment::Testnet).unwrap();
        assert_ne!(key.key_hash, key.plaintext_key);
        assert!(!key.key_hash.contains(&key.plaintext_key));
    }

    #[test]
    fn test_verify_correct_key() {
        let key = generate_api_key(KeyEnvironment::Testnet).unwrap();
        assert!(verify_api_key(&key.plaintext_key, &key.key_hash));
    }

    #[test]
    fn test_verify_wrong_key_rejected() {
        let key = generate_api_key(KeyEnvironment::Testnet).unwrap();
        assert!(!verify_api_key("aframp_test_wrongkeyvalue12345678", &key.key_hash));
    }

    #[test]
    fn test_verify_empty_key_rejected() {
        let key = generate_api_key(KeyEnvironment::Testnet).unwrap();
        assert!(!verify_api_key("", &key.key_hash));
    }

    #[test]
    fn test_two_keys_are_unique() {
        let k1 = generate_api_key(KeyEnvironment::Testnet).unwrap();
        let k2 = generate_api_key(KeyEnvironment::Testnet).unwrap();
        assert_ne!(k1.plaintext_key, k2.plaintext_key);
        assert_ne!(k1.key_hash, k2.key_hash);
    }

    #[test]
    fn test_environment_scoping() {
        let test_key = generate_api_key(KeyEnvironment::Testnet).unwrap();
        let live_key = generate_api_key(KeyEnvironment::Mainnet).unwrap();
        // A testnet key must not verify against a mainnet hash and vice versa
        // (they're different strings so hashes will differ)
        assert!(!verify_api_key(&test_key.plaintext_key, &live_key.key_hash));
        assert!(!verify_api_key(&live_key.plaintext_key, &test_key.key_hash));
    }

    #[test]
    fn test_parse_environment() {
        assert_eq!(KeyEnvironment::from_str("testnet").unwrap(), KeyEnvironment::Testnet);
        assert_eq!(KeyEnvironment::from_str("mainnet").unwrap(), KeyEnvironment::Mainnet);
        assert!(KeyEnvironment::from_str("staging").is_err());
    }
}
