//! RSA key pair management for RS256 JWT signing.
//!
//! The private key is loaded from the `OAUTH_RSA_PRIVATE_KEY` environment
//! variable (PEM-encoded PKCS#8 or PKCS#1 format).
//! The public key is exposed via the JWKS endpoint.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use jsonwebtoken::{DecodingKey, EncodingKey};
use rsa::{
    pkcs1::{DecodeRsaPrivateKey, EncodeRsaPublicKey},
    pkcs8::DecodePrivateKey,
    traits::PublicKeyParts,
    RsaPrivateKey, RsaPublicKey,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::types::OAuthError;

// ── Key pair ──────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct RsaKeyPair {
    /// PEM bytes of the private key (kept for jsonwebtoken)
    private_pem_bytes: Vec<u8>,
    /// Derived public key
    public_key: RsaPublicKey,
    /// Key ID — SHA-256 thumbprint prefix of the public modulus
    pub kid: String,
}

impl RsaKeyPair {
    /// Load from a PEM-encoded private key string (PKCS#8 or PKCS#1).
    pub fn from_pem(private_pem: &str) -> Result<Self, OAuthError> {
        // Try PKCS#8 first, then PKCS#1
        let private_key = RsaPrivateKey::from_pkcs8_pem(private_pem)
            .or_else(|_| RsaPrivateKey::from_pkcs1_pem(private_pem))
            .map_err(|e| {
                OAuthError::ServerError(format!("failed to load RSA private key: {}", e))
            })?;

        let public_key = RsaPublicKey::from(&private_key);
        let kid = compute_kid(&public_key);

        Ok(Self {
            private_pem_bytes: private_pem.as_bytes().to_vec(),
            public_key,
            kid,
        })
    }

    /// Load from `OAUTH_RSA_PRIVATE_KEY` environment variable.
    /// Supports literal `\n` sequences (common in CI/CD secrets).
    pub fn from_env() -> Result<Self, OAuthError> {
        let raw = std::env::var("OAUTH_RSA_PRIVATE_KEY").map_err(|_| {
            OAuthError::ServerError(
                "OAUTH_RSA_PRIVATE_KEY environment variable not set".to_string(),
            )
        })?;
        let pem = raw.replace("\\n", "\n");
        Self::from_pem(&pem)
    }

    /// jsonwebtoken `EncodingKey` for RS256 signing.
    pub fn encoding_key(&self) -> Result<EncodingKey, OAuthError> {
        EncodingKey::from_rsa_pem(&self.private_pem_bytes)
            .map_err(|e| OAuthError::ServerError(format!("encoding key error: {}", e)))
    }

    /// jsonwebtoken `DecodingKey` for RS256 verification.
    pub fn decoding_key(&self) -> Result<DecodingKey, OAuthError> {
        let pub_pem = self
            .public_key
            .to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)
            .map_err(|e| OAuthError::ServerError(format!("public key PEM error: {}", e)))?;
        DecodingKey::from_rsa_pem(pub_pem.as_bytes())
            .map_err(|e| OAuthError::ServerError(format!("decoding key error: {}", e)))
    }

    /// Build the JWK representation of the public key for the JWKS endpoint.
    pub fn to_jwk(&self) -> Jwk {
        let n = URL_SAFE_NO_PAD.encode(self.public_key.n().to_bytes_be());
        let e = URL_SAFE_NO_PAD.encode(self.public_key.e().to_bytes_be());
        Jwk {
            kty: "RSA".to_string(),
            alg: "RS256".to_string(),
            r#use: "sig".to_string(),
            kid: self.kid.clone(),
            n,
            e,
        }
    }
}

/// Compute a stable key ID from the public key modulus (first 8 bytes of SHA-256).
fn compute_kid(public_key: &RsaPublicKey) -> String {
    let modulus_bytes = public_key.n().to_bytes_be();
    let hash = Sha256::digest(&modulus_bytes);
    hex::encode(&hash[..8])
}

// ── JWKS types ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwk {
    pub kty: String,
    pub alg: String,
    #[serde(rename = "use")]
    pub r#use: String,
    pub kid: String,
    /// Base64url-encoded modulus
    pub n: String,
    /// Base64url-encoded public exponent
    pub e: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwkSet {
    pub keys: Vec<Jwk>,
}
