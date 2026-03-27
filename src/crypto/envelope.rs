//! Encrypted field envelope — serialisation, parsing, and AES-256-GCM operations.

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng as AeadOsRng},
    Aes256Gcm, Key, Nonce,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::keys::EncryptionError;

// ---------------------------------------------------------------------------
// Envelope
// ---------------------------------------------------------------------------

/// Marker value that identifies an encrypted field envelope.
pub const ENVELOPE_MARKER: bool = true;

/// Supported key-agreement + key-wrap algorithm.
pub const ALG_ECDH_ES_A256KW: &str = "ECDH-ES+A256KW";

/// Supported content-encryption algorithm.
pub const ENC_A256GCM: &str = "A256GCM";

/// Wire format for an encrypted field value.
///
/// All binary fields are base64url-encoded (no padding) for JSON transport.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedEnvelope {
    /// Marker — always `true`. Used to detect encrypted envelopes in request bodies.
    #[serde(rename = "__enc")]
    pub marker: bool,

    /// Key version identifier — matches a key in the platform's key store.
    pub kid: String,

    /// Key-agreement + key-wrap algorithm.
    pub alg: String,

    /// Content-encryption algorithm.
    pub enc: String,

    /// Ephemeral public key (base64url) — the consumer's one-time EC P-384 public key.
    pub epk: String,

    /// Encrypted (wrapped) session key (base64url).
    pub ek: String,

    /// AES-GCM nonce / IV (base64url, 12 bytes).
    pub iv: String,

    /// Ciphertext (base64url).
    pub ct: String,

    /// GCM authentication tag (base64url, 16 bytes).
    pub tag: String,
}

impl EncryptedEnvelope {
    /// Returns `true` if the JSON value looks like an encrypted envelope.
    pub fn is_envelope(value: &serde_json::Value) -> bool {
        value
            .get("__enc")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    }

    /// Validate algorithm identifiers.
    pub fn validate_algorithms(&self) -> Result<(), EncryptionError> {
        if self.alg != ALG_ECDH_ES_A256KW {
            return Err(EncryptionError::UnsupportedAlgorithm(self.alg.clone()));
        }
        if self.enc != ENC_A256GCM {
            return Err(EncryptionError::UnsupportedAlgorithm(self.enc.clone()));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// AES-256-GCM helpers
// ---------------------------------------------------------------------------

/// Encrypt `plaintext` with a fresh random nonce using the provided 32-byte key.
///
/// Returns `(nonce_bytes, ciphertext_with_tag)`.
pub fn aes_gcm_encrypt(
    key_bytes: &[u8; 32],
    plaintext: &[u8],
) -> Result<([u8; 12], Vec<u8>), EncryptionError> {
    let key = Key::<Aes256Gcm>::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key);

    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| EncryptionError::EncryptionFailed)?;

    Ok((nonce_bytes, ciphertext))
}

/// Decrypt `ciphertext_with_tag` (AES-256-GCM output, tag appended) using the
/// provided 32-byte key and 12-byte nonce.
///
/// Returns the plaintext as a [`Zeroizing`] buffer so it is wiped on drop.
pub fn aes_gcm_decrypt(
    key_bytes: &[u8; 32],
    nonce_bytes: &[u8; 12],
    ciphertext_with_tag: &[u8],
) -> Result<Zeroizing<Vec<u8>>, EncryptionError> {
    let key = Key::<Aes256Gcm>::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, ciphertext_with_tag)
        .map_err(|_| EncryptionError::AuthTagVerificationFailed)?;

    Ok(Zeroizing::new(plaintext))
}

/// Decode the IV field from an envelope into a fixed 12-byte array.
pub fn decode_nonce(b64: &str) -> Result<[u8; 12], EncryptionError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(b64)
        .map_err(|_| EncryptionError::MalformedEnvelope("invalid base64 iv".into()))?;
    bytes
        .try_into()
        .map_err(|_| EncryptionError::MalformedEnvelope("iv must be 12 bytes".into()))
}

/// Decode the ciphertext + tag from an envelope.
pub fn decode_ciphertext(b64: &str) -> Result<Vec<u8>, EncryptionError> {
    // ct and tag are stored separately in the envelope; callers concatenate them.
    URL_SAFE_NO_PAD
        .decode(b64)
        .map_err(|_| EncryptionError::MalformedEnvelope("invalid base64 ct".into()))
}

/// Concatenate `ct` and `tag` fields into a single buffer for `aes_gcm_decrypt`.
pub fn concat_ct_tag(envelope: &EncryptedEnvelope) -> Result<Vec<u8>, EncryptionError> {
    let mut ct = decode_ciphertext(&envelope.ct)?;
    let tag = URL_SAFE_NO_PAD
        .decode(&envelope.tag)
        .map_err(|_| EncryptionError::MalformedEnvelope("invalid base64 tag".into()))?;
    if tag.len() != 16 {
        return Err(EncryptionError::MalformedEnvelope("tag must be 16 bytes".into()));
    }
    ct.extend_from_slice(&tag);
    Ok(ct)
}

/// Generate a random 32-byte AES-256 session key.
pub fn generate_session_key() -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0u8; 32]);
    AeadOsRng.fill_bytes(key.as_mut());
    key
}
