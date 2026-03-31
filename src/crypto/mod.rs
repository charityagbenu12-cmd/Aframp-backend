//! End-to-end payload encryption — Issue: Data Security & Encryption
//!
//! Hybrid encryption scheme:
//!   1. Consumer generates a random AES-256 session key.
//!   2. Consumer encrypts each sensitive field with AES-256-GCM using the session key.
//!   3. Consumer encrypts the session key with the platform's EC P-384 public key (ECDH-ES + AES-KW).
//!   4. Consumer transmits both the encrypted fields and the encrypted session key.
//!   5. Server decrypts the session key with its private key, then decrypts each field.
//!
//! # Envelope format (JSON)
//! ```json
//! {
//!   "__enc": true,
//!   "kid":   "v1",
//!   "alg":   "ECDH-ES+A256KW",
//!   "enc":   "A256GCM",
//!   "epk":   "<base64url-encoded ephemeral public key>",
//!   "ek":    "<base64url-encoded wrapped session key>",
//!   "iv":    "<base64url-encoded 12-byte nonce>",
//!   "ct":    "<base64url-encoded ciphertext>",
//!   "tag":   "<base64url-encoded 16-byte GCM auth tag>"
//! }
//! ```

pub mod envelope;
pub mod keys;
pub mod middleware;
pub mod metrics;

#[cfg(test)]
pub mod tests;
