//! Gateway signature — HMAC-SHA256 X-Gateway-Signature header.
//! Upstream services call `verify_gateway_signature` to reject non-gateway traffic.

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Compute the gateway signature for a request: HMAC-SHA256(secret, method + path + timestamp).
pub fn compute_gateway_signature(method: &str, path: &str, timestamp: &str) -> String {
    let secret = crate::gateway::config::gateway_secret();
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .expect("HMAC accepts any key length");
    mac.update(format!("{}:{}:{}", method, path, timestamp).as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Verify the X-Gateway-Signature header on an incoming request to an upstream service.
/// Returns true if the signature is valid.
pub fn verify_gateway_signature(method: &str, path: &str, timestamp: &str, sig: &str) -> bool {
    let expected = compute_gateway_signature(method, path, timestamp);
    // Constant-time comparison to prevent timing attacks.
    expected.len() == sig.len()
        && expected
            .bytes()
            .zip(sig.bytes())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signature_round_trip() {
        let sig = compute_gateway_signature("POST", "/api/v1/onramp", "1700000000");
        assert!(verify_gateway_signature("POST", "/api/v1/onramp", "1700000000", &sig));
    }

    #[test]
    fn test_wrong_method_fails() {
        let sig = compute_gateway_signature("POST", "/api/v1/onramp", "1700000000");
        assert!(!verify_gateway_signature("GET", "/api/v1/onramp", "1700000000", &sig));
    }

    #[test]
    fn test_wrong_path_fails() {
        let sig = compute_gateway_signature("POST", "/api/v1/onramp", "1700000000");
        assert!(!verify_gateway_signature("POST", "/api/v1/offramp", "1700000000", &sig));
    }

    #[test]
    fn test_tampered_signature_fails() {
        let mut sig = compute_gateway_signature("POST", "/api/v1/onramp", "1700000000");
        sig.push('x');
        assert!(!verify_gateway_signature("POST", "/api/v1/onramp", "1700000000", &sig));
    }
}
