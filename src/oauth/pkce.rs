//! PKCE (Proof Key for Code Exchange) — RFC 7636
//!
//! Only S256 method is supported (plain is insecure and rejected).

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use sha2::{Digest, Sha256};

use super::types::OAuthError;

/// Verify a PKCE code_verifier against a stored S256 code_challenge.
///
/// The challenge was computed as:
///   BASE64URL(SHA256(ASCII(code_verifier)))
pub fn verify_pkce_s256(code_verifier: &str, code_challenge: &str) -> Result<(), OAuthError> {
    let computed = compute_s256_challenge(code_verifier);
    if computed == code_challenge {
        Ok(())
    } else {
        Err(OAuthError::InvalidGrant(
            "PKCE code_verifier does not match code_challenge".to_string(),
        ))
    }
}

/// Compute the S256 challenge from a verifier.
pub fn compute_s256_challenge(code_verifier: &str) -> String {
    let hash = Sha256::digest(code_verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(hash)
}

/// Validate that a code_challenge_method is supported (only "S256").
pub fn validate_challenge_method(method: &str) -> Result<(), OAuthError> {
    if method == "S256" {
        Ok(())
    } else {
        Err(OAuthError::InvalidRequest(format!(
            "unsupported code_challenge_method '{}'; only S256 is supported",
            method
        )))
    }
}

/// Validate code_verifier format per RFC 7636 §4.1:
/// 43–128 characters, unreserved chars [A-Z a-z 0-9 - . _ ~]
pub fn validate_code_verifier(verifier: &str) -> Result<(), OAuthError> {
    let len = verifier.len();
    if !(43..=128).contains(&len) {
        return Err(OAuthError::InvalidRequest(format!(
            "code_verifier must be 43-128 characters, got {}",
            len
        )));
    }
    let valid = verifier
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '~'));
    if !valid {
        return Err(OAuthError::InvalidRequest(
            "code_verifier contains invalid characters".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_s256_roundtrip() {
        // RFC 7636 Appendix B test vector
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let expected_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert_eq!(compute_s256_challenge(verifier), expected_challenge);
    }

    #[test]
    fn test_verify_pkce_success() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = compute_s256_challenge(verifier);
        assert!(verify_pkce_s256(verifier, &challenge).is_ok());
    }

    #[test]
    fn test_verify_pkce_wrong_verifier() {
        let challenge = compute_s256_challenge("correct_verifier_that_is_long_enough_here_abc");
        let result = verify_pkce_s256("wrong_verifier_that_is_long_enough_here_abcde", &challenge);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_code_verifier_too_short() {
        let result = validate_code_verifier("short");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_code_verifier_invalid_chars() {
        let verifier = "a".repeat(43) + "@";
        let result = validate_code_verifier(&verifier);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_code_verifier_valid() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        assert!(validate_code_verifier(verifier).is_ok());
    }

    #[test]
    fn test_plain_method_rejected() {
        assert!(validate_challenge_method("plain").is_err());
        assert!(validate_challenge_method("S256").is_ok());
    }
}
