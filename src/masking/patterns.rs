//! Pattern-based scanner for sensitive data in unstructured log message strings.

use regex::Regex;
use std::sync::OnceLock;

fn re_jwt() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}").unwrap()
    })
}

fn re_pem_private_key() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(
            r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
        )
        .unwrap()
    })
}

fn re_stellar_secret() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"\bS[A-Z2-7]{55}\b").unwrap())
}

fn re_credit_card() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(
            r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b",
        )
        .unwrap()
    })
}

fn re_api_key() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r"(?i)(?:api[_-]?key|apikey)[=:\s]+[A-Za-z0-9_\-]{16,}").unwrap()
    })
}

fn re_bvn() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"\bBVN[:\s]*[0-9]{11}\b").unwrap())
}

fn re_email() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b").unwrap()
    })
}

fn re_nin() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"\b[0-9]{11}\b").unwrap())
}

struct Pattern {
    name: &'static str,
    placeholder: &'static str,
    get: fn() -> &'static Regex,
}

static PATTERNS: &[Pattern] = &[
    Pattern { name: "jwt",            placeholder: "[JWT-REDACTED]",            get: re_jwt },
    Pattern { name: "pem_private_key",placeholder: "[PRIVKEY-REDACTED]",        get: re_pem_private_key },
    Pattern { name: "stellar_secret", placeholder: "[STELLAR-SECRET-REDACTED]", get: re_stellar_secret },
    Pattern { name: "credit_card",    placeholder: "[CARD-REDACTED]",           get: re_credit_card },
    Pattern { name: "api_key",        placeholder: "[APIKEY-REDACTED]",         get: re_api_key },
    Pattern { name: "bvn",            placeholder: "[BVN-REDACTED]",            get: re_bvn },
    Pattern { name: "email",          placeholder: "[EMAIL-REDACTED]",          get: re_email },
    Pattern { name: "nin",            placeholder: "[NIN-REDACTED]",            get: re_nin },
];

/// Scan a log message string and replace all sensitive patterns with placeholders.
/// Returns (sanitised_string, list_of_detected_pattern_names).
pub fn scan_and_redact(message: &str) -> (String, Vec<&'static str>) {
    let mut result = message.to_string();
    let mut detected = Vec::new();

    for p in PATTERNS {
        let re = (p.get)();
        if re.is_match(&result) {
            detected.push(p.name);
            result = re.replace_all(&result, p.placeholder).to_string();
        }
    }

    (result, detected)
}

/// Scan message and emit security alert if sensitive patterns are found.
/// Returns the sanitised message.
pub fn sanitise_log_message(message: &str) -> String {
    let (sanitised, detected) = scan_and_redact(message);
    for pattern_name in &detected {
        tracing::error!(
            pattern = pattern_name,
            "SECURITY ALERT: Sensitive data pattern detected in log message — remediation required"
        );
        crate::masking::metrics::record_masking_event(pattern_name, "log_message");
    }
    sanitised
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jwt_redacted() {
        let msg = "token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let (out, detected) = scan_and_redact(msg);
        assert!(detected.contains(&"jwt"));
        assert!(!out.contains("eyJ"));
    }

    #[test]
    fn test_credit_card_redacted() {
        let msg = "card number is 4111111111111111 for payment";
        let (out, detected) = scan_and_redact(msg);
        assert!(detected.contains(&"credit_card"));
        assert!(!out.contains("4111111111111111"));
    }

    #[test]
    fn test_email_redacted() {
        let msg = "user email: john.doe@example.com logged in";
        let (out, detected) = scan_and_redact(msg);
        assert!(detected.contains(&"email"));
        assert!(!out.contains("john.doe@example.com"));
    }

    #[test]
    fn test_pem_key_redacted() {
        let msg = "key: -----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkq\n-----END PRIVATE KEY-----";
        let (out, detected) = scan_and_redact(msg);
        assert!(detected.contains(&"pem_private_key"));
        assert!(!out.contains("MIIEvQIBADANBgkq"));
    }

    #[test]
    fn test_stellar_secret_redacted() {
        // 56-char Stellar secret key starting with S
        let secret = "SCZANGBAYHTNYVSK3JYHXPJZXJZXJZXJZXJZXJZXJZXJZXJZXJZXJZXJ";
        let msg = format!("secret={}", secret);
        let (out, detected) = scan_and_redact(&msg);
        assert!(detected.contains(&"stellar_secret"), "detected: {:?}", detected);
        assert!(!out.contains("SCZANGBA"));
    }

    #[test]
    fn test_api_key_redacted() {
        let msg = "api_key=test_key_abcdefghijklmnopqrstuvwx";
        let (out, detected) = scan_and_redact(msg);
        assert!(detected.contains(&"api_key"));
        assert!(!out.contains("test_key_abcdefghijklmnopqrstuvwx"));
    }

    #[test]
    fn test_clean_message_unchanged() {
        let msg = "User completed onramp transaction of 5000 NGN";
        let (out, detected) = scan_and_redact(msg);
        assert!(detected.is_empty());
        assert_eq!(out, msg);
    }

    #[test]
    fn test_bvn_redacted() {
        let msg = "BVN: 12345678901 verified";
        let (out, detected) = scan_and_redact(msg);
        assert!(detected.contains(&"bvn"));
        assert!(!out.contains("12345678901"));
    }
}
