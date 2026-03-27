//! Core masking engine — field registry, masking strategies, and log post-processor.

use regex::Regex;
use serde_json::{Map, Value};
use std::collections::HashSet;
use std::sync::{Arc, OnceLock};

// ---------------------------------------------------------------------------
// Masking strategies
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MaskingStrategy {
    /// Replace entire value with [REDACTED]
    FullRedaction,
    /// Show only last N chars, mask the rest with *
    PartialSuffix(usize),
    /// Show only first N chars, mask the rest with *
    PartialPrefix(usize),
    /// Replace with same-length string of *
    FormatPreserving,
}

impl MaskingStrategy {
    pub fn apply(&self, value: &str) -> String {
        match self {
            Self::FullRedaction => "[REDACTED]".to_string(),
            Self::PartialSuffix(n) => {
                if value.len() <= *n {
                    "*".repeat(value.len())
                } else {
                    format!("{}{}", "*".repeat(value.len() - n), &value[value.len() - n..])
                }
            }
            Self::PartialPrefix(n) => {
                if value.len() <= *n {
                    "*".repeat(value.len())
                } else {
                    format!("{}{}", &value[..*n], "*".repeat(value.len() - n))
                }
            }
            Self::FormatPreserving => "*".repeat(value.len()),
        }
    }
}

// ---------------------------------------------------------------------------
// Sensitive field registry
// ---------------------------------------------------------------------------

/// Canonical set of sensitive field names (lower-cased for case-insensitive matching).
static SENSITIVE_FIELDS: OnceLock<HashSet<&'static str>> = OnceLock::new();

fn sensitive_fields() -> &'static HashSet<&'static str> {
    SENSITIVE_FIELDS.get_or_init(|| {
        [
            // Auth / credentials
            "password", "passwd", "secret", "token", "access_token", "refresh_token",
            "id_token", "authorization", "api_key", "apikey", "client_secret",
            // Crypto key material
            "private_key", "privatekey", "seed", "mnemonic", "signing_key",
            "wallet_secret", "secret_key",
            // Government IDs
            "nin", "bvn", "ssn", "passport_number", "id_number", "document_number",
            "national_id",
            // Financial identifiers
            "account_number", "card_number", "cvv", "pin", "iban", "sort_code",
            "routing_number", "bank_account",
            // Contact PII
            "email", "phone", "phone_number", "mobile", "address",
            // cNGN wallet
            "wallet_private_key", "stellar_secret",
        ]
        .into_iter()
        .collect()
    })
}

/// Returns true if the field name is sensitive (case-insensitive).
pub fn is_sensitive_field(name: &str) -> bool {
    sensitive_fields().contains(name.to_lowercase().as_str())
}

/// Strategy to apply for a given sensitive field.
pub fn strategy_for_field(name: &str) -> MaskingStrategy {
    let lower = name.to_lowercase();
    match lower.as_str() {
        "account_number" | "bank_account" | "card_number" | "iban" => {
            MaskingStrategy::PartialSuffix(4)
        }
        "phone" | "phone_number" | "mobile" => MaskingStrategy::PartialSuffix(3),
        "email" => MaskingStrategy::PartialPrefix(3),
        _ => MaskingStrategy::FullRedaction,
    }
}

// ---------------------------------------------------------------------------
// JSON field masking (recursive, any nesting depth)
// ---------------------------------------------------------------------------

/// Recursively mask all sensitive fields in a JSON value in-place.
/// Returns a list of (field_name, strategy) pairs that were masked.
pub fn mask_json_value(value: &mut Value) -> Vec<(String, MaskingStrategy)> {
    let mut masked = Vec::new();
    mask_json_recursive(value, &mut masked);
    masked
}

fn mask_json_recursive(value: &mut Value, masked: &mut Vec<(String, MaskingStrategy)>) {
    match value {
        Value::Object(map) => {
            let keys: Vec<String> = map.keys().cloned().collect();
            for key in keys {
                if is_sensitive_field(&key) {
                    let strategy = strategy_for_field(&key);
                    if let Some(v) = map.get_mut(&key) {
                        let original = match v {
                            Value::String(s) => s.clone(),
                            other => other.to_string(),
                        };
                        *v = Value::String(strategy.apply(&original));
                        masked.push((key, strategy));
                    }
                } else if let Some(child) = map.get_mut(&key) {
                    mask_json_recursive(child, masked);
                }
            }
        }
        Value::Array(arr) => {
            for item in arr.iter_mut() {
                mask_json_recursive(item, masked);
            }
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Structured log event masking
// ---------------------------------------------------------------------------

/// Mask a structured log event represented as a JSON object.
/// Emits a warning for each masked field (field name + strategy, never the value).
pub fn mask_log_event(event: &mut Map<String, Value>) -> Vec<String> {
    let mut warned_fields = Vec::new();
    let mut root = Value::Object(event.clone());
    let masked = mask_json_value(&mut root);
    if let Value::Object(new_map) = root {
        *event = new_map;
    }
    for (field, strategy) in &masked {
        warned_fields.push(field.clone());
        tracing::warn!(
            field_name = %field,
            strategy = ?strategy,
            "Sensitive field detected and masked in log event"
        );
        crate::masking::metrics::record_masking_event(field, "log");
    }
    warned_fields
}

// ---------------------------------------------------------------------------
// Tests (unit)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod unit_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_full_redaction() {
        assert_eq!(MaskingStrategy::FullRedaction.apply("secret123"), "[REDACTED]");
    }

    #[test]
    fn test_partial_suffix_4() {
        assert_eq!(MaskingStrategy::PartialSuffix(4).apply("1234567890123456"), "************3456");
    }

    #[test]
    fn test_partial_suffix_3() {
        assert_eq!(MaskingStrategy::PartialSuffix(3).apply("08012345678"), "********678");
    }

    #[test]
    fn test_partial_prefix_3() {
        let result = MaskingStrategy::PartialPrefix(3).apply("user@example.com");
        assert!(result.starts_with("use"));
        assert!(result.contains('*'));
    }

    #[test]
    fn test_format_preserving() {
        let result = MaskingStrategy::FormatPreserving.apply("GABCDEF");
        assert_eq!(result.len(), 7);
        assert!(result.chars().all(|c| c == '*'));
    }

    #[test]
    fn test_is_sensitive_field_case_insensitive() {
        assert!(is_sensitive_field("Password"));
        assert!(is_sensitive_field("PASSWORD"));
        assert!(is_sensitive_field("private_key"));
        assert!(is_sensitive_field("PRIVATE_KEY"));
        assert!(!is_sensitive_field("amount"));
        assert!(!is_sensitive_field("currency"));
    }

    #[test]
    fn test_mask_json_flat() {
        let mut v = json!({"password": "secret123", "amount": 100});
        let masked = mask_json_value(&mut v);
        assert_eq!(v["password"], "[REDACTED]");
        assert_eq!(v["amount"], 100);
        assert_eq!(masked.len(), 1);
    }

    #[test]
    fn test_mask_json_nested() {
        let mut v = json!({
            "user": {
                "email": "user@example.com",
                "profile": {
                    "nin": "12345678901"
                }
            },
            "amount": 500
        });
        let masked = mask_json_value(&mut v);
        assert_ne!(v["user"]["email"], "user@example.com");
        assert_ne!(v["user"]["profile"]["nin"], "12345678901");
        assert_eq!(v["amount"], 500);
        assert_eq!(masked.len(), 2);
    }

    #[test]
    fn test_mask_json_array() {
        let mut v = json!([
            {"token": "abc123", "id": 1},
            {"token": "xyz789", "id": 2}
        ]);
        let masked = mask_json_value(&mut v);
        assert_eq!(v[0]["token"], "[REDACTED]");
        assert_eq!(v[1]["token"], "[REDACTED]");
        assert_eq!(masked.len(), 2);
    }

    #[test]
    fn test_account_number_partial_suffix() {
        let strategy = strategy_for_field("account_number");
        assert_eq!(strategy, MaskingStrategy::PartialSuffix(4));
        assert_eq!(strategy.apply("0123456789"), "******6789");
    }

    #[test]
    fn test_phone_partial_suffix() {
        let strategy = strategy_for_field("phone_number");
        assert_eq!(strategy, MaskingStrategy::PartialSuffix(3));
    }
}
