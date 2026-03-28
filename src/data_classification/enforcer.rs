//! Enforcement utilities — the runtime layer that applies policy decisions.
//!
//! This module provides:
//! - [`LogSanitizer`] — scrubs sensitive fields from structured log events.
//! - [`mask_field`] — apply the correct masking strategy for a known field.
//! - [`sanitize_json`] — walk a `serde_json::Value` and redact classified fields.
//! - [`ClassifiedString`] — a newtype that enforces masking on `Display`/`Debug`.
//! - [`guard_transmission`] — assert a field is allowed in a context or panic in debug.

use serde_json::{Map, Value as JsonValue};
use std::fmt;

use crate::data_classification::{
    policy::{transmission_decision, TransmissionContext, TransmissionDecision},
    registry::DataField,
    types::ClassificationTier,
};

// ---------------------------------------------------------------------------
// Field masking
// ---------------------------------------------------------------------------

/// Apply the registered masking strategy for `field` to `value`.
///
/// Returns the masked string.  If the field's tier is `Critical` this always
/// returns `"[REDACTED]"` regardless of the masking strategy.
pub fn mask_field(field: DataField, value: &str) -> String {
    if field.tier().must_never_log() {
        return "[REDACTED]".to_string();
    }
    field.masking_strategy().apply(value)
}

// ---------------------------------------------------------------------------
// ClassifiedString — safe wrapper for sensitive values
// ---------------------------------------------------------------------------

/// A string value tagged with its classification tier.
///
/// `Display` and `Debug` implementations automatically apply the masking
/// strategy so the raw value is never accidentally emitted to logs.
///
/// ```rust,no_run
/// use Bitmesh_backend::data_classification::enforcer::ClassifiedString;
/// use Bitmesh_backend::data_classification::registry::DataField;
///
/// let email = ClassifiedString::new("user@example.com", DataField::UserEmail);
/// // Logs will show the masked form, not the raw email.
/// println!("{}", email); // → "us*****.com" (masked)
/// ```
#[derive(Clone)]
pub struct ClassifiedString {
    raw: String,
    field: DataField,
}

impl ClassifiedString {
    /// Wrap a raw value with its field classification.
    pub fn new(raw: impl Into<String>, field: DataField) -> Self {
        Self {
            raw: raw.into(),
            field,
        }
    }

    /// Access the raw value.
    ///
    /// Only call this when you have verified the transmission context is
    /// appropriate (e.g., writing to the database, passing to a payment
    /// provider over TLS).  Never pass the raw value to a log macro.
    pub fn raw(&self) -> &str {
        &self.raw
    }

    /// Return the masked representation.
    pub fn masked(&self) -> String {
        mask_field(self.field, &self.raw)
    }

    /// The classification tier of this value.
    pub fn tier(&self) -> ClassificationTier {
        self.field.tier()
    }
}

/// `Display` always shows the masked form.
impl fmt::Display for ClassifiedString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.masked())
    }
}

/// `Debug` always shows the masked form.
impl fmt::Debug for ClassifiedString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ClassifiedString({:?})", self.masked())
    }
}

// ---------------------------------------------------------------------------
// JSON sanitizer
// ---------------------------------------------------------------------------

/// Well-known JSON key names that map to classified fields.
///
/// The sanitizer walks a `serde_json::Value` and redacts any key whose name
/// appears in this list.  Keys are matched case-insensitively.
const SENSITIVE_JSON_KEYS: &[(&str, DataField)] = &[
    // Critical
    ("private_key", DataField::WalletPrivateKey),
    ("privatekey", DataField::WalletPrivateKey),
    ("secret_seed", DataField::WalletSecretSeed),
    ("secretseed", DataField::WalletSecretSeed),
    ("secret_key", DataField::PaystackSecretKey),
    ("secretkey", DataField::PaystackSecretKey),
    ("api_key", DataField::ApiKeyPlaintext),
    ("apikey", DataField::ApiKeyPlaintext),
    ("consumer_secret", DataField::MpesaConsumerSecret),
    ("consumersecret", DataField::MpesaConsumerSecret),
    ("passkey", DataField::MpesaPasskey),
    ("webhook_secret", DataField::WebhookSignatureSecret),
    ("webhooksecret", DataField::WebhookSignatureSecret),
    ("card_number", DataField::CardPan),
    ("cardnumber", DataField::CardPan),
    ("pan", DataField::CardPan),
    ("totp_secret", DataField::TotpSecretSeed),
    ("totpsecret", DataField::TotpSecretSeed),
    // Restricted
    ("access_token", DataField::JwtAccessToken),
    ("accesstoken", DataField::JwtAccessToken),
    ("refresh_token", DataField::JwtRefreshToken),
    ("refreshtoken", DataField::JwtRefreshToken),
    ("document_number", DataField::KycDocumentNumber),
    ("documentnumber", DataField::KycDocumentNumber),
    ("selfie_image", DataField::KycSelfieImageRef),
    ("selfieimage", DataField::KycSelfieImageRef),
    ("document_image", DataField::KycDocumentImageRef),
    ("documentimage", DataField::KycDocumentImageRef),
    ("full_name", DataField::UserFullName),
    ("fullname", DataField::UserFullName),
    ("date_of_birth", DataField::UserDateOfBirth),
    ("dateofbirth", DataField::UserDateOfBirth),
    ("dob", DataField::UserDateOfBirth),
    ("bank_account_number", DataField::BankAccountNumber),
    ("bankaccountnumber", DataField::BankAccountNumber),
    ("account_number", DataField::BankAccountNumber),
    // Confidential
    ("email", DataField::UserEmail),
    ("phone", DataField::UserPhone),
    ("phone_number", DataField::UserPhone),
    ("phonenumber", DataField::UserPhone),
    ("wallet_address", DataField::WalletAddress),
    ("walletaddress", DataField::WalletAddress),
    ("ip_address", DataField::IpAddress),
    ("ipaddress", DataField::IpAddress),
    ("ip", DataField::IpAddress),
    ("amount", DataField::TransactionAmount),
    ("from_amount", DataField::TransactionFromAmount),
    ("to_amount", DataField::TransactionToAmount),
    ("balance", DataField::CryptoBalance),
    ("afri_balance", DataField::CngnBalance),
    ("cngn_balance", DataField::CngnBalance),
    ("payment_reference", DataField::TransactionPaymentReference),
    ("paymentreference", DataField::TransactionPaymentReference),
    ("signature", DataField::WebhookSignature),
];

/// Sanitize a `serde_json::Value` for use in a log line or API response.
///
/// Walks the JSON tree recursively.  For each object key that matches a
/// known sensitive field, the value is replaced with the masked form.
///
/// `context` controls how aggressively fields are masked:
/// - [`TransmissionContext::LogLine`] — masks all Confidential+ fields.
/// - [`TransmissionContext::ApiResponse`] — masks Restricted+ fields.
/// - Other contexts — passes through (caller is responsible).
pub fn sanitize_json(value: JsonValue, context: TransmissionContext) -> JsonValue {
    match value {
        JsonValue::Object(map) => {
            let sanitized: Map<String, JsonValue> = map
                .into_iter()
                .map(|(k, v)| {
                    let sanitized_v = sanitize_json_value_for_key(&k, v, context);
                    (k, sanitized_v)
                })
                .collect();
            JsonValue::Object(sanitized)
        }
        JsonValue::Array(arr) => {
            JsonValue::Array(arr.into_iter().map(|v| sanitize_json(v, context)).collect())
        }
        other => other,
    }
}

fn sanitize_json_value_for_key(
    key: &str,
    value: JsonValue,
    context: TransmissionContext,
) -> JsonValue {
    let key_lower = key.to_lowercase();

    // Look up the field in the sensitive key registry
    if let Some((_, field)) = SENSITIVE_JSON_KEYS
        .iter()
        .find(|(k, _)| *k == key_lower.as_str())
    {
        let decision = transmission_decision(*field, context);
        match decision {
            TransmissionDecision::Deny { .. } => {
                return JsonValue::String("[REDACTED]".to_string());
            }
            TransmissionDecision::AllowMasked(strategy) => {
                if let JsonValue::String(s) = &value {
                    return JsonValue::String(strategy.apply(s));
                }
                return JsonValue::String("[REDACTED]".to_string());
            }
            TransmissionDecision::Allow => {}
        }
    }

    // Recurse into nested objects/arrays
    match value {
        JsonValue::Object(_) | JsonValue::Array(_) => sanitize_json(value, context),
        other => other,
    }
}

// ---------------------------------------------------------------------------
// Log sanitizer
// ---------------------------------------------------------------------------

/// Sanitizes a free-form string (e.g., a log message or error string) by
/// applying regex-based redaction for known sensitive patterns.
///
/// This is a defence-in-depth measure for cases where structured field
/// masking was not applied upstream.
pub struct LogSanitizer;

impl LogSanitizer {
    /// Redact known sensitive patterns from a log string.
    pub fn sanitize(input: &str) -> String {
        let mut result = input.to_string();

        // JWT tokens (three base64url segments separated by dots)
        result = redact_pattern(
            &result,
            r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
            "[JWT_REDACTED]",
        );

        // Stellar secret seeds (S + 55 base32 chars)
        result = redact_pattern(&result, r"\bS[A-Z2-7]{55}\b", "[STELLAR_SECRET_REDACTED]");

        // Credentials adjacent to secret-like key names
        result = redact_pattern(
            &result,
            r#"(?i)(secret|private_key|seed)["\s:=]+[A-Za-z0-9+/=]{20,}"#,
            "[SECRET_REDACTED]",
        );

        // API keys with known prefixes
        result = redact_pattern(
            &result,
            r"aframp_(live|test)_[A-Za-z0-9]{32}",
            "[API_KEY_REDACTED]",
        );

        // Paystack secret keys
        result = redact_pattern(
            &result,
            r"sk_(live|test)_[A-Za-z0-9]{40,}",
            "[PSK_REDACTED]",
        );

        // Flutterwave secret keys
        result = redact_pattern(
            &result,
            r"FLWSECK[_-][A-Za-z0-9]{20,}",
            "[FLW_SECRET_REDACTED]",
        );

        // Card PANs (13-19 digit sequences, optionally space/dash separated)
        result = redact_pattern(
            &result,
            r"\b(?:\d[ -]?){13,19}\b",
            "[CARD_PAN_REDACTED]",
        );

        result
    }
}

fn redact_pattern(input: &str, pattern: &str, replacement: &str) -> String {
    match regex::Regex::new(pattern) {
        Ok(re) => re.replace_all(input, replacement).to_string(),
        Err(_) => input.to_string(), // never panic on bad pattern
    }
}

// ---------------------------------------------------------------------------
// Transmission guard
// ---------------------------------------------------------------------------

/// Assert that `field` is allowed in `context`.
///
/// In debug builds this panics with a descriptive message if the policy
/// denies the transmission.  In release builds it logs an error and
/// returns `false` so callers can handle the denial gracefully.
///
/// Returns `true` if the transmission is allowed (possibly with masking).
pub fn guard_transmission(field: DataField, context: TransmissionContext) -> bool {
    let decision = transmission_decision(field, context);
    match decision {
        TransmissionDecision::Deny { reason } => {
            #[cfg(debug_assertions)]
            panic!(
                "Data classification policy violation: field {:?} denied in context {:?}: {}",
                field, context, reason
            );
            #[cfg(not(debug_assertions))]
            {
                tracing::error!(
                    field = ?field,
                    context = ?context,
                    reason = reason,
                    "DATA_CLASSIFICATION_VIOLATION: field denied in context"
                );
                false
            }
        }
        _ => true,
    }
}

// ---------------------------------------------------------------------------
// Retention enforcement helper
// ---------------------------------------------------------------------------

/// Returns the maximum retention period in days for a field.
///
/// Callers (e.g., the DB maintenance worker) use this to schedule purge jobs.
pub fn retention_days_for_field(field: DataField) -> Option<u32> {
    field.tier().default_retention_days()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn mask_field_critical_always_redacts() {
        let result = mask_field(
            DataField::WalletPrivateKey,
            "SXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
        );
        assert_eq!(result, "[REDACTED]");
    }

    #[test]
    fn mask_field_email_partial() {
        let result = mask_field(DataField::UserEmail, "user@example.com");
        assert!(!result.contains("user@example.com"));
        assert!(result.starts_with("us"));
    }

    #[test]
    fn classified_string_display_is_masked() {
        let cs = ClassifiedString::new(
            "SXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
            DataField::WalletPrivateKey,
        );
        let displayed = format!("{}", cs);
        assert_eq!(displayed, "[REDACTED]");
    }

    #[test]
    fn classified_string_raw_accessible() {
        let raw = "user@example.com";
        let cs = ClassifiedString::new(raw, DataField::UserEmail);
        assert_eq!(cs.raw(), raw);
    }

    #[test]
    fn sanitize_json_redacts_private_key() {
        let input = json!({
            "private_key": "SXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
            "amount": "1000"
        });
        let sanitized = sanitize_json(input, TransmissionContext::LogLine);
        assert_eq!(sanitized["private_key"], "[REDACTED]");
    }

    #[test]
    fn sanitize_json_masks_email_in_log() {
        let input = json!({ "email": "user@example.com" });
        let sanitized = sanitize_json(input, TransmissionContext::LogLine);
        let email_val = sanitized["email"].as_str().unwrap();
        assert_ne!(email_val, "user@example.com");
    }

    #[test]
    fn sanitize_json_allows_currency_code() {
        let input = json!({ "currency": "NGN" });
        let sanitized = sanitize_json(input, TransmissionContext::LogLine);
        assert_eq!(sanitized["currency"], "NGN");
    }

    #[test]
    fn log_sanitizer_redacts_jwt() {
        // A real JWT token split across a concat to stay within line length
        let header = "eyJhbGciOiJIUzI1NiJ9";
        let log = format!(
            "token={}.eyJzdWIiOiJ1c2VyIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
            header
        );
        let sanitized = LogSanitizer::sanitize(&log);
        assert!(!sanitized.contains(header));
        assert!(sanitized.contains("[JWT_REDACTED]"));
    }

    #[test]
    fn log_sanitizer_redacts_stellar_secret() {
        let log = "seed=SCZANGBA5XTONSOWMNZOVLY4SWDTCMFKOOIIUZNSP5ZH5TZJNHQOWOBQ";
        let sanitized = LogSanitizer::sanitize(log);
        assert!(sanitized.contains("[STELLAR_SECRET_REDACTED]"));
    }

    #[test]
    fn log_sanitizer_redacts_api_key() {
        let log = "key=aframp_live_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456";
        let sanitized = LogSanitizer::sanitize(log);
        assert!(sanitized.contains("[API_KEY_REDACTED]"));
    }
}
