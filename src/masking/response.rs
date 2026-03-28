//! API response redaction — error responses and consumer-facing partial masking.

use axum::{
    body::Body,
    http::{Request, Response, StatusCode},
    middleware::Next,
    response::IntoResponse,
    Json,
};
use serde_json::{json, Value};
use std::env;

use crate::masking::engine::mask_json_value;

// ---------------------------------------------------------------------------
// Error response redaction
// ---------------------------------------------------------------------------

/// Fields that must never appear in consumer-facing error responses.
const INTERNAL_ERROR_FIELDS: &[&str] = &[
    "stack_trace", "stacktrace", "stack", "backtrace",
    "db_error", "database_error", "sql", "query",
    "provider_error", "provider_response", "internal_detail",
    "cause", "source",
];

/// Redact internal fields from an error response body.
pub fn redact_error_response(mut body: Value) -> Value {
    if let Some(obj) = body.as_object_mut() {
        for field in INTERNAL_ERROR_FIELDS {
            obj.remove(*field);
        }
    }
    body
}

/// Build a safe consumer-facing error response.
/// In non-production with DEBUG_MODE=true, includes extra context.
pub fn safe_error_response(
    status: u16,
    code: &str,
    message: &str,
    debug_detail: Option<&str>,
) -> Value {
    let is_production = env::var("APP_ENV")
        .map(|e| e == "production")
        .unwrap_or(false);
    let debug_mode = !is_production
        && env::var("DEBUG_MODE")
            .map(|v| v == "true")
            .unwrap_or(false);

    let mut resp = json!({
        "error": {
            "code": code,
            "message": message,
            "status": status
        }
    });

    if debug_mode {
        if let Some(detail) = debug_detail {
            resp["error"]["debug"] = Value::String(detail.to_string());
        }
    }

    resp
}

/// Validate at startup that DEBUG_MODE is not enabled in production.
pub fn validate_debug_mode_disabled_in_production() -> Result<(), String> {
    let app_env = env::var("APP_ENV").unwrap_or_else(|_| "development".into());
    if app_env == "production" {
        let debug = env::var("DEBUG_MODE")
            .map(|v| v == "true")
            .unwrap_or(false);
        if debug {
            return Err("DEBUG_MODE must be false in production".to_string());
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Consumer-facing response partial masking
// ---------------------------------------------------------------------------

/// Apply partial masking to financial identifiers in a response body.
/// - bank account numbers: show last 4 digits
/// - mobile money numbers: show last 3 digits
/// - government ID / document_number: remove entirely, keep doc_type + country
pub fn mask_consumer_response(mut value: Value) -> Value {
    mask_consumer_recursive(&mut value);
    value
}

fn mask_consumer_recursive(value: &mut Value) {
    match value {
        Value::Object(map) => {
            // Mask bank account numbers — last 4
            for key in &["account_number", "bank_account", "iban"] {
                if let Some(v) = map.get_mut(*key) {
                    if let Some(s) = v.as_str() {
                        let masked = if s.len() > 4 {
                            format!("****{}", &s[s.len() - 4..])
                        } else {
                            "****".to_string()
                        };
                        *v = Value::String(masked);
                    }
                }
            }
            // Mask mobile money numbers — last 3
            for key in &["phone", "phone_number", "mobile", "mobile_money_number"] {
                if let Some(v) = map.get_mut(*key) {
                    if let Some(s) = v.as_str() {
                        let masked = if s.len() > 3 {
                            format!("*****{}", &s[s.len() - 3..])
                        } else {
                            "*****".to_string()
                        };
                        *v = Value::String(masked);
                    }
                }
            }
            // KYC: remove document_number, keep doc_type + issuing_country
            map.remove("document_number");
            map.remove("id_number");
            map.remove("nin");
            map.remove("bvn");
            map.remove("ssn");

            for child in map.values_mut() {
                mask_consumer_recursive(child);
            }
        }
        Value::Array(arr) => {
            for item in arr.iter_mut() {
                mask_consumer_recursive(item);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_redact_error_response_removes_internal_fields() {
        let body = json!({
            "error": "something failed",
            "stack_trace": "at line 42...",
            "db_error": "relation does not exist",
            "message": "Internal server error"
        });
        let redacted = redact_error_response(body);
        assert!(redacted.get("stack_trace").is_none());
        assert!(redacted.get("db_error").is_none());
        assert!(redacted.get("message").is_some());
    }

    #[test]
    fn test_safe_error_response_no_debug_in_production() {
        std::env::set_var("APP_ENV", "production");
        std::env::set_var("DEBUG_MODE", "false");
        let resp = safe_error_response(500, "INTERNAL_ERROR", "Service unavailable", Some("db timeout"));
        assert!(resp["error"].get("debug").is_none());
        std::env::remove_var("APP_ENV");
        std::env::remove_var("DEBUG_MODE");
    }

    #[test]
    fn test_validate_debug_mode_blocked_in_production() {
        std::env::set_var("APP_ENV", "production");
        std::env::set_var("DEBUG_MODE", "true");
        assert!(validate_debug_mode_disabled_in_production().is_err());
        std::env::remove_var("APP_ENV");
        std::env::remove_var("DEBUG_MODE");
    }

    #[test]
    fn test_validate_debug_mode_ok_in_development() {
        std::env::set_var("APP_ENV", "development");
        std::env::set_var("DEBUG_MODE", "true");
        assert!(validate_debug_mode_disabled_in_production().is_ok());
        std::env::remove_var("APP_ENV");
        std::env::remove_var("DEBUG_MODE");
    }

    #[test]
    fn test_mask_consumer_response_bank_account() {
        let resp = json!({"account_number": "0123456789", "amount": 5000});
        let masked = mask_consumer_response(resp);
        assert_eq!(masked["account_number"], "****6789");
        assert_eq!(masked["amount"], 5000);
    }

    #[test]
    fn test_mask_consumer_response_phone() {
        let resp = json!({"phone_number": "08012345678"});
        let masked = mask_consumer_response(resp);
        let phone = masked["phone_number"].as_str().unwrap();
        assert!(phone.ends_with("678"));
        assert!(phone.starts_with('*'));
    }

    #[test]
    fn test_mask_consumer_response_removes_kyc_ids() {
        let resp = json!({
            "document_type": "PASSPORT",
            "issuing_country": "NG",
            "document_number": "A12345678",
            "nin": "12345678901"
        });
        let masked = mask_consumer_response(resp);
        assert!(masked.get("document_number").is_none());
        assert!(masked.get("nin").is_none());
        assert_eq!(masked["document_type"], "PASSPORT");
        assert_eq!(masked["issuing_country"], "NG");
    }

    #[test]
    fn test_mask_consumer_response_nested() {
        let resp = json!({
            "payment_method": {
                "account_number": "9876543210",
                "bank_name": "Test Bank"
            }
        });
        let masked = mask_consumer_response(resp);
        assert_eq!(masked["payment_method"]["account_number"], "****3210");
        assert_eq!(masked["payment_method"]["bank_name"], "Test Bank");
    }
}
