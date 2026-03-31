//! Integration tests for the masking system.

#[cfg(test)]
mod integration {
    use serde_json::json;

    use crate::masking::{
        engine::{mask_json_value, mask_log_event, MaskingStrategy},
        patterns::scan_and_redact,
        response::{mask_consumer_response, redact_error_response, validate_debug_mode_disabled_in_production},
        rules::RuleStore,
        tracing_layer::{mask_span_attributes, safe_metric_label},
    };

    // ── Log field masking at all nesting depths ──────────────────────────────

    #[test]
    fn test_log_field_masking_depth_1() {
        let mut v = json!({"password": "s3cr3t", "amount": 100});
        mask_json_value(&mut v);
        assert_eq!(v["password"], "[REDACTED]");
        assert_eq!(v["amount"], 100);
    }

    #[test]
    fn test_log_field_masking_depth_2() {
        let mut v = json!({"user": {"token": "abc", "name": "Alice"}});
        mask_json_value(&mut v);
        assert_eq!(v["user"]["token"], "[REDACTED]");
        assert_eq!(v["user"]["name"], "Alice");
    }

    #[test]
    fn test_log_field_masking_depth_3() {
        let mut v = json!({"a": {"b": {"private_key": "SXXX", "c": 1}}});
        mask_json_value(&mut v);
        assert_eq!(v["a"]["b"]["private_key"], "[REDACTED]");
        assert_eq!(v["a"]["b"]["c"], 1);
    }

    #[test]
    fn test_log_field_masking_in_array() {
        let mut v = json!([{"api_key": "key1"}, {"api_key": "key2"}]);
        mask_json_value(&mut v);
        assert_eq!(v[0]["api_key"], "[REDACTED]");
        assert_eq!(v[1]["api_key"], "[REDACTED]");
    }

    // ── Pattern scanner accuracy ─────────────────────────────────────────────

    #[test]
    fn test_pattern_scanner_jwt() {
        let (out, detected) = scan_and_redact("Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c");
        assert!(detected.contains(&"jwt"));
        assert!(!out.contains("eyJ"));
    }

    #[test]
    fn test_pattern_scanner_credit_card() {
        let (out, detected) = scan_and_redact("card: 4111111111111111");
        assert!(detected.contains(&"credit_card"));
        assert!(!out.contains("4111111111111111"));
    }

    #[test]
    fn test_pattern_scanner_email() {
        let (out, detected) = scan_and_redact("contact admin@aframp.io for help");
        assert!(detected.contains(&"email"));
        assert!(!out.contains("admin@aframp.io"));
    }

    #[test]
    fn test_pattern_scanner_pem_key() {
        let msg = "key=-----BEGIN PRIVATE KEY-----\nABCDEF\n-----END PRIVATE KEY-----";
        let (out, detected) = scan_and_redact(msg);
        assert!(detected.contains(&"pem_private_key"));
        assert!(!out.contains("ABCDEF"));
    }

    #[test]
    fn test_pattern_scanner_api_key() {
        let (out, detected) = scan_and_redact("api_key=test_key_abcdefghijklmnopqrstuvwx");
        assert!(detected.contains(&"api_key"));
        assert!(!out.contains("test_key_abcdefghijklmnopqrstuvwx"));
    }

    // ── Response redaction ───────────────────────────────────────────────────

    #[test]
    fn test_error_response_no_stack_trace() {
        let body = json!({"message": "error", "stack_trace": "line 42", "db_error": "syntax error"});
        let redacted = redact_error_response(body);
        assert!(redacted.get("stack_trace").is_none());
        assert!(redacted.get("db_error").is_none());
        assert!(redacted.get("message").is_some());
    }

    #[test]
    fn test_debug_mode_blocked_in_production() {
        std::env::set_var("APP_ENV", "production");
        std::env::set_var("DEBUG_MODE", "true");
        assert!(validate_debug_mode_disabled_in_production().is_err());
        std::env::remove_var("APP_ENV");
        std::env::remove_var("DEBUG_MODE");
    }

    // ── Partial masking format correctness ───────────────────────────────────

    #[test]
    fn test_bank_account_last_4() {
        let resp = json!({"account_number": "0123456789"});
        let masked = mask_consumer_response(resp);
        assert_eq!(masked["account_number"], "****6789");
    }

    #[test]
    fn test_mobile_money_last_3() {
        let resp = json!({"phone_number": "08012345678"});
        let masked = mask_consumer_response(resp);
        let phone = masked["phone_number"].as_str().unwrap();
        assert!(phone.ends_with("678"));
    }

    #[test]
    fn test_kyc_document_number_removed() {
        let resp = json!({"document_type": "NIN_SLIP", "issuing_country": "NG", "document_number": "12345678901"});
        let masked = mask_consumer_response(resp);
        assert!(masked.get("document_number").is_none());
        assert_eq!(masked["document_type"], "NIN_SLIP");
        assert_eq!(masked["issuing_country"], "NG");
    }

    // ── Tracing span attribute masking ───────────────────────────────────────

    #[test]
    fn test_span_attributes_masked() {
        let attrs = vec![
            ("token".to_string(), "secret_token_value".to_string()),
            ("http.method".to_string(), "POST".to_string()),
        ];
        let masked = mask_span_attributes(attrs);
        let token = masked.iter().find(|(k, _)| k == "token").unwrap();
        assert_eq!(token.1, "[REDACTED]");
        let method = masked.iter().find(|(k, _)| k == "http.method").unwrap();
        assert_eq!(method.1, "POST");
    }

    // ── Prometheus metric label safety ───────────────────────────────────────

    #[test]
    fn test_metric_label_sensitive_redacted() {
        assert_eq!(safe_metric_label("email", "user@example.com"), "[REDACTED]");
    }

    #[test]
    fn test_metric_label_non_sensitive_preserved() {
        assert_eq!(safe_metric_label("status_code", "200"), "200");
    }

    // ── Rule cache invalidation ───────────────────────────────────────────────

    #[test]
    fn test_rule_add_takes_effect_immediately() {
        let store = RuleStore::new();
        let initial_count = store.list().len();
        let rule = crate::masking::rules::MaskingRule::new(
            "new_sensitive_field",
            "test",
            MaskingStrategy::FullRedaction,
            vec!["log".into()],
        );
        let id = store.add(rule);
        assert_eq!(store.list().len(), initial_count + 1);
        assert!(store.get(&id).is_some());
    }

    #[test]
    fn test_rule_remove_takes_effect_immediately() {
        let store = RuleStore::new();
        let rule = crate::masking::rules::MaskingRule::new(
            "temp_field",
            "test",
            MaskingStrategy::FullRedaction,
            vec![],
        );
        let id = store.add(rule);
        assert!(store.remove(&id));
        assert!(store.get(&id).is_none());
    }
}
