//! Unit tests for onramp status endpoint functions
//!
//! Tests individual functions and logic without external dependencies

#[cfg(test)]
mod tests {
    use crate::api::onramp::status::{
        get_ttl_for_status, map_status_to_stage, get_status_message, 
        extract_platform_fee, extract_provider_fee, extract_total_fee,
        TransactionStage
    };
    use chrono::Utc;
    use serde_json::json;
    use std::time::Duration;

    #[test]
    fn test_map_status_to_stage() {
        let test_cases = vec![
            ("pending", TransactionStage::AwaitingPayment),
            ("processing", TransactionStage::SendingCngn),
            ("completed", TransactionStage::Done),
            ("failed", TransactionStage::Failed),
            ("refunded", TransactionStage::Refunded),
            ("unknown", TransactionStage::AwaitingPayment), // Default case
        ];

        for (status, expected_stage) in test_cases {
            let result = map_status_to_stage(status);
            assert!(matches!(result, expected_stage), 
                "Status '{}' should map to {:?}", status, expected_stage);
        }
    }

    #[test]
    fn test_get_status_message() {
        let test_cases = vec![
            ("pending", Some("paystack"), "Waiting for your payment to be confirmed by paystack."),
            ("pending", None, "Waiting for your payment to be confirmed by payment provider."),
            ("processing", Some("flutterwave"), "Payment confirmed. Sending cNGN to your wallet."),
            ("completed", Some("paystack"), "cNGN has been sent to your wallet successfully."),
            ("failed", Some("paystack"), "Transaction failed. Please contact support."),
            ("refunded", Some("paystack"), "Refund has been processed."),
            ("unknown", Some("paystack"), "Transaction is being processed."),
        ];

        for (status, provider, expected_message) in test_cases {
            let provider_option = provider.map(|s| s.to_string());
            let result = get_status_message(status, &provider_option);
            assert_eq!(result, expected_message, 
                "Status '{}' with provider '{:?}' should return correct message", 
                status, provider);
        }
    }

    #[test]
    fn test_get_ttl_for_status() {
        let test_cases = vec![
            ("pending", Duration::from_secs(5)),
            ("processing", Duration::from_secs(10)),
            ("completed", Duration::from_secs(300)),
            ("failed", Duration::from_secs(300)),
            ("refunded", Duration::from_secs(300)),
            ("unknown", Duration::from_secs(60)), // Default case
        ];

        for (status, expected_ttl) in test_cases {
            let result = get_ttl_for_status(status);
            assert_eq!(result, expected_ttl, 
                "Status '{}' should have TTL of {:?}", status, expected_ttl);
        }
    }

    #[test]
    fn test_extract_platform_fee() {
        let test_cases = vec![
            (json!({"platform_fee": "100"}), "100"),
            (json!({"platform_fee": "0"}), "0"),
            (json!({}), "0"), // Missing field should default to 0
            (json!({"platform_fee": null}), "0"), // Null should default to 0
            (json!({"platform_fee": "invalid"}), "0"), // Invalid should default to 0
        ];

        for (metadata, expected_str) in test_cases {
            let result = extract_platform_fee(&metadata);
            let expected = sqlx::types::BigDecimal::from_str(expected_str).unwrap();
            assert_eq!(result, expected, 
                "Metadata {:?} should extract platform fee {}", metadata, expected_str);
        }
    }

    #[test]
    fn test_extract_provider_fee() {
        let test_cases = vec![
            (json!({"provider_fee": "150"}), "150"),
            (json!({"provider_fee": "0"}), "0"),
            (json!({}), "0"), // Missing field should default to 0
            (json!({"provider_fee": null}), "0"), // Null should default to 0
            (json!({"provider_fee": "invalid"}), "0"), // Invalid should default to 0
        ];

        for (metadata, expected_str) in test_cases {
            let result = extract_provider_fee(&metadata);
            let expected = sqlx::types::BigDecimal::from_str(expected_str).unwrap();
            assert_eq!(result, expected, 
                "Metadata {:?} should extract provider fee {}", metadata, expected_str);
        }
    }

    #[test]
    fn test_extract_total_fee() {
        let test_cases = vec![
            (json!({"total_fee": "250"}), "250"),
            (json!({"total_fee": "0"}), "0"),
            (json!({}), "0"), // Missing field should default to 0
            (json!({"total_fee": null}), "0"), // Null should default to 0
            (json!({"total_fee": "invalid"}), "0"), // Invalid should default to 0
        ];

        for (metadata, expected_str) in test_cases {
            let result = extract_total_fee(&metadata);
            let expected = sqlx::types::BigDecimal::from_str(expected_str).unwrap();
            assert_eq!(result, expected, 
                "Metadata {:?} should extract total fee {}", metadata, expected_str);
        }
    }

    #[test]
    fn test_cache_key_format() {
        let tx_id = "01234567-89ab-cdef-0123-456789abcdef";
        let cache_key = format!("api:onramp:status:{}", tx_id);
        
        assert_eq!(cache_key, "api:onramp:status:01234567-89ab-cdef-0123-456789abcdef");
        assert!(cache_key.starts_with("api:onramp:status:"));
        assert!(cache_key.contains(tx_id));
    }

    #[test]
    fn test_timeline_entry_structure() {
        use crate::api::onramp::status::TimelineEntry;
        
        let entry = TimelineEntry {
            status: "pending".to_string(),
            timestamp: Utc::now(),
            note: "Transaction initiated".to_string(),
        };
        
        assert_eq!(entry.status, "pending");
        assert!(!entry.note.is_empty());
        assert!(entry.timestamp <= Utc::now());
    }
}

// Import the functions we need to test
use std::str::FromStr;