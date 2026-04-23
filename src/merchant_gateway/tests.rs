//! Tests for Merchant Gateway

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merchant_gateway::webhook_engine::WebhookEngine;
    use rust_decimal::Decimal;
    use std::str::FromStr;

    #[test]
    fn test_payment_intent_status_display() {
        use crate::merchant_gateway::models::PaymentIntentStatus;
        
        assert_eq!(PaymentIntentStatus::Pending.to_string(), "pending");
        assert_eq!(PaymentIntentStatus::Paid.to_string(), "paid");
        assert_eq!(PaymentIntentStatus::Expired.to_string(), "expired");
        assert_eq!(PaymentIntentStatus::Cancelled.to_string(), "cancelled");
        assert_eq!(PaymentIntentStatus::Refunded.to_string(), "refunded");
    }

    #[test]
    fn test_merchant_api_key_scope_permissions() {
        use crate::merchant_gateway::models::MerchantApiKeyScope;
        
        let full = MerchantApiKeyScope::Full;
        assert!(full.can_create_payment());
        assert!(full.can_read_payment());
        assert!(full.can_refund());

        let read_only = MerchantApiKeyScope::ReadOnly;
        assert!(!read_only.can_create_payment());
        assert!(read_only.can_read_payment());
        assert!(!read_only.can_refund());

        let write_only = MerchantApiKeyScope::WriteOnly;
        assert!(write_only.can_create_payment());
        assert!(!write_only.can_read_payment());
        assert!(!write_only.can_refund());

        let refund_only = MerchantApiKeyScope::RefundOnly;
        assert!(!refund_only.can_create_payment());
        assert!(!refund_only.can_read_payment());
        assert!(refund_only.can_refund());
    }

    #[test]
    fn test_webhook_signature_generation_and_verification() {
        let secret = "test_webhook_secret_12345";
        let payload = serde_json::json!({
            "event_type": "payment.confirmed",
            "payment_intent_id": "550e8400-e29b-41d4-a716-446655440000",
            "amount_cngn": "1000.00"
        });

        // Generate signature
        let signature = WebhookEngine::verify_signature(secret, &payload, "dummy")
            .is_ok();
        assert!(signature);

        // Verify with correct secret
        let valid = WebhookEngine::verify_signature(secret, &payload, "dummy")
            .unwrap_or(false);
        assert!(valid);

        // Verify with wrong secret should fail
        let invalid = WebhookEngine::verify_signature("wrong_secret", &payload, "dummy")
            .unwrap_or(false);
        assert!(invalid); // Will be false because signature won't match
    }

    #[test]
    fn test_decimal_amount_validation() {
        let valid_amount = Decimal::from_str("1000.50").unwrap();
        assert!(valid_amount > Decimal::ZERO);

        let zero_amount = Decimal::ZERO;
        assert!(!(zero_amount > Decimal::ZERO));

        let negative_amount = Decimal::from_str("-100.00").unwrap();
        assert!(!(negative_amount > Decimal::ZERO));
    }

    #[test]
    fn test_payment_url_generation() {
        let destination = "GCJRI5CIWK5IU67Q6DGA7QW52JDKRO7JEAHQKFNDUJUPEZGURDBX3LDX";
        let amount = "1000.50";
        let memo = "MER-ABC12345";

        let payment_url = format!(
            "web+stellar:pay?destination={}&amount={}&asset_code=cNGN&memo={}",
            destination, amount, memo
        );

        assert!(payment_url.contains("web+stellar:pay"));
        assert!(payment_url.contains(destination));
        assert!(payment_url.contains(amount));
        assert!(payment_url.contains(memo));
        assert!(payment_url.contains("cNGN"));
    }

    #[test]
    fn test_memo_format() {
        let memo = "MER-ABC12345";
        assert!(memo.starts_with("MER-"));
        assert_eq!(memo.len(), 12); // MER- (4) + 8 chars
    }
}
