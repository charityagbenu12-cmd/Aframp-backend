//! Unit tests for the M-Pesa payment provider adapter.
//!
//! M-Pesa methods currently return "not implemented yet" stubs.
//! These tests verify stub behaviour, webhook parsing, and adapter metadata.

use crate::payments::provider::PaymentProvider;
use crate::payments::providers::mpesa::{MpesaConfig, MpesaProvider};
use crate::payments::types::{
    CustomerContact, Money, PaymentMethod, PaymentRequest, PaymentState, ProviderName,
    StatusRequest, WithdrawalMethod, WithdrawalRecipient, WithdrawalRequest,
};

// ── helpers ───────────────────────────────────────────────────────────────────

fn provider() -> MpesaProvider {
    MpesaProvider::new(MpesaConfig {
        consumer_key: "test_consumer_key".to_string(),
        consumer_secret: "test_consumer_secret".to_string(),
        passkey: "test_passkey".to_string(),
    })
    .expect("provider init should succeed")
}

fn payment_request() -> PaymentRequest {
    PaymentRequest {
        amount: Money {
            amount: "1000".to_string(),
            currency: "KES".to_string(),
        },
        customer: CustomerContact {
            email: None,
            phone: Some("+254712345678".to_string()),
        },
        payment_method: PaymentMethod::MobileMoney,
        callback_url: Some("https://example.com/mpesa/callback".to_string()),
        transaction_reference: "txn_mpesa_001".to_string(),
        metadata: None,
    }
}

fn withdrawal_request() -> WithdrawalRequest {
    WithdrawalRequest {
        amount: Money {
            amount: "500".to_string(),
            currency: "KES".to_string(),
        },
        recipient: WithdrawalRecipient {
            account_name: None,
            account_number: None,
            bank_code: None,
            phone_number: Some("+254712345678".to_string()),
        },
        withdrawal_method: WithdrawalMethod::MobileMoney,
        transaction_reference: "wd_mpesa_001".to_string(),
        reason: Some("B2C payout".to_string()),
        metadata: None,
    }
}

// ── provider metadata ─────────────────────────────────────────────────────────

#[test]
fn provider_name_is_mpesa() {
    assert_eq!(provider().name(), ProviderName::Mpesa);
}

#[test]
fn supported_currencies_include_kes_tzs_ugx() {
    let c = provider().supported_currencies();
    assert!(c.contains(&"KES"));
    assert!(c.contains(&"TZS"));
    assert!(c.contains(&"UGX"));
}

#[test]
fn supported_countries_include_ke_tz_ug() {
    let c = provider().supported_countries();
    assert!(c.contains(&"KE"));
    assert!(c.contains(&"TZ"));
    assert!(c.contains(&"UG"));
}

// ── config validation ─────────────────────────────────────────────────────────

#[test]
fn mpesa_config_from_env_fails_when_keys_missing() {
    std::env::remove_var("MPESA_CONSUMER_KEY");
    std::env::remove_var("MPESA_CONSUMER_SECRET");
    std::env::remove_var("MPESA_PASSKEY");

    let err = MpesaConfig::from_env().expect_err("should fail without env vars");
    assert!(
        err.to_string().contains("MPESA_CONSUMER_KEY")
            || err.to_string().contains("required"),
        "unexpected error: {}",
        err
    );
}

// ── STK push — initiate_payment stub ─────────────────────────────────────────

#[tokio::test]
async fn stk_push_initiate_returns_not_implemented_error() {
    let err = provider()
        .initiate_payment(payment_request())
        .await
        .expect_err("stub should return error");

    assert!(
        err.to_string().contains("not implemented"),
        "unexpected error: {}",
        err
    );
}

#[tokio::test]
async fn stk_push_stub_error_is_not_retryable() {
    let err = provider()
        .initiate_payment(payment_request())
        .await
        .expect_err("stub should return error");

    assert!(!err.is_retryable(), "stub error should not be retryable");
}

// ── STK push response fixtures ────────────────────────────────────────────────

/// Successful STK push response fixture (Safaricom format).
fn stk_push_success_fixture() -> serde_json::Value {
    serde_json::json!({
        "MerchantRequestID": "29115-34620561-1",
        "CheckoutRequestID": "ws_CO_191220191020363925",
        "ResponseCode": "0",
        "ResponseDescription": "Success. Request accepted for processing",
        "CustomerMessage": "Success. Request accepted for processing"
    })
}

/// Failed / timeout STK push response fixture.
fn stk_push_failed_fixture() -> serde_json::Value {
    serde_json::json!({
        "MerchantRequestID": "29115-34620561-2",
        "CheckoutRequestID": "ws_CO_191220191020363926",
        "ResponseCode": "1032",
        "ResponseDescription": "Request cancelled by user",
        "CustomerMessage": "Request cancelled by user"
    })
}

#[test]
fn stk_push_success_fixture_has_response_code_zero() {
    let f = stk_push_success_fixture();
    assert_eq!(f["ResponseCode"], "0");
}

#[test]
fn stk_push_failed_fixture_has_non_zero_response_code() {
    let f = stk_push_failed_fixture();
    assert_ne!(f["ResponseCode"], "0");
    assert_eq!(f["ResponseCode"], "1032");
}

// ── verify_payment stub ───────────────────────────────────────────────────────

#[tokio::test]
async fn verify_payment_returns_not_implemented_error() {
    let err = provider()
        .verify_payment(StatusRequest {
            transaction_reference: Some("txn_mpesa_001".to_string()),
            provider_reference: None,
        })
        .await
        .expect_err("stub should return error");

    assert!(err.to_string().contains("not implemented"));
}

// ── B2C withdrawal stub ───────────────────────────────────────────────────────

#[tokio::test]
async fn b2c_withdrawal_returns_not_implemented_error() {
    let err = provider()
        .process_withdrawal(withdrawal_request())
        .await
        .expect_err("stub should return error");

    assert!(err.to_string().contains("not implemented"));
}

#[tokio::test]
async fn b2c_withdrawal_stub_error_is_not_retryable() {
    let err = provider()
        .process_withdrawal(withdrawal_request())
        .await
        .expect_err("stub should return error");

    assert!(!err.is_retryable());
}

/// Successful B2C response fixture (Safaricom format).
fn b2c_success_fixture() -> serde_json::Value {
    serde_json::json!({
        "ConversationID": "AG_20191219_00005797af5d7d75f652",
        "OriginatorConversationID": "16740-34861180-1",
        "ResponseCode": "0",
        "ResponseDescription": "Accept the service request successfully."
    })
}

/// Failed B2C response fixture.
fn b2c_failed_fixture() -> serde_json::Value {
    serde_json::json!({
        "requestId": "16740-34861180-2",
        "errorCode": "401.002.01",
        "errorMessage": "Error Occurred - Invalid Access Token"
    })
}

#[test]
fn b2c_success_fixture_has_response_code_zero() {
    assert_eq!(b2c_success_fixture()["ResponseCode"], "0");
}

#[test]
fn b2c_failed_fixture_has_error_code() {
    let f = b2c_failed_fixture();
    assert!(f["errorCode"].as_str().is_some());
}

// ── webhook / callback parsing ────────────────────────────────────────────────

#[test]
fn verify_webhook_returns_not_implemented_result() {
    let result = provider()
        .verify_webhook(b"payload", "any_sig")
        .expect("should not error");

    assert!(!result.valid, "stub should return valid=false");
    assert!(result.reason.is_some(), "stub should include a reason");
}

#[test]
fn verify_webhook_tampered_signature_also_returns_invalid() {
    let result = provider()
        .verify_webhook(b"payload", "tampered_sig_xyz")
        .expect("should not error");

    assert!(!result.valid);
}

#[test]
fn parse_webhook_event_parses_stk_callback_payload() {
    let payload = br#"{
        "Body": {
            "stkCallback": {
                "MerchantRequestID": "29115-34620561-1",
                "CheckoutRequestID": "ws_CO_191220191020363925",
                "ResultCode": 0,
                "ResultDesc": "The service request is processed successfully."
            }
        }
    }"#;

    let event = provider()
        .parse_webhook_event(payload)
        .expect("should parse without error");

    assert_eq!(event.provider, ProviderName::Mpesa);
    assert!(!event.event_type.is_empty());
    assert!(!event.received_at.is_empty());
}

#[test]
fn parse_webhook_event_handles_malformed_json_gracefully() {
    // Stub uses unwrap_or_else(|_| json!({})) — must NOT panic
    let event = provider()
        .parse_webhook_event(b"not valid json {{{{")
        .expect("stub must not panic on malformed JSON");

    assert_eq!(event.provider, ProviderName::Mpesa);
}

#[test]
fn parse_webhook_event_handles_empty_object_gracefully() {
    let event = provider()
        .parse_webhook_event(b"{}")
        .expect("should handle empty object");

    assert_eq!(event.provider, ProviderName::Mpesa);
    assert!(event.transaction_reference.is_none());
    assert!(event.provider_reference.is_none());
}

#[test]
fn parse_webhook_event_handles_unexpected_structure_gracefully() {
    let event = provider()
        .parse_webhook_event(br#"{"completely":"unexpected","nested":{"deep":true}}"#)
        .expect("should not panic on unexpected structure");

    assert_eq!(event.provider, ProviderName::Mpesa);
    assert!(event.transaction_reference.is_none());
}

#[test]
fn parse_webhook_event_sets_unknown_status_for_unrecognised_payload() {
    let event = provider()
        .parse_webhook_event(br#"{"event":"some_future_event"}"#)
        .expect("should parse");

    // Stub sets status to Some(PaymentState::Unknown)
    assert!(matches!(
        event.status,
        Some(PaymentState::Unknown) | None
    ));
}
