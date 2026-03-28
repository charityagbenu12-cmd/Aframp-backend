//! Unit tests for the Flutterwave payment provider adapter.
//!
//! All HTTP interactions are intercepted by wiremock — no real network calls.

use crate::payments::provider::PaymentProvider;
use crate::payments::providers::flutterwave::{FlutterwaveConfig, FlutterwaveProvider};
use crate::payments::types::{
    CustomerContact, Money, PaymentMethod, PaymentRequest, PaymentState, StatusRequest,
    WithdrawalMethod, WithdrawalRecipient, WithdrawalRequest,
};
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

// ── helpers ──────────────────────────────────────────────────────────────────

fn provider_with_base(base_url: &str) -> FlutterwaveProvider {
    FlutterwaveProvider::new(FlutterwaveConfig {
        secret_key: "FLWSECK_TEST_demo".to_string(),
        webhook_secret: Some("webhook_hash_secret".to_string()),
        base_url: base_url.to_string(),
        timeout_secs: 5,
        max_retries: 0, // no retries so tests are fast
    })
    .expect("provider init should succeed")
}

fn payment_request() -> PaymentRequest {
    PaymentRequest {
        amount: Money {
            amount: "5000".to_string(),
            currency: "NGN".to_string(),
        },
        customer: CustomerContact {
            email: Some("user@example.com".to_string()),
            phone: Some("+2348012345678".to_string()),
        },
        payment_method: PaymentMethod::Card,
        callback_url: Some("https://example.com/callback".to_string()),
        transaction_reference: "txn_flw_001".to_string(),
        metadata: None,
    }
}

fn withdrawal_request() -> WithdrawalRequest {
    WithdrawalRequest {
        amount: Money {
            amount: "2000".to_string(),
            currency: "NGN".to_string(),
        },
        recipient: WithdrawalRecipient {
            account_name: Some("John Doe".to_string()),
            account_number: Some("0123456789".to_string()),
            bank_code: Some("058".to_string()),
            phone_number: None,
        },
        withdrawal_method: WithdrawalMethod::BankTransfer,
        transaction_reference: "wd_flw_001".to_string(),
        reason: Some("Payout".to_string()),
        metadata: None,
    }
}

// ── initiate_payment ──────────────────────────────────────────────────────────

#[tokio::test]
async fn initiate_payment_constructs_correct_request_and_parses_success() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/payments"))
        .and(header("Authorization", "Bearer FLWSECK_TEST_demo"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "status": "success",
            "message": "Hosted Link",
            "data": {
                "link": "https://checkout.flutterwave.com/pay/abc123",
                "tx_ref": "txn_flw_001"
            }
        })))
        .mount(&server)
        .await;

    let provider = provider_with_base(&server.uri());
    let response = provider
        .initiate_payment(payment_request())
        .await
        .expect("initiation should succeed");

    assert_eq!(response.status, PaymentState::Pending);
    assert_eq!(response.transaction_reference, "txn_flw_001");
    assert_eq!(
        response.payment_url.as_deref(),
        Some("https://checkout.flutterwave.com/pay/abc123")
    );
}

#[tokio::test]
async fn initiate_payment_uses_checkout_url_fallback() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/payments"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "status": "success",
            "message": "Hosted Link",
            "data": {
                "checkout_url": "https://checkout.flutterwave.com/pay/fallback"
            }
        })))
        .mount(&server)
        .await;

    let provider = provider_with_base(&server.uri());
    let response = provider
        .initiate_payment(payment_request())
        .await
        .expect("initiation should succeed");

    assert_eq!(
        response.payment_url.as_deref(),
        Some("https://checkout.flutterwave.com/pay/fallback")
    );
}

#[tokio::test]
async fn initiate_payment_returns_error_when_status_not_success() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/payments"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "status": "error",
            "message": "Invalid key",
            "data": null
        })))
        .mount(&server)
        .await;

    let provider = provider_with_base(&server.uri());
    let err = provider
        .initiate_payment(payment_request())
        .await
        .expect_err("should fail on error status");

    let msg = err.to_string();
    assert!(
        msg.contains("Invalid key") || msg.contains("invalid"),
        "unexpected error: {}",
        msg
    );
}

#[tokio::test]
async fn initiate_payment_fails_when_payment_link_missing() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/payments"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "status": "success",
            "message": "ok",
            "data": { "tx_ref": "txn_flw_001" }
        })))
        .mount(&server)
        .await;

    let provider = provider_with_base(&server.uri());
    let err = provider
        .initiate_payment(payment_request())
        .await
        .expect_err("should fail when link is absent");

    assert!(err.to_string().contains("missing payment link"));
}

#[tokio::test]
async fn initiate_payment_validates_empty_transaction_reference() {
    let provider = provider_with_base("http://localhost:9999");
    let mut req = payment_request();
    req.transaction_reference = "  ".to_string();

    let err = provider
        .initiate_payment(req)
        .await
        .expect_err("should fail on empty tx ref");

    assert!(err.to_string().contains("transaction_reference"));
}

#[tokio::test]
async fn initiate_payment_validates_missing_email() {
    let provider = provider_with_base("http://localhost:9999");
    let mut req = payment_request();
    req.customer.email = None;

    let err = provider
        .initiate_payment(req)
        .await
        .expect_err("should fail on missing email");

    assert!(err.to_string().contains("email"));
}

#[tokio::test]
async fn initiate_payment_validates_zero_amount() {
    let provider = provider_with_base("http://localhost:9999");
    let mut req = payment_request();
    req.amount.amount = "0".to_string();

    let err = provider
        .initiate_payment(req)
        .await
        .expect_err("should fail on zero amount");

    assert!(err.to_string().contains("amount"));
}

// ── verify_payment ────────────────────────────────────────────────────────────

#[tokio::test]
async fn verify_payment_parses_successful_response() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/transactions/verify_by_reference"))
        .and(query_param("tx_ref", "txn_flw_001"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "status": "success",
            "message": "Transaction fetched",
            "data": {
                "status": "successful",
                "tx_ref": "txn_flw_001",
                "flw_ref": "FLW-MOCK-123",
                "amount": 5000,
                "currency": "NGN",
                "payment_type": "card",
                "created_at": "2026-03-01T10:00:00Z"
            }
        })))
        .mount(&server)
        .await;

    let provider = provider_with_base(&server.uri());
    let response = provider
        .verify_payment(StatusRequest {
            transaction_reference: Some("txn_flw_001".to_string()),
            provider_reference: None,
        })
        .await
        .expect("verification should succeed");

    assert_eq!(response.status, PaymentState::Success);
    assert_eq!(
        response.provider_reference.as_deref(),
        Some("FLW-MOCK-123")
    );
    assert_eq!(
        response.payment_method,
        Some(PaymentMethod::Card)
    );
}

#[tokio::test]
async fn verify_payment_maps_failed_status() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/transactions/verify_by_reference"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "status": "success",
            "message": "Transaction fetched",
            "data": {
                "status": "failed",
                "tx_ref": "txn_flw_001",
                "flw_ref": "FLW-MOCK-456",
                "amount": 5000,
                "currency": "NGN",
                "payment_type": "card",
                "processor_response": "Insufficient funds"
            }
        })))
        .mount(&server)
        .await;

    let provider = provider_with_base(&server.uri());
    let response = provider
        .verify_payment(StatusRequest {
            transaction_reference: Some("txn_flw_001".to_string()),
            provider_reference: None,
        })
        .await
        .expect("should parse failed response without error");

    assert_eq!(response.status, PaymentState::Failed);
    assert_eq!(
        response.failure_reason.as_deref(),
        Some("Insufficient funds")
    );
}

#[tokio::test]
async fn verify_payment_returns_error_when_provider_status_error() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/transactions/verify_by_reference"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "status": "error",
            "message": "Transaction not found",
            "data": null
        })))
        .mount(&server)
        .await;

    let provider = provider_with_base(&server.uri());
    let err = provider
        .verify_payment(StatusRequest {
            transaction_reference: Some("txn_flw_001".to_string()),
            provider_reference: None,
        })
        .await
        .expect_err("should fail on error status");

    assert!(err.to_string().contains("not found") || err.to_string().contains("Transaction"));
}

#[tokio::test]
async fn verify_payment_requires_reference() {
    let provider = provider_with_base("http://localhost:9999");
    let err = provider
        .verify_payment(StatusRequest {
            transaction_reference: None,
            provider_reference: None,
        })
        .await
        .expect_err("should fail without reference");

    assert!(err.to_string().contains("reference"));
}

// ── process_withdrawal ────────────────────────────────────────────────────────

#[tokio::test]
async fn process_withdrawal_constructs_correct_request_and_parses_success() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/transfers"))
        .and(header("Authorization", "Bearer FLWSECK_TEST_demo"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "status": "success",
            "message": "Transfer Queued Successfully",
            "data": {
                "id": 12345,
                "reference": "wd_flw_001",
                "status": "NEW",
                "amount": 2000,
                "currency": "NGN"
            }
        })))
        .mount(&server)
        .await;

    let provider = provider_with_base(&server.uri());
    let response = provider
        .process_withdrawal(withdrawal_request())
        .await
        .expect("withdrawal should succeed");

    assert_eq!(response.transaction_reference, "wd_flw_001");
    assert_eq!(response.status, PaymentState::Processing);
    assert!(response.provider_reference.is_some());
}

#[tokio::test]
async fn process_withdrawal_maps_successful_transfer_status() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/transfers"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "status": "success",
            "message": "Transfer Queued Successfully",
            "data": {
                "id": 99,
                "reference": "wd_flw_002",
                "status": "SUCCESSFUL",
                "amount": 2000,
                "currency": "NGN"
            }
        })))
        .mount(&server)
        .await;

    let provider = provider_with_base(&server.uri());
    let response = provider
        .process_withdrawal(withdrawal_request())
        .await
        .expect("withdrawal should succeed");

    assert_eq!(response.status, PaymentState::Success);
}

#[tokio::test]
async fn process_withdrawal_returns_error_on_provider_failure() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/transfers"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "status": "error",
            "message": "Insufficient balance",
            "data": null
        })))
        .mount(&server)
        .await;

    let provider = provider_with_base(&server.uri());
    let err = provider
        .process_withdrawal(withdrawal_request())
        .await
        .expect_err("should fail on provider error");

    // "insufficient" triggers InsufficientFundsError
    assert!(err.to_string().to_lowercase().contains("insufficient"));
}

#[tokio::test]
async fn process_withdrawal_rejects_non_bank_transfer_method() {
    let provider = provider_with_base("http://localhost:9999");
    let mut req = withdrawal_request();
    req.withdrawal_method = WithdrawalMethod::MobileMoney;

    let err = provider
        .process_withdrawal(req)
        .await
        .expect_err("should reject mobile money");

    assert!(err.to_string().contains("bank transfer"));
}

#[tokio::test]
async fn process_withdrawal_requires_account_number() {
    let provider = provider_with_base("http://localhost:9999");
    let mut req = withdrawal_request();
    req.recipient.account_number = None;

    let err = provider
        .process_withdrawal(req)
        .await
        .expect_err("should fail without account number");

    assert!(err.to_string().contains("account_number"));
}

#[tokio::test]
async fn process_withdrawal_requires_bank_code() {
    let provider = provider_with_base("http://localhost:9999");
    let mut req = withdrawal_request();
    req.recipient.bank_code = None;

    let err = provider
        .process_withdrawal(req)
        .await
        .expect_err("should fail without bank code");

    assert!(err.to_string().contains("bank_code"));
}

// ── webhook signature verification ───────────────────────────────────────────

#[test]
fn verify_webhook_accepts_valid_signature() {
    let provider = provider_with_base("http://localhost:9999");
    let result = provider
        .verify_webhook(br#"{"event":"charge.completed"}"#, "webhook_hash_secret")
        .expect("should not error");

    assert!(result.valid, "valid signature should be accepted");
    assert!(result.reason.is_none());
}

#[test]
fn verify_webhook_rejects_tampered_signature() {
    let provider = provider_with_base("http://localhost:9999");
    let result = provider
        .verify_webhook(br#"{"event":"charge.completed"}"#, "wrong_hash")
        .expect("should not error");

    assert!(!result.valid, "tampered signature should be rejected");
    assert!(result.reason.is_some());
}

#[test]
fn verify_webhook_rejects_empty_signature() {
    let provider = provider_with_base("http://localhost:9999");
    let result = provider
        .verify_webhook(br#"{"event":"charge.completed"}"#, "")
        .expect("should not error");

    assert!(!result.valid);
}

#[test]
fn verify_webhook_errors_when_secret_not_configured() {
    let provider = FlutterwaveProvider::new(FlutterwaveConfig {
        secret_key: "sk".to_string(),
        webhook_secret: None, // no secret configured
        base_url: "http://localhost:9999".to_string(),
        timeout_secs: 5,
        max_retries: 0,
    })
    .unwrap();

    let err = provider
        .verify_webhook(b"payload", "sig")
        .expect_err("should error when secret is missing");

    assert!(err.to_string().contains("not configured"));
}

// ── parse_webhook_event ───────────────────────────────────────────────────────

#[test]
fn parse_webhook_event_maps_all_fields_correctly() {
    let provider = provider_with_base("http://localhost:9999");
    let payload = br#"{
        "event": "charge.completed",
        "data": {
            "status": "successful",
            "tx_ref": "txn_flw_001",
            "flw_ref": "FLW-MOCK-789",
            "amount": 5000
        }
    }"#;

    let event = provider
        .parse_webhook_event(payload)
        .expect("should parse successfully");

    assert_eq!(event.event_type, "charge.completed");
    assert_eq!(
        event.transaction_reference.as_deref(),
        Some("txn_flw_001")
    );
    assert_eq!(
        event.provider_reference.as_deref(),
        Some("FLW-MOCK-789")
    );
    assert!(matches!(event.status, Some(PaymentState::Success)));
}

#[test]
fn parse_webhook_event_maps_failed_status() {
    let provider = provider_with_base("http://localhost:9999");
    let payload = br#"{
        "event": "charge.completed",
        "data": { "status": "failed", "tx_ref": "txn_flw_002" }
    }"#;

    let event = provider
        .parse_webhook_event(payload)
        .expect("should parse");

    assert!(matches!(event.status, Some(PaymentState::Failed)));
}

#[test]
fn parse_webhook_event_handles_malformed_json() {
    let provider = provider_with_base("http://localhost:9999");
    let err = provider
        .parse_webhook_event(b"not valid json {{{{")
        .expect_err("should fail on malformed JSON");

    assert!(err.to_string().contains("invalid webhook JSON"));
}

#[test]
fn parse_webhook_event_handles_missing_data_fields_gracefully() {
    let provider = provider_with_base("http://localhost:9999");
    // Valid JSON but missing all optional fields
    let event = provider
        .parse_webhook_event(br#"{"event":"unknown_event"}"#)
        .expect("should not panic on missing fields");

    assert_eq!(event.event_type, "unknown_event");
    assert!(event.transaction_reference.is_none());
    assert!(event.provider_reference.is_none());
    assert!(event.status.is_none());
}
