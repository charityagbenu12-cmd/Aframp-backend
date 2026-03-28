//! Unit tests for the Paystack payment provider adapter.
//!
//! All HTTP interactions are intercepted by wiremock — no real network calls.

use crate::payments::provider::PaymentProvider;
use crate::payments::providers::paystack::{PaystackConfig, PaystackProvider};
use crate::payments::types::{
    CustomerContact, Money, PaymentMethod, PaymentRequest, PaymentState, StatusRequest,
    WithdrawalMethod, WithdrawalRecipient, WithdrawalRequest,
};
use crate::payments::utils::verify_hmac_sha512_hex;
use hmac::{Hmac, Mac};
use sha2::Sha512;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

// ── helpers ──────────────────────────────────────────────────────────────────

fn provider_with_base(base_url: &str) -> PaystackProvider {
    PaystackProvider::new(PaystackConfig {
        public_key: Some("pk_test_demo".to_string()),
        secret_key: "sk_test_demo".to_string(),
        webhook_secret: Some("wh_secret_demo".to_string()),
        base_url: base_url.to_string(),
        timeout_secs: 5,
        max_retries: 0,
    })
    .expect("provider init should succeed")
}

fn payment_request() -> PaymentRequest {
    PaymentRequest {
        amount: Money {
            amount: "10000".to_string(),
            currency: "NGN".to_string(),
        },
        customer: CustomerContact {
            email: Some("customer@example.com".to_string()),
            phone: None,
        },
        payment_method: PaymentMethod::Card,
        callback_url: Some("https://example.com/callback".to_string()),
        transaction_reference: "txn_ps_001".to_string(),
        metadata: None,
    }
}

fn withdrawal_request() -> WithdrawalRequest {
    WithdrawalRequest {
        amount: Money {
            amount: "5000".to_string(),
            currency: "NGN".to_string(),
        },
        recipient: WithdrawalRecipient {
            account_name: Some("Jane Doe".to_string()),
            account_number: Some("0987654321".to_string()),
            bank_code: Some("033".to_string()),
            phone_number: None,
        },
        withdrawal_method: WithdrawalMethod::BankTransfer,
        transaction_reference: "wd_ps_001".to_string(),
        reason: Some("Salary".to_string()),
        metadata: None,
    }
}

/// Compute a valid HMAC-SHA512 hex signature for a payload using the test secret.
fn valid_hmac_signature(payload: &[u8], secret: &str) -> String {
    type HmacSha512 = Hmac<Sha512>;
    let mut mac = HmacSha512::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(payload);
    hex::encode(mac.finalize().into_bytes())
}

// ── initiate_payment ──────────────────────────────────────────────────────────

#[tokio::test]
async fn initiate_payment_constructs_correct_request_and_parses_success() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/transaction/initialize"))
        .and(header("Authorization", "Bearer sk_test_demo"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "status": true,
            "message": "Authorization URL created",
            "data": {
                "authorization_url": "https://checkout.paystack.com/abc123",
                "access_code": "acc_abc123",
                "reference": "txn_ps_001"
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
    assert_eq!(response.transaction_reference, "txn_ps_001");
    assert_eq!(
        response.payment_url.as_deref(),
        Some("https://checkout.paystack.com/abc123")
    );
    assert_eq!(
        response.provider_reference.as_deref(),
        Some("txn_ps_001")
    );
}

#[tokio::test]
async fn initiate_payment_returns_error_when_status_false() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/transaction/initialize"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "status": false,
            "message": "Invalid key",
            "data": {}
        })))
        .mount(&server)
        .await;

    let provider = provider_with_base(&server.uri());
    let err = provider
        .initiate_payment(payment_request())
        .await
        .expect_err("should fail when status is false");

    assert!(err.to_string().contains("Invalid key"));
}

#[tokio::test]
async fn initiate_payment_validates_missing_email() {
    let provider = provider_with_base("http://localhost:9999");
    let mut req = payment_request();
    req.customer.email = None;

    let err = provider
        .initiate_payment(req)
        .await
        .expect_err("should fail without email");

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

#[tokio::test]
async fn initiate_payment_handles_malformed_response_body() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/transaction/initialize"))
        .respond_with(ResponseTemplate::new(200).set_body_string("not json at all"))
        .mount(&server)
        .await;

    let provider = provider_with_base(&server.uri());
    let err = provider
        .initiate_payment(payment_request())
        .await
        .expect_err("should fail on malformed response");

    assert!(
        err.to_string().contains("invalid provider JSON")
            || err.to_string().contains("JSON"),
        "unexpected error: {}",
        err
    );
}

// ── verify_payment ────────────────────────────────────────────────────────────

#[tokio::test]
async fn verify_payment_parses_successful_response() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/transaction/verify/txn_ps_001"))
        .and(header("Authorization", "Bearer sk_test_demo"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "status": true,
            "message": "Verification successful",
            "data": {
                "status": "success",
                "amount": 10000,
                "currency": "NGN",
                "channel": "card",
                "paid_at": "2026-03-01T10:00:00.000Z",
                "gateway_response": "Approved"
            }
        })))
        .mount(&server)
        .await;

    let provider = provider_with_base(&server.uri());
    let response = provider
        .verify_payment(StatusRequest {
            transaction_reference: None,
            provider_reference: Some("txn_ps_001".to_string()),
        })
        .await
        .expect("verification should succeed");

    assert_eq!(response.status, PaymentState::Success);
    assert_eq!(response.payment_method, Some(PaymentMethod::Card));
    assert!(response.amount.is_some());
}

#[tokio::test]
async fn verify_payment_maps_abandoned_to_cancelled() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/transaction/verify/txn_ps_002"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "status": true,
            "message": "Verification successful",
            "data": {
                "status": "abandoned",
                "amount": 10000,
                "currency": "NGN",
                "channel": "card"
            }
        })))
        .mount(&server)
        .await;

    let provider = provider_with_base(&server.uri());
    let response = provider
        .verify_payment(StatusRequest {
            provider_reference: Some("txn_ps_002".to_string()),
            transaction_reference: None,
        })
        .await
        .expect("should parse abandoned status");

    assert_eq!(response.status, PaymentState::Cancelled);
}

#[tokio::test]
async fn verify_payment_maps_failed_status() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/transaction/verify/txn_ps_003"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "status": true,
            "message": "Verification successful",
            "data": {
                "status": "failed",
                "amount": 10000,
                "currency": "NGN",
                "channel": "bank",
                "gateway_response": "Declined"
            }
        })))
        .mount(&server)
        .await;

    let provider = provider_with_base(&server.uri());
    let response = provider
        .verify_payment(StatusRequest {
            provider_reference: Some("txn_ps_003".to_string()),
            transaction_reference: None,
        })
        .await
        .expect("should parse failed status");

    assert_eq!(response.status, PaymentState::Failed);
    assert_eq!(response.failure_reason.as_deref(), Some("Declined"));
}

#[tokio::test]
async fn verify_payment_returns_error_when_status_false() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/transaction/verify/txn_ps_001"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "status": false,
            "message": "Transaction reference not found",
            "data": {}
        })))
        .mount(&server)
        .await;

    let provider = provider_with_base(&server.uri());
    let err = provider
        .verify_payment(StatusRequest {
            provider_reference: Some("txn_ps_001".to_string()),
            transaction_reference: None,
        })
        .await
        .expect_err("should fail when status is false");

    assert!(err.to_string().contains("not found") || err.to_string().contains("reference"));
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

#[tokio::test]
async fn verify_payment_handles_malformed_response_body() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/transaction/verify/txn_ps_001"))
        .respond_with(ResponseTemplate::new(200).set_body_string("{broken json"))
        .mount(&server)
        .await;

    let provider = provider_with_base(&server.uri());
    let err = provider
        .verify_payment(StatusRequest {
            provider_reference: Some("txn_ps_001".to_string()),
            transaction_reference: None,
        })
        .await
        .expect_err("should fail on malformed JSON");

    assert!(err.to_string().contains("JSON") || err.to_string().contains("invalid"));
}

// ── process_withdrawal ────────────────────────────────────────────────────────

#[tokio::test]
async fn process_withdrawal_constructs_correct_request_and_parses_success() {
    let server = MockServer::start().await;

    // First call: create recipient
    Mock::given(method("POST"))
        .and(path("/transferrecipient"))
        .and(header("Authorization", "Bearer sk_test_demo"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "status": true,
            "message": "Transfer recipient created successfully",
            "data": {
                "recipient_code": "RCP_abc123"
            }
        })))
        .mount(&server)
        .await;

    // Second call: initiate transfer
    Mock::given(method("POST"))
        .and(path("/transfer"))
        .and(header("Authorization", "Bearer sk_test_demo"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "status": true,
            "message": "Transfer has been queued",
            "data": {
                "transfer_code": "TRF_xyz789",
                "reference": "wd_ps_001",
                "status": "pending",
                "failure_reason": null
            }
        })))
        .mount(&server)
        .await;

    let provider = provider_with_base(&server.uri());
    let response = provider
        .process_withdrawal(withdrawal_request())
        .await
        .expect("withdrawal should succeed");

    assert_eq!(response.transaction_reference, "wd_ps_001");
    assert_eq!(response.status, PaymentState::Processing);
    assert_eq!(
        response.provider_reference.as_deref(),
        Some("wd_ps_001")
    );
}

#[tokio::test]
async fn process_withdrawal_maps_success_transfer_status() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/transferrecipient"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "status": true,
            "message": "ok",
            "data": { "recipient_code": "RCP_success" }
        })))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/transfer"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "status": true,
            "message": "Transfer has been queued",
            "data": {
                "transfer_code": "TRF_ok",
                "reference": "wd_ps_001",
                "status": "success"
            }
        })))
        .mount(&server)
        .await;

    let provider = provider_with_base(&server.uri());
    let response = provider
        .process_withdrawal(withdrawal_request())
        .await
        .expect("should succeed");

    assert_eq!(response.status, PaymentState::Success);
}

#[tokio::test]
async fn process_withdrawal_returns_error_when_recipient_creation_fails() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/transferrecipient"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "status": false,
            "message": "Invalid bank account",
            "data": {}
        })))
        .mount(&server)
        .await;

    let provider = provider_with_base(&server.uri());
    let err = provider
        .process_withdrawal(withdrawal_request())
        .await
        .expect_err("should fail when recipient creation fails");

    assert!(err.to_string().contains("Invalid bank account"));
}

#[tokio::test]
async fn process_withdrawal_returns_error_when_transfer_fails() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/transferrecipient"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "status": true,
            "message": "ok",
            "data": { "recipient_code": "RCP_fail" }
        })))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/transfer"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "status": false,
            "message": "Insufficient balance",
            "data": {}
        })))
        .mount(&server)
        .await;

    let provider = provider_with_base(&server.uri());
    let err = provider
        .process_withdrawal(withdrawal_request())
        .await
        .expect_err("should fail when transfer fails");

    assert!(err.to_string().contains("Insufficient balance"));
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
fn verify_webhook_accepts_valid_hmac_sha512_signature() {
    let provider = provider_with_base("http://localhost:9999");
    let payload = br#"{"event":"charge.success","data":{"reference":"txn_ps_001"}}"#;
    let sig = valid_hmac_signature(payload, "wh_secret_demo");

    let result = provider
        .verify_webhook(payload, &sig)
        .expect("should not error");

    assert!(result.valid, "valid HMAC signature should be accepted");
    assert!(result.reason.is_none());
}

#[test]
fn verify_webhook_rejects_tampered_signature() {
    let provider = provider_with_base("http://localhost:9999");
    let payload = br#"{"event":"charge.success"}"#;

    let result = provider
        .verify_webhook(payload, "deadbeefdeadbeef")
        .expect("should not error");

    assert!(!result.valid, "tampered signature should be rejected");
    assert!(result.reason.is_some());
}

#[test]
fn verify_webhook_rejects_empty_signature() {
    let provider = provider_with_base("http://localhost:9999");
    let result = provider
        .verify_webhook(b"payload", "")
        .expect("should not error");

    assert!(!result.valid);
}

#[test]
fn verify_webhook_falls_back_to_secret_key_when_no_webhook_secret() {
    // When webhook_secret is None, Paystack falls back to secret_key
    let provider = PaystackProvider::new(PaystackConfig {
        public_key: None,
        secret_key: "sk_fallback".to_string(),
        webhook_secret: None,
        base_url: "http://localhost:9999".to_string(),
        timeout_secs: 5,
        max_retries: 0,
    })
    .unwrap();

    let payload = b"test payload";
    let sig = valid_hmac_signature(payload, "sk_fallback");

    let result = provider.verify_webhook(payload, &sig).unwrap();
    assert!(result.valid);
}

#[test]
fn verify_hmac_sha512_hex_utility_works_correctly() {
    let payload = b"hello world";
    let secret = "my_secret";
    let sig = valid_hmac_signature(payload, secret);

    assert!(verify_hmac_sha512_hex(payload, secret, &sig));
    assert!(!verify_hmac_sha512_hex(payload, secret, "wrong"));
    assert!(!verify_hmac_sha512_hex(b"different", secret, &sig));
}

// ── parse_webhook_event ───────────────────────────────────────────────────────

#[test]
fn parse_webhook_event_maps_charge_success() {
    let provider = provider_with_base("http://localhost:9999");
    let payload = br#"{
        "event": "charge.success",
        "data": {
            "reference": "txn_ps_001",
            "status": "success"
        }
    }"#;

    let event = provider
        .parse_webhook_event(payload)
        .expect("should parse successfully");

    assert_eq!(event.event_type, "charge.success");
    assert_eq!(
        event.provider_reference.as_deref(),
        Some("txn_ps_001")
    );
    assert!(matches!(event.status, Some(PaymentState::Success)));
}

#[test]
fn parse_webhook_event_maps_failed_status() {
    let provider = provider_with_base("http://localhost:9999");
    let payload = br#"{
        "event": "charge.failed",
        "data": { "reference": "txn_ps_002", "status": "failed" }
    }"#;

    let event = provider.parse_webhook_event(payload).expect("should parse");
    assert!(matches!(event.status, Some(PaymentState::Failed)));
}

#[test]
fn parse_webhook_event_handles_malformed_json() {
    let provider = provider_with_base("http://localhost:9999");
    let err = provider
        .parse_webhook_event(b"{{not valid json")
        .expect_err("should fail on malformed JSON");

    assert!(err.to_string().contains("invalid webhook JSON"));
}

#[test]
fn parse_webhook_event_handles_missing_optional_fields_gracefully() {
    let provider = provider_with_base("http://localhost:9999");
    let event = provider
        .parse_webhook_event(br#"{"event":"transfer.success"}"#)
        .expect("should not panic on missing fields");

    assert_eq!(event.event_type, "transfer.success");
    assert!(event.provider_reference.is_none());
    assert!(event.status.is_none());
}
