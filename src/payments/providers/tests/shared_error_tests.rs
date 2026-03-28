//! Shared provider error handling tests.
//!
//! Covers: network timeout, non-200 HTTP status codes, rate limiting,
//! retry eligibility, and malformed responses — all via wiremock mocks.

use crate::payments::error::PaymentError;
use crate::payments::provider::PaymentProvider;
use crate::payments::providers::flutterwave::{FlutterwaveConfig, FlutterwaveProvider};
use crate::payments::providers::paystack::{PaystackConfig, PaystackProvider};
use crate::payments::types::{
    CustomerContact, Money, PaymentMethod, PaymentRequest, StatusRequest,
};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

// ── helpers ───────────────────────────────────────────────────────────────────

fn flutterwave(base_url: &str) -> FlutterwaveProvider {
    FlutterwaveProvider::new(FlutterwaveConfig {
        secret_key: "sk_test".to_string(),
        webhook_secret: Some("wh_secret".to_string()),
        base_url: base_url.to_string(),
        timeout_secs: 5,
        max_retries: 0, // no retries — tests must be deterministic
    })
    .unwrap()
}

fn paystack(base_url: &str) -> PaystackProvider {
    PaystackProvider::new(PaystackConfig {
        public_key: None,
        secret_key: "sk_test".to_string(),
        webhook_secret: None,
        base_url: base_url.to_string(),
        timeout_secs: 5,
        max_retries: 0,
    })
    .unwrap()
}

fn payment_request() -> PaymentRequest {
    PaymentRequest {
        amount: Money {
            amount: "1000".to_string(),
            currency: "NGN".to_string(),
        },
        customer: CustomerContact {
            email: Some("user@example.com".to_string()),
            phone: None,
        },
        payment_method: PaymentMethod::Card,
        callback_url: None,
        transaction_reference: "txn_shared_001".to_string(),
        metadata: None,
    }
}

// ── non-200 HTTP status codes ─────────────────────────────────────────────────

#[tokio::test]
async fn flutterwave_returns_provider_error_on_400() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/payments"))
        .respond_with(ResponseTemplate::new(400).set_body_string("Bad Request"))
        .mount(&server)
        .await;

    let err = flutterwave(&server.uri())
        .initiate_payment(payment_request())
        .await
        .expect_err("should fail on 400");

    assert!(
        matches!(err, PaymentError::ProviderError { .. } | PaymentError::ValidationError { .. }),
        "unexpected error variant: {:?}",
        err
    );
}

#[tokio::test]
async fn flutterwave_returns_provider_error_on_401() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/payments"))
        .respond_with(ResponseTemplate::new(401).set_body_string("Unauthorized"))
        .mount(&server)
        .await;

    let err = flutterwave(&server.uri())
        .initiate_payment(payment_request())
        .await
        .expect_err("should fail on 401");

    assert!(matches!(err, PaymentError::ProviderError { .. }));
}

#[tokio::test]
async fn flutterwave_returns_provider_error_on_500() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/payments"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
        .mount(&server)
        .await;

    let err = flutterwave(&server.uri())
        .initiate_payment(payment_request())
        .await
        .expect_err("should fail on 500");

    assert!(matches!(err, PaymentError::ProviderError { .. }));
}

#[tokio::test]
async fn paystack_returns_provider_error_on_400() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/transaction/initialize"))
        .respond_with(ResponseTemplate::new(400).set_body_string("Bad Request"))
        .mount(&server)
        .await;

    let err = paystack(&server.uri())
        .initiate_payment(payment_request())
        .await
        .expect_err("should fail on 400");

    assert!(matches!(err, PaymentError::ProviderError { .. }));
}

#[tokio::test]
async fn paystack_returns_provider_error_on_500() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/transaction/initialize"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Server Error"))
        .mount(&server)
        .await;

    let err = paystack(&server.uri())
        .initiate_payment(payment_request())
        .await
        .expect_err("should fail on 500");

    assert!(matches!(err, PaymentError::ProviderError { .. }));
}

// ── rate limit (429) handling ─────────────────────────────────────────────────

#[tokio::test]
async fn flutterwave_returns_rate_limit_error_on_429() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/payments"))
        .respond_with(ResponseTemplate::new(429).set_body_string("Too Many Requests"))
        .mount(&server)
        .await;

    let err = flutterwave(&server.uri())
        .initiate_payment(payment_request())
        .await
        .expect_err("should fail on 429");

    assert!(
        matches!(err, PaymentError::RateLimitError { .. }),
        "expected RateLimitError, got: {:?}",
        err
    );
}

#[tokio::test]
async fn paystack_returns_rate_limit_error_on_429() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/transaction/initialize"))
        .respond_with(ResponseTemplate::new(429).set_body_string("Too Many Requests"))
        .mount(&server)
        .await;

    let err = paystack(&server.uri())
        .initiate_payment(payment_request())
        .await
        .expect_err("should fail on 429");

    assert!(
        matches!(err, PaymentError::RateLimitError { .. }),
        "expected RateLimitError, got: {:?}",
        err
    );
}

#[tokio::test]
async fn flutterwave_verify_payment_returns_rate_limit_error_on_429() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/transactions/verify_by_reference"))
        .respond_with(ResponseTemplate::new(429).set_body_string("Too Many Requests"))
        .mount(&server)
        .await;

    let err = flutterwave(&server.uri())
        .verify_payment(StatusRequest {
            transaction_reference: Some("txn_shared_001".to_string()),
            provider_reference: None,
        })
        .await
        .expect_err("should fail on 429");

    assert!(matches!(err, PaymentError::RateLimitError { .. }));
}

// ── network timeout simulation ────────────────────────────────────────────────

#[tokio::test]
async fn flutterwave_returns_network_error_when_server_unreachable() {
    // Port 1 is reserved and will refuse connections immediately
    let provider = FlutterwaveProvider::new(FlutterwaveConfig {
        secret_key: "sk_test".to_string(),
        webhook_secret: Some("wh".to_string()),
        base_url: "http://127.0.0.1:1".to_string(),
        timeout_secs: 2,
        max_retries: 0,
    })
    .unwrap();

    let err = provider
        .initiate_payment(payment_request())
        .await
        .expect_err("should fail when server is unreachable");

    assert!(
        matches!(err, PaymentError::NetworkError { .. } | PaymentError::ProviderError { .. }),
        "unexpected error variant: {:?}",
        err
    );
}

#[tokio::test]
async fn paystack_returns_network_error_when_server_unreachable() {
    let provider = PaystackProvider::new(PaystackConfig {
        public_key: None,
        secret_key: "sk_test".to_string(),
        webhook_secret: None,
        base_url: "http://127.0.0.1:1".to_string(),
        timeout_secs: 2,
        max_retries: 0,
    })
    .unwrap();

    let err = provider
        .initiate_payment(payment_request())
        .await
        .expect_err("should fail when server is unreachable");

    assert!(
        matches!(err, PaymentError::NetworkError { .. } | PaymentError::ProviderError { .. }),
        "unexpected error variant: {:?}",
        err
    );
}

// ── retry eligibility per error type ─────────────────────────────────────────

#[test]
fn network_error_is_retryable() {
    let err = PaymentError::NetworkError {
        message: "connection refused".to_string(),
    };
    assert!(err.is_retryable());
}

#[test]
fn rate_limit_error_is_retryable() {
    let err = PaymentError::RateLimitError {
        message: "too many requests".to_string(),
        retry_after_seconds: Some(30),
    };
    assert!(err.is_retryable());
}

#[test]
fn provider_error_with_retryable_true_is_retryable() {
    let err = PaymentError::ProviderError {
        provider: "flutterwave".to_string(),
        message: "server error".to_string(),
        provider_code: Some("500".to_string()),
        retryable: true,
    };
    assert!(err.is_retryable());
}

#[test]
fn provider_error_with_retryable_false_is_not_retryable() {
    let err = PaymentError::ProviderError {
        provider: "paystack".to_string(),
        message: "invalid key".to_string(),
        provider_code: Some("401".to_string()),
        retryable: false,
    };
    assert!(!err.is_retryable());
}

#[test]
fn validation_error_is_not_retryable() {
    let err = PaymentError::ValidationError {
        message: "email required".to_string(),
        field: Some("email".to_string()),
    };
    assert!(!err.is_retryable());
}

#[test]
fn payment_declined_error_is_not_retryable() {
    let err = PaymentError::PaymentDeclinedError {
        message: "do not honor".to_string(),
        provider_code: Some("05".to_string()),
    };
    assert!(!err.is_retryable());
}

#[test]
fn insufficient_funds_error_is_not_retryable() {
    let err = PaymentError::InsufficientFundsError {
        message: "low balance".to_string(),
    };
    assert!(!err.is_retryable());
}

#[test]
fn webhook_verification_error_is_not_retryable() {
    let err = PaymentError::WebhookVerificationError {
        message: "invalid signature".to_string(),
    };
    assert!(!err.is_retryable());
}

// ── malformed response bodies ─────────────────────────────────────────────────

#[tokio::test]
async fn flutterwave_handles_empty_response_body_gracefully() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/payments"))
        .respond_with(ResponseTemplate::new(200).set_body_string(""))
        .mount(&server)
        .await;

    let err = flutterwave(&server.uri())
        .initiate_payment(payment_request())
        .await
        .expect_err("should fail on empty body");

    assert!(matches!(err, PaymentError::ProviderError { .. }));
}

#[tokio::test]
async fn flutterwave_handles_html_response_body_gracefully() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/payments"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("<html><body>Gateway Error</body></html>"),
        )
        .mount(&server)
        .await;

    let err = flutterwave(&server.uri())
        .initiate_payment(payment_request())
        .await
        .expect_err("should fail on HTML body");

    assert!(matches!(err, PaymentError::ProviderError { .. }));
}

#[tokio::test]
async fn paystack_handles_empty_response_body_gracefully() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/transaction/initialize"))
        .respond_with(ResponseTemplate::new(200).set_body_string(""))
        .mount(&server)
        .await;

    let err = paystack(&server.uri())
        .initiate_payment(payment_request())
        .await
        .expect_err("should fail on empty body");

    assert!(matches!(err, PaymentError::ProviderError { .. }));
}

#[tokio::test]
async fn paystack_handles_partial_json_response_gracefully() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/transaction/initialize"))
        .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"status":true"#))
        .mount(&server)
        .await;

    let err = paystack(&server.uri())
        .initiate_payment(payment_request())
        .await
        .expect_err("should fail on truncated JSON");

    assert!(matches!(err, PaymentError::ProviderError { .. }));
}

#[tokio::test]
async fn flutterwave_verify_payment_handles_malformed_body_gracefully() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/transactions/verify_by_reference"))
        .respond_with(ResponseTemplate::new(200).set_body_string("null"))
        .mount(&server)
        .await;

    let err = flutterwave(&server.uri())
        .verify_payment(StatusRequest {
            transaction_reference: Some("txn_shared_001".to_string()),
            provider_reference: None,
        })
        .await
        .expect_err("should fail on null body");

    assert!(matches!(err, PaymentError::ProviderError { .. }));
}
