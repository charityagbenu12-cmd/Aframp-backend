//! Helper utilities and mocks for onramp E2E integration tests

use aframp_backend::payments::types::{
    Money, PaymentMethod, PaymentRequest, PaymentResponse, PaymentState, StatusRequest,
    StatusResponse, WebhookEvent, WebhookVerificationResult, WithdrawalMethod, WithdrawalRequest,
    WithdrawalResponse,
};
use serde_json::{json, Value as JsonValue};
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;

// ============================================================================
// Mock Payment Provider for Testing
// ============================================================================

/// Mock payment provider for testing webhook flows
pub struct MockPaymentProvider {
    pub initiated_payments: Arc<Mutex<Vec<PaymentRequest>>>,
    pub verified_payments: Arc<Mutex<Vec<StatusRequest>>>,
    pub webhook_events: Arc<Mutex<Vec<WebhookEvent>>>,
    pub should_fail: Arc<Mutex<bool>>,
}

impl MockPaymentProvider {
    pub fn new() -> Self {
        Self {
            initiated_payments: Arc::new(Mutex::new(Vec::new())),
            verified_payments: Arc::new(Mutex::new(Vec::new())),
            webhook_events: Arc::new(Mutex::new(Vec::new())),
            should_fail: Arc::new(Mutex::new(false)),
        }
    }

    pub async fn get_initiated_payments(&self) -> Vec<PaymentRequest> {
        self.initiated_payments.lock().await.clone()
    }

    pub async fn get_verified_payments(&self) -> Vec<StatusRequest> {
        self.verified_payments.lock().await.clone()
    }

    pub async fn set_should_fail(&self, should_fail: bool) {
        *self.should_fail.lock().await = should_fail;
    }

    /// Generate a mock webhook payload for payment confirmation
    pub fn generate_payment_confirmation_webhook(
        &self,
        transaction_reference: &str,
        amount: i64,
    ) -> JsonValue {
        json!({
            "event": "charge.completed",
            "data": {
                "id": Uuid::new_v4().to_string(),
                "tx_ref": transaction_reference,
                "amount": amount,
                "currency": "NGN",
                "status": "successful",
                "payment_type": "card",
                "customer": {
                    "id": 123456,
                    "email": "test@example.com",
                    "name": "Test User"
                },
                "created_at": chrono::Utc::now().to_rfc3339()
            }
        })
    }

    /// Generate a mock webhook payload for payment failure
    pub fn generate_payment_failure_webhook(
        &self,
        transaction_reference: &str,
        reason: &str,
    ) -> JsonValue {
        json!({
            "event": "charge.failed",
            "data": {
                "id": Uuid::new_v4().to_string(),
                "tx_ref": transaction_reference,
                "status": "failed",
                "reason": reason,
                "created_at": chrono::Utc::now().to_rfc3339()
            }
        })
    }

    /// Generate a mock webhook signature
    pub fn generate_webhook_signature(&self, payload: &JsonValue) -> String {
        use sha2::{Digest, Sha256};
        let payload_str = serde_json::to_string(payload).unwrap_or_default();
        let secret = "test_webhook_secret";
        let mut hasher = Sha256::new();
        hasher.update(format!("{}{}", payload_str, secret));
        format!("{:x}", hasher.finalize())
    }
}

impl Default for MockPaymentProvider {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Mock Stellar Client for Testing
// ============================================================================

/// Mock Stellar client for testing blockchain operations
pub struct MockStellarClient {
    pub submitted_transactions: Arc<Mutex<Vec<String>>>,
    pub confirmed_transactions: Arc<Mutex<Vec<String>>>,
    pub should_fail_submission: Arc<Mutex<bool>>,
    pub should_fail_confirmation: Arc<Mutex<bool>>,
}

impl MockStellarClient {
    pub fn new() -> Self {
        Self {
            submitted_transactions: Arc::new(Mutex::new(Vec::new())),
            confirmed_transactions: Arc::new(Mutex::new(Vec::new())),
            should_fail_submission: Arc::new(Mutex::new(false)),
            should_fail_confirmation: Arc::new(Mutex::new(false)),
        }
    }

    pub async fn get_submitted_transactions(&self) -> Vec<String> {
        self.submitted_transactions.lock().await.clone()
    }

    pub async fn get_confirmed_transactions(&self) -> Vec<String> {
        self.confirmed_transactions.lock().await.clone()
    }

    pub async fn set_should_fail_submission(&self, should_fail: bool) {
        *self.should_fail_submission.lock().await = should_fail;
    }

    pub async fn set_should_fail_confirmation(&self, should_fail: bool) {
        *self.should_fail_confirmation.lock().await = should_fail;
    }

    /// Generate a mock Stellar transaction hash
    pub fn generate_transaction_hash() -> String {
        format!("{:x}", sha2::Sha256::digest(Uuid::new_v4().as_bytes()))
    }

    /// Generate a mock Stellar account sequence number
    pub fn generate_sequence_number() -> i64 {
        rand::random::<i64>().abs()
    }
}

impl Default for MockStellarClient {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Test Data Builders
// ============================================================================

/// Builder for creating test payment requests
pub struct PaymentRequestBuilder {
    amount: i64,
    currency: String,
    customer_email: String,
    transaction_reference: String,
    payment_method: String,
}

impl PaymentRequestBuilder {
    pub fn new() -> Self {
        Self {
            amount: 50_000,
            currency: "NGN".to_string(),
            customer_email: "test@example.com".to_string(),
            transaction_reference: Uuid::new_v4().to_string(),
            payment_method: "card".to_string(),
        }
    }

    pub fn with_amount(mut self, amount: i64) -> Self {
        self.amount = amount;
        self
    }

    pub fn with_currency(mut self, currency: &str) -> Self {
        self.currency = currency.to_string();
        self
    }

    pub fn with_customer_email(mut self, email: &str) -> Self {
        self.customer_email = email.to_string();
        self
    }

    pub fn with_transaction_reference(mut self, reference: &str) -> Self {
        self.transaction_reference = reference.to_string();
        self
    }

    pub fn with_payment_method(mut self, method: &str) -> Self {
        self.payment_method = method.to_string();
        self
    }

    pub fn build(self) -> JsonValue {
        json!({
            "amount": self.amount,
            "currency": self.currency,
            "customer": {
                "email": self.customer_email,
                "name": "Test User"
            },
            "tx_ref": self.transaction_reference,
            "payment_method": self.payment_method,
            "redirect_url": "https://example.com/callback"
        })
    }
}

impl Default for PaymentRequestBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for creating test webhook payloads
pub struct WebhookPayloadBuilder {
    event_type: String,
    transaction_reference: String,
    status: String,
    amount: i64,
    currency: String,
    provider: String,
}

impl WebhookPayloadBuilder {
    pub fn new() -> Self {
        Self {
            event_type: "charge.completed".to_string(),
            transaction_reference: Uuid::new_v4().to_string(),
            status: "successful".to_string(),
            amount: 50_000,
            currency: "NGN".to_string(),
            provider: "flutterwave".to_string(),
        }
    }

    pub fn with_event_type(mut self, event_type: &str) -> Self {
        self.event_type = event_type.to_string();
        self
    }

    pub fn with_transaction_reference(mut self, reference: &str) -> Self {
        self.transaction_reference = reference.to_string();
        self
    }

    pub fn with_status(mut self, status: &str) -> Self {
        self.status = status.to_string();
        self
    }

    pub fn with_amount(mut self, amount: i64) -> Self {
        self.amount = amount;
        self
    }

    pub fn with_provider(mut self, provider: &str) -> Self {
        self.provider = provider.to_string();
        self
    }

    pub fn build_flutterwave(self) -> JsonValue {
        json!({
            "event": self.event_type,
            "data": {
                "id": Uuid::new_v4().to_string(),
                "tx_ref": self.transaction_reference,
                "amount": self.amount,
                "currency": self.currency,
                "status": self.status,
                "payment_type": "card",
                "customer": {
                    "id": 123456,
                    "email": "test@example.com",
                    "name": "Test User"
                },
                "created_at": chrono::Utc::now().to_rfc3339()
            }
        })
    }

    pub fn build_paystack(self) -> JsonValue {
        json!({
            "event": self.event_type,
            "data": {
                "id": Uuid::new_v4().to_string(),
                "reference": self.transaction_reference,
                "amount": self.amount * 100, // Paystack uses kobo
                "currency": self.currency,
                "status": self.status,
                "customer": {
                    "id": 123456,
                    "email": "test@example.com",
                    "first_name": "Test",
                    "last_name": "User"
                },
                "created_at": chrono::Utc::now().timestamp()
            }
        })
    }

    pub fn build_mpesa(self) -> JsonValue {
        json!({
            "event": self.event_type,
            "data": {
                "transaction_id": Uuid::new_v4().to_string(),
                "reference": self.transaction_reference,
                "amount": self.amount,
                "currency": self.currency,
                "status": self.status,
                "phone_number": "+254712345678",
                "created_at": chrono::Utc::now().to_rfc3339()
            }
        })
    }
}

impl Default for WebhookPayloadBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Assertion Helpers
// ============================================================================

/// Assert transaction state is correct
pub fn assert_transaction_state(
    transaction: &serde_json::Value,
    expected_status: &str,
    expected_provider: Option<&str>,
) {
    assert_eq!(
        transaction["status"].as_str(),
        Some(expected_status),
        "Transaction status mismatch"
    );

    if let Some(provider) = expected_provider {
        assert_eq!(
            transaction["payment_provider"].as_str(),
            Some(provider),
            "Payment provider mismatch"
        );
    }
}

/// Assert quote is valid
pub fn assert_quote_valid(quote: &serde_json::Value) {
    assert!(quote["quote_id"].is_string(), "quote_id must be present");
    assert!(quote["amount_ngn"].is_number(), "amount_ngn must be present");
    assert!(quote["exchange_rate"].is_string(), "exchange_rate must be present");
    assert!(quote["gross_cngn"].is_string(), "gross_cngn must be present");
    assert!(quote["fee_cngn"].is_string(), "fee_cngn must be present");
    assert!(quote["net_cngn"].is_string(), "net_cngn must be present");
    assert!(quote["expires_at"].is_string(), "expires_at must be present");
}

/// Assert webhook payload is valid
pub fn assert_webhook_payload_valid(payload: &JsonValue) {
    assert!(payload["event"].is_string(), "event must be present");
    assert!(payload["data"].is_object(), "data must be present");
    assert!(
        payload["data"]["tx_ref"].is_string() || payload["data"]["reference"].is_string(),
        "transaction reference must be present"
    );
}

// ============================================================================
// Test Constants
// ============================================================================

pub const TEST_WALLET_ADDRESS: &str =
    "GBUQWP3BOUZX34ULNQG23RQ6F4BVWCIEAL7EFZO5HLRUES5CTUWV5G7U";
pub const TEST_AMOUNT_NGN_MIN: i64 = 1_000;
pub const TEST_AMOUNT_NGN_NORMAL: i64 = 50_000;
pub const TEST_AMOUNT_NGN_MAX: i64 = 5_000_000;
pub const TEST_EXCHANGE_RATE: &str = "0.0025";
pub const TEST_QUOTE_TTL_SECS: u64 = 180;
pub const TEST_PAYMENT_TIMEOUT_MINS: u64 = 30;

// ============================================================================
// Retry and Polling Helpers
// ============================================================================

/// Poll a condition with exponential backoff
pub async fn poll_with_backoff<F, T>(
    mut condition: F,
    max_attempts: u32,
    initial_delay_ms: u64,
) -> Result<T, String>
where
    F: FnMut() -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<T>>>>,
{
    let mut delay = initial_delay_ms;
    for attempt in 0..max_attempts {
        if let Some(result) = condition().await {
            return Ok(result);
        }
        if attempt < max_attempts - 1 {
            tokio::time::sleep(tokio::time::Duration::from_millis(delay)).await;
            delay = (delay * 2).min(5000); // Cap at 5 seconds
        }
    }
    Err(format!(
        "Condition not met after {} attempts",
        max_attempts
    ))
}

/// Wait for transaction to reach a specific status
pub async fn wait_for_transaction_status(
    db_pool: &sqlx::PgPool,
    transaction_id: uuid::Uuid,
    expected_status: &str,
    timeout_secs: u64,
) -> Result<(), String> {
    let start = std::time::Instant::now();
    loop {
        let result: Option<(String,)> = sqlx::query_as(
            "SELECT status FROM transactions WHERE transaction_id = $1"
        )
        .bind(transaction_id)
        .fetch_optional(db_pool)
        .await
        .map_err(|e| e.to_string())?;

        if let Some((status,)) = result {
            if status == expected_status {
                return Ok(());
            }
        }

        if start.elapsed().as_secs() > timeout_secs {
            return Err(format!(
                "Timeout waiting for transaction status: {}",
                expected_status
            ));
        }

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    }
}

/// Wait for webhook event to be processed
pub async fn wait_for_webhook_event(
    db_pool: &sqlx::PgPool,
    event_id: &str,
    timeout_secs: u64,
) -> Result<(), String> {
    let start = std::time::Instant::now();
    loop {
        let result: Option<(String,)> = sqlx::query_as(
            "SELECT status FROM webhook_events WHERE event_id = $1"
        )
        .bind(event_id)
        .fetch_optional(db_pool)
        .await
        .map_err(|e| e.to_string())?;

        if let Some((status,)) = result {
            if status == "completed" {
                return Ok(());
            }
        }

        if start.elapsed().as_secs() > timeout_secs {
            return Err("Timeout waiting for webhook event".to_string());
        }

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    }
}
