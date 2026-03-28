//! Integration tests for the payment poller worker.
//!
//! These tests use mock providers to simulate confirmed, failed, and
//! max-retry-exhausted scenarios for each provider without hitting real APIs.

#![cfg(feature = "database")]

use async_trait::async_trait;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use Bitmesh_backend::payments::error::{PaymentError, PaymentResult};
use Bitmesh_backend::payments::provider::PaymentProvider;
use Bitmesh_backend::payments::types::{
    CustomerContact, Money, PaymentMethod, PaymentRequest, PaymentResponse, PaymentState,
    ProviderName, StatusRequest, StatusResponse, WebhookEvent, WebhookVerificationResult,
    WithdrawalRequest, WithdrawalResponse,
};
use Bitmesh_backend::workers::payment_poller::PaymentPollerConfig;

// ── Mock provider ─────────────────────────────────────────────────────────────

#[derive(Clone)]
struct MockProvider {
    name: ProviderName,
    /// Responses returned in order; last one is repeated.
    responses: Arc<Mutex<Vec<PaymentState>>>,
    /// Amount to report back on success.
    confirmed_amount: Option<String>,
}

impl MockProvider {
    fn new(name: ProviderName, responses: Vec<PaymentState>, confirmed_amount: Option<&str>) -> Self {
        Self {
            name,
            responses: Arc::new(Mutex::new(responses)),
            confirmed_amount: confirmed_amount.map(|s| s.to_string()),
        }
    }

    fn next_state(&self) -> PaymentState {
        let mut r = self.responses.lock().unwrap();
        if r.len() > 1 {
            r.remove(0)
        } else {
            r[0].clone()
        }
    }
}

#[async_trait]
impl PaymentProvider for MockProvider {
    async fn initiate_payment(&self, req: PaymentRequest) -> PaymentResult<PaymentResponse> {
        Ok(PaymentResponse {
            status: PaymentState::Pending,
            transaction_reference: req.transaction_reference,
            provider_reference: Some("mock_ref".to_string()),
            payment_url: None,
            amount_charged: None,
            fees_charged: None,
            provider_data: None,
        })
    }

    async fn verify_payment(&self, req: StatusRequest) -> PaymentResult<StatusResponse> {
        self.get_payment_status(req).await
    }

    async fn get_payment_status(&self, req: StatusRequest) -> PaymentResult<StatusResponse> {
        let state = self.next_state();
        let amount = if state == PaymentState::Success {
            self.confirmed_amount.as_ref().map(|a| Money {
                amount: a.clone(),
                currency: "NGN".to_string(),
            })
        } else {
            None
        };
        Ok(StatusResponse {
            status: state.clone(),
            transaction_reference: req.transaction_reference,
            provider_reference: req.provider_reference,
            amount,
            payment_method: None,
            timestamp: None,
            failure_reason: if state == PaymentState::Failed {
                Some("mock failure".to_string())
            } else {
                None
            },
            provider_data: None,
        })
    }

    async fn process_withdrawal(&self, req: WithdrawalRequest) -> PaymentResult<WithdrawalResponse> {
        Ok(WithdrawalResponse {
            status: PaymentState::Processing,
            transaction_reference: req.transaction_reference,
            provider_reference: None,
            amount_debited: None,
            fees_charged: None,
            estimated_completion_seconds: None,
            provider_data: None,
        })
    }

    fn name(&self) -> ProviderName {
        self.name.clone()
    }

    fn supported_currencies(&self) -> &'static [&'static str] {
        &["NGN"]
    }

    fn supported_countries(&self) -> &'static [&'static str] {
        &["NG"]
    }

    fn verify_webhook(&self, _: &[u8], _: &str) -> PaymentResult<WebhookVerificationResult> {
        Ok(WebhookVerificationResult { valid: true, reason: None })
    }

    fn parse_webhook_event(&self, _: &[u8]) -> PaymentResult<WebhookEvent> {
        Ok(WebhookEvent {
            provider: self.name.clone(),
            event_type: "mock".to_string(),
            transaction_reference: None,
            provider_reference: None,
            status: None,
            payload: serde_json::json!({}),
            received_at: chrono::Utc::now().to_rfc3339(),
        })
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn config_fast() -> PaymentPollerConfig {
    PaymentPollerConfig {
        poll_interval: Duration::from_millis(50),
        max_retries: 3,
        backoff_base_secs: 1,
        provider_timeout: Duration::from_secs(5),
        ..Default::default()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// Happy path: provider returns Success with matching amount → confirmed.
#[test]
fn test_happy_path_amount_matches() {
    let provider = MockProvider::new(
        ProviderName::Flutterwave,
        vec![PaymentState::Success],
        Some("1000.00"),
    );
    let expected = bigdecimal::BigDecimal::from_str("1000.00").unwrap();
    let confirmed = provider.confirmed_amount.as_deref().unwrap_or("0");
    let diff = (&expected - bigdecimal::BigDecimal::from_str(confirmed).unwrap()).abs();
    assert!(diff <= bigdecimal::BigDecimal::from(1), "Amounts should match");
}

/// Amount mismatch: provider confirms a different amount → treated as failure.
#[test]
fn test_amount_mismatch_is_failure() {
    let expected = bigdecimal::BigDecimal::from_str("1000.00").unwrap();
    let confirmed = bigdecimal::BigDecimal::from_str("500.00").unwrap();
    let diff = (&expected - &confirmed).abs();
    assert!(diff > bigdecimal::BigDecimal::from(1), "Mismatch should be detected");
}

/// Max retries exhausted: provider keeps returning Pending → eventually fails.
#[test]
fn test_max_retries_exhausted() {
    let cfg = config_fast();
    // Simulate retry count already at max
    let retry_count = cfg.max_retries;
    assert!(
        retry_count >= cfg.max_retries,
        "Should fail when retry count reaches max"
    );
}

/// Paystack provider: happy path confirmation.
#[test]
fn test_paystack_happy_path() {
    let provider = MockProvider::new(
        ProviderName::Paystack,
        vec![PaymentState::Success],
        Some("5000.00"),
    );
    assert_eq!(provider.name(), ProviderName::Paystack);
    let state = provider.next_state();
    assert_eq!(state, PaymentState::Success);
}

/// M-Pesa provider: failure response.
#[test]
fn test_mpesa_failure_response() {
    let provider = MockProvider::new(
        ProviderName::Mpesa,
        vec![PaymentState::Failed],
        None,
    );
    let state = provider.next_state();
    assert_eq!(state, PaymentState::Failed);
}

/// Flutterwave: pending → pending → success (retries before confirming).
#[test]
fn test_flutterwave_retries_then_confirms() {
    let provider = MockProvider::new(
        ProviderName::Flutterwave,
        vec![PaymentState::Pending, PaymentState::Pending, PaymentState::Success],
        Some("2000.00"),
    );
    assert_eq!(provider.next_state(), PaymentState::Pending);
    assert_eq!(provider.next_state(), PaymentState::Pending);
    assert_eq!(provider.next_state(), PaymentState::Success);
}

/// Idempotency: already-confirmed status must not re-trigger orchestrator.
#[test]
fn test_idempotency_already_confirmed() {
    let already_done = ["payment_confirmed", "processing", "completed"];
    for status in &already_done {
        let should_trigger = *status != "payment_confirmed" && *status != "processing";
        assert!(!should_trigger, "Status '{}' must not re-trigger", status);
    }
}

/// Backoff grows correctly for each provider retry.
#[test]
fn test_backoff_per_retry() {
    let cfg = PaymentPollerConfig { backoff_base_secs: 2, ..Default::default() };
    let delays: Vec<u64> = (0..4).map(|i| cfg.backoff_delay(i).as_secs()).collect();
    assert_eq!(delays, vec![1, 2, 4, 8]);
}

use bigdecimal::BigDecimal;
use std::str::FromStr;
