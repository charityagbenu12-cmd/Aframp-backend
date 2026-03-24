use crate::payments::error::PaymentResult;
use crate::payments::provider::PaymentProvider;
use crate::payments::types::{
    PaymentRequest, PaymentResponse, PaymentState, ProviderName, StatusRequest, StatusResponse,
    WebhookEvent, WebhookVerificationResult, WithdrawalRequest, WithdrawalResponse,
};
use async_trait::async_trait;

pub struct MockProvider;

impl MockProvider {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl PaymentProvider for MockProvider {
    async fn initiate_payment(&self, request: PaymentRequest) -> PaymentResult<PaymentResponse> {
        Ok(PaymentResponse {
            status: PaymentState::Pending,
            transaction_reference: request.transaction_reference,
            provider_reference: Some("mock_ref".to_string()),
            payment_url: Some("https://mock.payment.url".to_string()),
            amount_charged: Some(request.amount),
            fees_charged: None,
            provider_data: None,
        })
    }

    async fn verify_payment(&self, request: StatusRequest) -> PaymentResult<StatusResponse> {
        Ok(StatusResponse {
            status: PaymentState::Success,
            transaction_reference: request.transaction_reference,
            provider_reference: request.provider_reference,
            amount: None,
            payment_method: None,
            timestamp: None,
            failure_reason: None,
            provider_data: None,
        })
    }

    async fn process_withdrawal(
        &self,
        request: WithdrawalRequest,
    ) -> PaymentResult<WithdrawalResponse> {
        Ok(WithdrawalResponse {
            status: PaymentState::Success,
            transaction_reference: request.transaction_reference,
            provider_reference: Some("mock_withdrawal_ref".to_string()),
            amount_debited: Some(request.amount),
            fees_charged: None,
            estimated_completion_seconds: Some(1),
            provider_data: None,
        })
    }

    async fn get_payment_status(&self, request: StatusRequest) -> PaymentResult<StatusResponse> {
        self.verify_payment(request).await
    }

    fn name(&self) -> ProviderName {
        ProviderName::Mock
    }

    fn supported_currencies(&self) -> &'static [&'static str] {
        &["NGN", "USD", "cNGN"]
    }

    fn supported_countries(&self) -> &'static [&'static str] {
        &["NG", "US"]
    }

    fn verify_webhook(
        &self,
        _payload: &[u8],
        _signature: &str,
    ) -> PaymentResult<WebhookVerificationResult> {
        Ok(WebhookVerificationResult {
            valid: true,
            reason: None,
        })
    }

    fn parse_webhook_event(&self, _payload: &[u8]) -> PaymentResult<WebhookEvent> {
        Ok(WebhookEvent {
            provider: ProviderName::Mock,
            event_type: "mock.event".to_string(),
            transaction_reference: None,
            provider_reference: None,
            status: Some(PaymentState::Success),
            payload: serde_json::json!({}),
            received_at: chrono::Utc::now().to_rfc3339(),
        })
    }
}
