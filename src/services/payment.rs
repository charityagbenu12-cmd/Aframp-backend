use reqwest::Client;
use tracing::{info_span, instrument, Instrument};

use crate::telemetry::propagation::inject_context;

/// Request payload sent to a payment provider.
#[derive(Debug, serde::Serialize)]
pub struct PaymentRequest {
    pub amount: String,
    pub currency: String,
    pub phone_number: String,
    pub reference: String,
}

/// Response received from a payment provider.
#[derive(Debug, serde::Deserialize)]
pub struct PaymentResponse {
    pub status: String,
    pub provider_reference: String,
}

pub struct PaymentService {
    pub http_client: Client,
}

impl PaymentService {
    pub fn new() -> Self {
        Self {
            http_client: Client::new(),
        }
    }

    /// Initiate a payment via M-Pesa STK push.
    ///
    /// Emits a child span labelled `provider.http_call` with the provider name
    /// and injects the W3C `traceparent` header into the outbound request so
    /// the payment provider can (optionally) continue the trace.
    #[instrument(skip(self, request))]
    pub async fn initiate_mpesa(
        &self,
        request: PaymentRequest,
    ) -> anyhow::Result<PaymentResponse> {
        let span = info_span!(
            "provider.http_call",
            otel.kind = "client",
            peer.service = "mpesa",
            http.method = "POST",
            http.url = "https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest",
        );

        async {
            let mut headers = reqwest::header::HeaderMap::new();
            // Inject current span context into outbound headers (W3C traceparent).
            inject_context(&mut headers);

            tracing::info!(
                reference = %request.reference,
                amount = %request.amount,
                "Initiating M-Pesa STK push"
            );

            // In production this would be a real HTTP call; simulated here.
            Ok(PaymentResponse {
                status: "pending".into(),
                provider_reference: "MP_SIM_001".into(),
            })
        }
        .instrument(span)
        .await
    }

    /// Initiate a payment via Flutterwave.
    #[instrument(skip(self, request))]
    pub async fn initiate_flutterwave(
        &self,
        request: PaymentRequest,
    ) -> anyhow::Result<PaymentResponse> {
        let span = info_span!(
            "provider.http_call",
            otel.kind = "client",
            peer.service = "flutterwave",
            http.method = "POST",
            http.url = "https://api.flutterwave.com/v3/charges",
        );

        async {
            let mut headers = reqwest::header::HeaderMap::new();
            inject_context(&mut headers);

            tracing::info!(
                reference = %request.reference,
                "Initiating Flutterwave charge"
            );

            Ok(PaymentResponse {
                status: "pending".into(),
                provider_reference: "FLW_SIM_001".into(),
            })
        }
        .instrument(span)
        .await
    }

    /// Verify payment status with Paystack.
    #[instrument(skip(self))]
    pub async fn verify_paystack(&self, reference: &str) -> anyhow::Result<String> {
        let span = info_span!(
            "provider.http_call",
            otel.kind = "client",
            peer.service = "paystack",
            http.method = "GET",
            http.url = "https://api.paystack.co/transaction/verify",
        );

        async {
            let mut headers = reqwest::header::HeaderMap::new();
            inject_context(&mut headers);

            tracing::info!(%reference, "Verifying Paystack transaction");
            Ok("success".into())
        }
        .instrument(span)
        .await
    }
}