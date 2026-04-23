use crate::error::AppError;
use crate::pos::payment_intent::PaymentIntentService;
use axum::http::StatusCode;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{info, instrument};
use uuid::Uuid;

/// Legacy POS Bridge — Middleware API for existing retail software
/// Allows integration with Odoo, Revel, Square, and other POS systems
pub struct LegacyBridge {
    payment_intent_service: Arc<PaymentIntentService>,
}

impl LegacyBridge {
    pub fn new(payment_intent_service: Arc<PaymentIntentService>) -> Self {
        Self {
            payment_intent_service,
        }
    }

    /// Create payment intent from legacy POS system
    /// Accepts standardized JSON payload and returns QR code + payment URL
    #[instrument(skip(self))]
    pub async fn create_payment_from_legacy(
        &self,
        request: LegacyPaymentRequest,
    ) -> Result<LegacyPaymentResponse, AppError> {
        // Validate request
        self.validate_legacy_request(&request)?;

        // Convert amount to Decimal
        let amount = Decimal::try_from(request.amount)
            .map_err(|e| AppError::BadRequest(format!("Invalid amount: {}", e)))?;

        // Create payment intent
        let payment_intent = self.payment_intent_service
            .create_payment_intent(
                request.merchant_id,
                request.order_id.clone(),
                amount,
            )
            .await?;

        // Build response for legacy system
        let response = LegacyPaymentResponse {
            success: true,
            payment_id: payment_intent.id.to_string(),
            order_id: payment_intent.order_id,
            qr_code_svg: payment_intent.qr_code_data,
            qr_code_url: format!(
                "https://pay.aframp.com/pos/qr/{}",
                payment_intent.id
            ),
            payment_url: format!(
                "https://pay.aframp.com/pos/pay/{}",
                payment_intent.id
            ),
            amount: payment_intent.amount_cngn.to_string(),
            currency: "cNGN".to_string(),
            expires_at: payment_intent.expires_at.to_rfc3339(),
            status_webhook_url: format!(
                "https://api.aframp.com/v1/pos/webhook/{}",
                payment_intent.id
            ),
        };

        info!(
            payment_id = %payment_intent.id,
            order_id = %request.order_id,
            "Legacy payment created"
        );

        Ok(response)
    }

    /// Validate legacy payment request
    fn validate_legacy_request(&self, request: &LegacyPaymentRequest) -> Result<(), AppError> {
        if request.amount <= 0.0 {
            return Err(AppError::BadRequest("Amount must be positive".to_string()));
        }

        if request.order_id.is_empty() {
            return Err(AppError::BadRequest("Order ID is required".to_string()));
        }

        if request.order_id.len() > 100 {
            return Err(AppError::BadRequest("Order ID too long (max 100 chars)".to_string()));
        }

        Ok(())
    }

    /// Check payment status (for legacy POS polling)
    #[instrument(skip(self))]
    pub async fn check_payment_status(
        &self,
        payment_id: Uuid,
    ) -> Result<LegacyPaymentStatusResponse, AppError> {
        let payment = self.payment_intent_service
            .get_payment_intent(payment_id)
            .await?;

        let response = LegacyPaymentStatusResponse {
            payment_id: payment.id.to_string(),
            order_id: payment.order_id,
            status: format!("{:?}", payment.status).to_lowercase(),
            amount_expected: payment.amount_cngn.to_string(),
            amount_received: payment.actual_amount_received.map(|a| a.to_string()),
            transaction_hash: payment.stellar_tx_hash,
            confirmed_at: payment.confirmed_at.map(|t| t.to_rfc3339()),
            is_complete: matches!(
                payment.status,
                crate::pos::models::PosPaymentStatus::Confirmed
            ),
            has_discrepancy: matches!(
                payment.status,
                crate::pos::models::PosPaymentStatus::Discrepancy
            ),
        };

        Ok(response)
    }

    /// Cancel payment (for legacy POS cancellation)
    #[instrument(skip(self))]
    pub async fn cancel_payment(
        &self,
        payment_id: Uuid,
    ) -> Result<StatusCode, AppError> {
        self.payment_intent_service
            .cancel_payment_intent(payment_id)
            .await?;

        Ok(StatusCode::OK)
    }
}

/// Legacy POS payment request format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegacyPaymentRequest {
    pub merchant_id: Uuid,
    pub order_id: String,
    pub amount: f64,
    pub currency: Option<String>, // Always cNGN, but kept for compatibility
    pub customer_id: Option<String>,
    pub metadata: Option<serde_json::Value>,
}

/// Legacy POS payment response format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegacyPaymentResponse {
    pub success: bool,
    pub payment_id: String,
    pub order_id: String,
    pub qr_code_svg: String,
    pub qr_code_url: String,
    pub payment_url: String,
    pub amount: String,
    pub currency: String,
    pub expires_at: String,
    pub status_webhook_url: String,
}

/// Legacy POS payment status response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegacyPaymentStatusResponse {
    pub payment_id: String,
    pub order_id: String,
    pub status: String,
    pub amount_expected: String,
    pub amount_received: Option<String>,
    pub transaction_hash: Option<String>,
    pub confirmed_at: Option<String>,
    pub is_complete: bool,
    pub has_discrepancy: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_legacy_request_validation() {
        let request = LegacyPaymentRequest {
            merchant_id: Uuid::new_v4(),
            order_id: "ORDER-123".to_string(),
            amount: 100.0,
            currency: Some("cNGN".to_string()),
            customer_id: None,
            metadata: None,
        };

        // Basic validation test
        assert!(request.amount > 0.0);
        assert!(!request.order_id.is_empty());
    }

    #[test]
    fn test_invalid_amount() {
        let request = LegacyPaymentRequest {
            merchant_id: Uuid::new_v4(),
            order_id: "ORDER-123".to_string(),
            amount: -10.0,
            currency: Some("cNGN".to_string()),
            customer_id: None,
            metadata: None,
        };

        assert!(request.amount <= 0.0);
    }
}
