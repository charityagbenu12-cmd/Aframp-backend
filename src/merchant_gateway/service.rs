//! Business logic for Merchant Gateway

use crate::chains::stellar::client::StellarClient;
use crate::error::AppError;
use crate::merchant_gateway::models::*;
use crate::merchant_gateway::repository::*;
use crate::merchant_gateway::webhook_engine::WebhookEngine;
use chrono::{Duration, Utc};
use rust_decimal::Decimal;
use sqlx::PgPool;
use std::sync::Arc;
use tracing::{info, instrument, warn};
use uuid::Uuid;

// ============================================================================
// MERCHANT GATEWAY SERVICE
// ============================================================================

pub struct MerchantGatewayService {
    merchant_repo: Arc<MerchantRepository>,
    payment_intent_repo: Arc<PaymentIntentRepository>,
    webhook_engine: Arc<WebhookEngine>,
    stellar_client: Arc<StellarClient>,
    default_expiry_minutes: i64,
}

impl MerchantGatewayService {
    pub fn new(
        pool: PgPool,
        webhook_engine: Arc<WebhookEngine>,
        stellar_client: Arc<StellarClient>,
    ) -> Self {
        Self {
            merchant_repo: Arc::new(MerchantRepository::new(pool.clone())),
            payment_intent_repo: Arc::new(PaymentIntentRepository::new(pool.clone())),
            webhook_engine,
            stellar_client,
            default_expiry_minutes: 15,
        }
    }

    /// Create a new payment intent (invoice)
    /// Target: <300ms response time
    #[instrument(skip(self))]
    pub async fn create_payment_intent(
        &self,
        merchant_id: Uuid,
        request: CreatePaymentIntentRequest,
    ) -> Result<PaymentIntentResponse, AppError> {
        let start = std::time::Instant::now();

        // Validate merchant
        let merchant = self
            .merchant_repo
            .find_by_id(merchant_id)
            .await
            .map_err(|e| AppError::DatabaseError(e.to_string()))?
            .ok_or_else(|| AppError::NotFound("Merchant not found".to_string()))?;

        if !merchant.is_active {
            return Err(AppError::BadRequest("Merchant is not active".to_string()));
        }

        if merchant.kyb_status != "approved" {
            return Err(AppError::BadRequest(
                "Merchant KYB not approved".to_string(),
            ));
        }

        // Idempotency check
        if let Some(existing) = self
            .payment_intent_repo
            .find_by_merchant_reference(merchant_id, &request.merchant_reference)
            .await
            .map_err(|e| AppError::DatabaseError(e.to_string()))?
        {
            info!(
                payment_intent_id = %existing.id,
                merchant_reference = %request.merchant_reference,
                "Returning existing payment intent (idempotent)"
            );
            return Ok(self.build_payment_intent_response(existing));
        }

        // Validate amount
        if request.amount_cngn <= Decimal::ZERO {
            return Err(AppError::BadRequest("Amount must be positive".to_string()));
        }

        // Generate unique memo
        let memo = self.generate_unique_memo().await?;

        // Calculate expiry
        let expiry_minutes = request.expiry_minutes.unwrap_or(self.default_expiry_minutes);
        let expires_at = Utc::now() + Duration::minutes(expiry_minutes);

        // Create payment intent
        let payment_intent = self
            .payment_intent_repo
            .create(
                merchant_id,
                &request.merchant_reference,
                request.amount_cngn,
                &merchant.stellar_address,
                &memo,
                expires_at,
                request.customer_email.as_deref(),
                request.customer_phone.as_deref(),
                request.callback_url.as_deref(),
                request.metadata.unwrap_or_else(|| serde_json::json!({})),
            )
            .await
            .map_err(|e| AppError::DatabaseError(e.to_string()))?;

        let elapsed = start.elapsed();
        info!(
            payment_intent_id = %payment_intent.id,
            merchant_id = %merchant_id,
            merchant_reference = %request.merchant_reference,
            amount = %request.amount_cngn,
            elapsed_ms = elapsed.as_millis(),
            "Payment intent created"
        );

        // SLA check
        if elapsed.as_millis() > 300 {
            warn!(
                elapsed_ms = elapsed.as_millis(),
                "Payment intent creation exceeded 300ms SLA"
            );
        }

        Ok(self.build_payment_intent_response(payment_intent))
    }

    /// Get payment intent by ID
    #[instrument(skip(self))]
    pub async fn get_payment_intent(
        &self,
        merchant_id: Uuid,
        payment_intent_id: Uuid,
    ) -> Result<MerchantPaymentIntent, AppError> {
        let payment_intent = self
            .payment_intent_repo
            .find_by_id(payment_intent_id)
            .await
            .map_err(|e| AppError::DatabaseError(e.to_string()))?
            .ok_or_else(|| AppError::NotFound("Payment intent not found".to_string()))?;

        // Authorization check
        if payment_intent.merchant_id != merchant_id {
            return Err(AppError::Forbidden(
                "Not authorized to access this payment intent".to_string(),
            ));
        }

        Ok(payment_intent)
    }

    /// Cancel a pending payment intent
    #[instrument(skip(self))]
    pub async fn cancel_payment_intent(
        &self,
        merchant_id: Uuid,
        payment_intent_id: Uuid,
    ) -> Result<MerchantPaymentIntent, AppError> {
        let payment_intent = self.get_payment_intent(merchant_id, payment_intent_id).await?;

        if payment_intent.status != PaymentIntentStatus::Pending {
            return Err(AppError::BadRequest(
                "Can only cancel pending payment intents".to_string(),
            ));
        }

        let cancelled = self
            .payment_intent_repo
            .cancel(payment_intent_id)
            .await
            .map_err(|e| AppError::DatabaseError(e.to_string()))?;

        info!(
            payment_intent_id = %payment_intent_id,
            merchant_id = %merchant_id,
            "Payment intent cancelled"
        );

        // Send webhook notification
        let webhook_engine = self.webhook_engine.clone();
        let merchant_repo = self.merchant_repo.clone();
        tokio::spawn(async move {
            if let Ok(Some(merchant)) = merchant_repo.find_by_id(merchant_id).await {
                let _ = webhook_engine
                    .send_webhook(&merchant, &cancelled, "payment.cancelled")
                    .await;
            }
        });

        Ok(cancelled)
    }

    /// Process incoming Stellar payment (called by blockchain monitor)
    #[instrument(skip(self))]
    pub async fn process_stellar_payment(
        &self,
        memo: &str,
        stellar_tx_hash: &str,
        amount: Decimal,
        sender_address: &str,
    ) -> Result<(), AppError> {
        // Find payment intent by memo
        let payment_intent = self
            .payment_intent_repo
            .find_by_memo(memo)
            .await
            .map_err(|e| AppError::DatabaseError(e.to_string()))?
            .ok_or_else(|| AppError::NotFound(format!("No payment intent found for memo: {}", memo)))?;

        // Idempotency: already paid
        if payment_intent.status == PaymentIntentStatus::Paid {
            info!(
                payment_intent_id = %payment_intent.id,
                memo = %memo,
                "Payment already processed (idempotent)"
            );
            return Ok(());
        }

        // Check if expired
        if payment_intent.expires_at < Utc::now() {
            warn!(
                payment_intent_id = %payment_intent.id,
                memo = %memo,
                "Payment received for expired intent"
            );
            return Err(AppError::BadRequest("Payment intent has expired".to_string()));
        }

        // Validate amount (allow slight overpayment)
        if amount < payment_intent.amount_cngn {
            warn!(
                payment_intent_id = %payment_intent.id,
                expected = %payment_intent.amount_cngn,
                received = %amount,
                "Underpayment detected"
            );
            return Err(AppError::BadRequest("Insufficient payment amount".to_string()));
        }

        // Update payment intent to paid
        let updated = self
            .payment_intent_repo
            .update_status_to_paid(
                payment_intent.id,
                stellar_tx_hash,
                amount,
                Some(sender_address),
            )
            .await
            .map_err(|e| AppError::DatabaseError(e.to_string()))?;

        info!(
            payment_intent_id = %payment_intent.id,
            merchant_id = %payment_intent.merchant_id,
            amount = %amount,
            stellar_tx_hash = %stellar_tx_hash,
            "Payment confirmed - transitioning to PAID"
        );

        // Send webhook notification (async)
        let webhook_engine = self.webhook_engine.clone();
        let merchant_repo = self.merchant_repo.clone();
        let merchant_id = payment_intent.merchant_id;
        tokio::spawn(async move {
            if let Ok(Some(merchant)) = merchant_repo.find_by_id(merchant_id).await {
                let _ = webhook_engine
                    .send_webhook(&merchant, &updated, "payment.confirmed")
                    .await;
            }
        });

        Ok(())
    }

    /// Mark payment as confirmed (after blockchain confirmations)
    /// Target: <5 seconds from blockchain confirmation
    #[instrument(skip(self))]
    pub async fn mark_payment_confirmed(
        &self,
        payment_intent_id: Uuid,
    ) -> Result<(), AppError> {
        let payment_intent = self
            .payment_intent_repo
            .mark_confirmed(payment_intent_id)
            .await
            .map_err(|e| AppError::DatabaseError(e.to_string()))?;

        info!(
            payment_intent_id = %payment_intent_id,
            "Payment blockchain confirmation recorded"
        );

        Ok(())
    }

    /// List payment intents for a merchant
    #[instrument(skip(self))]
    pub async fn list_payment_intents(
        &self,
        merchant_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<MerchantPaymentIntent>, AppError> {
        self.payment_intent_repo
            .list_by_merchant(merchant_id, limit, offset)
            .await
            .map_err(|e| AppError::DatabaseError(e.to_string()))
    }

    // ========================================================================
    // PRIVATE HELPERS
    // ========================================================================

    async fn generate_unique_memo(&self) -> Result<String, AppError> {
        // Use database function for atomic uniqueness
        let memo: (String,) = sqlx::query_as("SELECT generate_payment_memo()")
            .fetch_one(self.payment_intent_repo.pool())
            .await
            .map_err(|e| AppError::DatabaseError(e.to_string()))?;
        Ok(memo.0)
    }

    fn build_payment_intent_response(
        &self,
        payment_intent: MerchantPaymentIntent,
    ) -> PaymentIntentResponse {
        // Build Stellar payment URL for mobile wallets
        let payment_url = format!(
            "web+stellar:pay?destination={}&amount={}&asset_code=cNGN&memo={}",
            payment_intent.destination_address,
            payment_intent.amount_cngn,
            payment_intent.memo
        );

        PaymentIntentResponse {
            payment_intent_id: payment_intent.id,
            merchant_reference: payment_intent.merchant_reference,
            amount_cngn: payment_intent.amount_cngn,
            destination_address: payment_intent.destination_address,
            memo: payment_intent.memo,
            status: payment_intent.status,
            expires_at: payment_intent.expires_at,
            payment_url,
            qr_code_data: None, // TODO: Generate QR code
            created_at: payment_intent.created_at,
        }
    }
}

// Extension trait to access pool from repository
trait RepositoryPool {
    fn pool(&self) -> &PgPool;
}

impl RepositoryPool for PaymentIntentRepository {
    fn pool(&self) -> &PgPool {
        &self.pool
    }
}
