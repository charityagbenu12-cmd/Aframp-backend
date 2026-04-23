use crate::error::AppError;
use crate::pos::models::{PosMerchant, PosPaymentIntent, PosPaymentStatus};
use crate::pos::qr_generator::QrGenerator;
use chrono::{Duration, Utc};
use rust_decimal::Decimal;
use sqlx::PgPool;
use std::sync::Arc;
use tracing::{info, instrument};
use uuid::Uuid;

/// Service for creating and managing POS payment intents
pub struct PaymentIntentService {
    db: PgPool,
    qr_generator: Arc<QrGenerator>,
    default_timeout_secs: i32,
}

impl PaymentIntentService {
    pub fn new(db: PgPool, qr_generator: Arc<QrGenerator>) -> Self {
        Self {
            db,
            qr_generator,
            default_timeout_secs: 900, // 15 minutes default
        }
    }

    /// Create a new payment intent for a POS transaction
    /// Target: <300ms total time (including QR generation)
    #[instrument(skip(self))]
    pub async fn create_payment_intent(
        &self,
        merchant_id: Uuid,
        order_id: String,
        amount_cngn: Decimal,
    ) -> Result<PosPaymentIntent, AppError> {
        let start = std::time::Instant::now();

        // Fetch merchant configuration
        let merchant = self.get_merchant(merchant_id).await?;
        
        if !merchant.is_active {
            return Err(AppError::BadRequest("Merchant is not active".to_string()));
        }

        // Generate unique memo for this payment
        let memo = format!("POS-{}", Uuid::new_v4().to_string().split('-').next().unwrap());
        
        // Calculate expiry time
        let timeout_secs = merchant.payment_timeout_secs.max(60); // Minimum 60 seconds
        let expires_at = Utc::now() + Duration::seconds(timeout_secs as i64);

        // Create payment intent record
        let payment_id = Uuid::new_v4();
        let mut payment_intent = PosPaymentIntent {
            id: payment_id,
            merchant_id,
            order_id: order_id.clone(),
            amount_cngn,
            destination_address: merchant.stellar_address.clone(),
            memo: memo.clone(),
            qr_code_data: String::new(), // Will be populated below
            status: PosPaymentStatus::Pending,
            stellar_tx_hash: None,
            actual_amount_received: None,
            customer_address: None,
            expires_at,
            confirmed_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        // Generate QR code
        let qr_code_svg = self.qr_generator.generate_dynamic_qr(&payment_intent)?;
        payment_intent.qr_code_data = qr_code_svg;

        // Insert into database
        sqlx::query(
            r#"
            INSERT INTO pos_payment_intents (
                id, merchant_id, order_id, amount_cngn, destination_address,
                memo, qr_code_data, status, expires_at, created_at, updated_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            "#
        )
        .bind(payment_intent.id)
        .bind(payment_intent.merchant_id)
        .bind(&payment_intent.order_id)
        .bind(payment_intent.amount_cngn)
        .bind(&payment_intent.destination_address)
        .bind(&payment_intent.memo)
        .bind(&payment_intent.qr_code_data)
        .bind(&payment_intent.status)
        .bind(payment_intent.expires_at)
        .bind(payment_intent.created_at)
        .bind(payment_intent.updated_at)
        .execute(&self.db)
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?;

        let elapsed = start.elapsed();
        info!(
            payment_id = %payment_id,
            order_id = %order_id,
            amount = %amount_cngn,
            elapsed_ms = elapsed.as_millis(),
            "Payment intent created"
        );

        // Ensure we meet the <300ms SLA
        if elapsed.as_millis() > 300 {
            tracing::warn!(
                elapsed_ms = elapsed.as_millis(),
                "Payment intent creation exceeded 300ms target"
            );
        }

        Ok(payment_intent)
    }

    /// Get merchant by ID
    #[instrument(skip(self))]
    async fn get_merchant(&self, merchant_id: Uuid) -> Result<PosMerchant, AppError> {
        let merchant = sqlx::query_as::<_, PosMerchant>(
            r#"
            SELECT * FROM pos_merchants
            WHERE id = $1
            "#
        )
        .bind(merchant_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?
        .ok_or_else(|| AppError::NotFound("Merchant not found".to_string()))?;

        Ok(merchant)
    }

    /// Get payment intent by ID
    #[instrument(skip(self))]
    pub async fn get_payment_intent(
        &self,
        payment_id: Uuid,
    ) -> Result<PosPaymentIntent, AppError> {
        let payment = sqlx::query_as::<_, PosPaymentIntent>(
            r#"
            SELECT * FROM pos_payment_intents
            WHERE id = $1
            "#
        )
        .bind(payment_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?
        .ok_or_else(|| AppError::NotFound("Payment intent not found".to_string()))?;

        Ok(payment)
    }

    /// Get payment intent by order ID
    #[instrument(skip(self))]
    pub async fn get_payment_by_order_id(
        &self,
        order_id: &str,
    ) -> Result<Option<PosPaymentIntent>, AppError> {
        let payment = sqlx::query_as::<_, PosPaymentIntent>(
            r#"
            SELECT * FROM pos_payment_intents
            WHERE order_id = $1
            ORDER BY created_at DESC
            LIMIT 1
            "#
        )
        .bind(order_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?;

        Ok(payment)
    }

    /// Cancel a payment intent
    #[instrument(skip(self))]
    pub async fn cancel_payment_intent(
        &self,
        payment_id: Uuid,
    ) -> Result<(), AppError> {
        sqlx::query(
            r#"
            UPDATE pos_payment_intents
            SET status = 'failed',
                updated_at = $1
            WHERE id = $2 AND status = 'pending'
            "#
        )
        .bind(Utc::now())
        .bind(payment_id)
        .execute(&self.db)
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?;

        info!(payment_id = %payment_id, "Payment intent cancelled");
        Ok(())
    }

    /// Refund a payment (for discrepancies or merchant request)
    #[instrument(skip(self))]
    pub async fn refund_payment(
        &self,
        payment_id: Uuid,
        reason: String,
    ) -> Result<(), AppError> {
        // Update payment status to refunded
        sqlx::query(
            r#"
            UPDATE pos_payment_intents
            SET status = 'refunded',
                updated_at = $1
            WHERE id = $2
            "#
        )
        .bind(Utc::now())
        .bind(payment_id)
        .execute(&self.db)
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?;

        // In production, this would trigger a Stellar refund transaction
        // For now, we just mark it as refunded in the database

        info!(
            payment_id = %payment_id,
            reason = %reason,
            "Payment refunded"
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_payment_intent_service_creation() {
        // Basic compilation test
    }
}
