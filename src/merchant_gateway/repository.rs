//! Database repository for Merchant Gateway

use crate::database::error::{DatabaseError, DatabaseErrorKind};
use crate::merchant_gateway::models::*;
use chrono::{DateTime, Duration, Utc};
use rust_decimal::Decimal;
use sqlx::PgPool;
use uuid::Uuid;

// ============================================================================
// MERCHANT REPOSITORY
// ============================================================================

pub struct MerchantRepository {
    pool: PgPool,
}

impl MerchantRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn create(
        &self,
        business_name: &str,
        business_email: &str,
        business_phone: Option<&str>,
        stellar_address: &str,
        webhook_url: Option<&str>,
        webhook_secret: &str,
        monthly_volume_limit: Option<Decimal>,
        gas_fee_sponsor: bool,
    ) -> Result<Merchant, DatabaseError> {
        sqlx::query_as::<_, Merchant>(
            r#"
            INSERT INTO merchants (
                business_name, business_email, business_phone, stellar_address,
                webhook_url, webhook_secret, monthly_volume_limit, gas_fee_sponsor
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING *
            "#,
        )
        .bind(business_name)
        .bind(business_email)
        .bind(business_phone)
        .bind(stellar_address)
        .bind(webhook_url)
        .bind(webhook_secret)
        .bind(monthly_volume_limit)
        .bind(gas_fee_sponsor)
        .fetch_one(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)
    }

    pub async fn find_by_id(&self, merchant_id: Uuid) -> Result<Option<Merchant>, DatabaseError> {
        sqlx::query_as::<_, Merchant>("SELECT * FROM merchants WHERE id = $1")
            .bind(merchant_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(DatabaseError::from_sqlx)
    }

    pub async fn find_by_email(&self, email: &str) -> Result<Option<Merchant>, DatabaseError> {
        sqlx::query_as::<_, Merchant>("SELECT * FROM merchants WHERE business_email = $1")
            .bind(email)
            .fetch_optional(&self.pool)
            .await
            .map_err(DatabaseError::from_sqlx)
    }

    pub async fn update_webhook_url(
        &self,
        merchant_id: Uuid,
        webhook_url: &str,
    ) -> Result<Merchant, DatabaseError> {
        sqlx::query_as::<_, Merchant>(
            "UPDATE merchants SET webhook_url = $2 WHERE id = $1 RETURNING *",
        )
        .bind(merchant_id)
        .bind(webhook_url)
        .fetch_one(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)
    }

    pub async fn deactivate(&self, merchant_id: Uuid) -> Result<Merchant, DatabaseError> {
        sqlx::query_as::<_, Merchant>(
            "UPDATE merchants SET is_active = false WHERE id = $1 RETURNING *",
        )
        .bind(merchant_id)
        .fetch_one(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)
    }
}

// ============================================================================
// PAYMENT INTENT REPOSITORY
// ============================================================================

pub struct PaymentIntentRepository {
    pool: PgPool,
}

impl PaymentIntentRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn create(
        &self,
        merchant_id: Uuid,
        merchant_reference: &str,
        amount_cngn: Decimal,
        destination_address: &str,
        memo: &str,
        expires_at: DateTime<Utc>,
        customer_email: Option<&str>,
        customer_phone: Option<&str>,
        callback_url: Option<&str>,
        metadata: serde_json::Value,
    ) -> Result<MerchantPaymentIntent, DatabaseError> {
        sqlx::query_as::<_, MerchantPaymentIntent>(
            r#"
            INSERT INTO merchant_payment_intents (
                merchant_id, merchant_reference, amount_cngn, destination_address,
                memo, expires_at, customer_email, customer_phone, callback_url, metadata
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            RETURNING *
            "#,
        )
        .bind(merchant_id)
        .bind(merchant_reference)
        .bind(amount_cngn)
        .bind(destination_address)
        .bind(memo)
        .bind(expires_at)
        .bind(customer_email)
        .bind(customer_phone)
        .bind(callback_url)
        .bind(metadata)
        .fetch_one(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)
    }

    pub async fn find_by_id(
        &self,
        payment_intent_id: Uuid,
    ) -> Result<Option<MerchantPaymentIntent>, DatabaseError> {
        sqlx::query_as::<_, MerchantPaymentIntent>(
            "SELECT * FROM merchant_payment_intents WHERE id = $1",
        )
        .bind(payment_intent_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)
    }

    pub async fn find_by_merchant_reference(
        &self,
        merchant_id: Uuid,
        merchant_reference: &str,
    ) -> Result<Option<MerchantPaymentIntent>, DatabaseError> {
        sqlx::query_as::<_, MerchantPaymentIntent>(
            "SELECT * FROM merchant_payment_intents WHERE merchant_id = $1 AND merchant_reference = $2",
        )
        .bind(merchant_id)
        .bind(merchant_reference)
        .fetch_optional(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)
    }

    pub async fn find_by_memo(
        &self,
        memo: &str,
    ) -> Result<Option<MerchantPaymentIntent>, DatabaseError> {
        sqlx::query_as::<_, MerchantPaymentIntent>(
            "SELECT * FROM merchant_payment_intents WHERE memo = $1",
        )
        .bind(memo)
        .fetch_optional(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)
    }

    pub async fn update_status_to_paid(
        &self,
        payment_intent_id: Uuid,
        stellar_tx_hash: &str,
        actual_amount: Decimal,
        customer_address: Option<&str>,
    ) -> Result<MerchantPaymentIntent, DatabaseError> {
        sqlx::query_as::<_, MerchantPaymentIntent>(
            r#"
            UPDATE merchant_payment_intents
            SET status = 'paid',
                stellar_tx_hash = $2,
                actual_amount_received = $3,
                customer_address = $4,
                paid_at = NOW()
            WHERE id = $1 AND status = 'pending'
            RETURNING *
            "#,
        )
        .bind(payment_intent_id)
        .bind(stellar_tx_hash)
        .bind(actual_amount)
        .bind(customer_address)
        .fetch_one(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)
    }

    pub async fn mark_confirmed(
        &self,
        payment_intent_id: Uuid,
    ) -> Result<MerchantPaymentIntent, DatabaseError> {
        sqlx::query_as::<_, MerchantPaymentIntent>(
            r#"
            UPDATE merchant_payment_intents
            SET confirmed_at = NOW()
            WHERE id = $1 AND confirmed_at IS NULL
            RETURNING *
            "#,
        )
        .bind(payment_intent_id)
        .fetch_one(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)
    }

    pub async fn cancel(
        &self,
        payment_intent_id: Uuid,
    ) -> Result<MerchantPaymentIntent, DatabaseError> {
        sqlx::query_as::<_, MerchantPaymentIntent>(
            r#"
            UPDATE merchant_payment_intents
            SET status = 'cancelled'
            WHERE id = $1 AND status = 'pending'
            RETURNING *
            "#,
        )
        .bind(payment_intent_id)
        .fetch_one(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)
    }

    pub async fn find_expired(&self, limit: i64) -> Result<Vec<MerchantPaymentIntent>, DatabaseError> {
        sqlx::query_as::<_, MerchantPaymentIntent>(
            r#"
            SELECT * FROM merchant_payment_intents
            WHERE status = 'pending' AND expires_at < NOW()
            ORDER BY expires_at ASC
            LIMIT $1
            "#,
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)
    }

    pub async fn mark_expired(
        &self,
        payment_intent_id: Uuid,
    ) -> Result<MerchantPaymentIntent, DatabaseError> {
        sqlx::query_as::<_, MerchantPaymentIntent>(
            r#"
            UPDATE merchant_payment_intents
            SET status = 'expired'
            WHERE id = $1 AND status = 'pending'
            RETURNING *
            "#,
        )
        .bind(payment_intent_id)
        .fetch_one(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)
    }

    pub async fn list_by_merchant(
        &self,
        merchant_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<MerchantPaymentIntent>, DatabaseError> {
        sqlx::query_as::<_, MerchantPaymentIntent>(
            r#"
            SELECT * FROM merchant_payment_intents
            WHERE merchant_id = $1
            ORDER BY created_at DESC
            LIMIT $2 OFFSET $3
            "#,
        )
        .bind(merchant_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)
    }

    /// Find pending payments that need blockchain monitoring
    pub async fn find_pending_for_monitoring(
        &self,
        limit: i64,
    ) -> Result<Vec<MerchantPaymentIntent>, DatabaseError> {
        sqlx::query_as::<_, MerchantPaymentIntent>(
            r#"
            SELECT * FROM merchant_payment_intents
            WHERE status = 'pending'
              AND expires_at > NOW()
              AND created_at > NOW() - INTERVAL '24 hours'
            ORDER BY created_at ASC
            LIMIT $1
            "#,
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)
    }
}

// ============================================================================
// WEBHOOK DELIVERY REPOSITORY
// ============================================================================

pub struct WebhookDeliveryRepository {
    pool: PgPool,
}

impl WebhookDeliveryRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn create(
        &self,
        payment_intent_id: Uuid,
        merchant_id: Uuid,
        webhook_url: &str,
        event_type: &str,
        payload: serde_json::Value,
        signature: &str,
    ) -> Result<WebhookDelivery, DatabaseError> {
        sqlx::query_as::<_, WebhookDelivery>(
            r#"
            INSERT INTO merchant_webhook_deliveries (
                payment_intent_id, merchant_id, webhook_url, event_type, payload, signature
            )
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING *
            "#,
        )
        .bind(payment_intent_id)
        .bind(merchant_id)
        .bind(webhook_url)
        .bind(event_type)
        .bind(payload)
        .bind(signature)
        .fetch_one(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)
    }

    pub async fn mark_delivered(
        &self,
        webhook_id: Uuid,
        http_status: i32,
        response_body: Option<&str>,
    ) -> Result<WebhookDelivery, DatabaseError> {
        sqlx::query_as::<_, WebhookDelivery>(
            r#"
            UPDATE merchant_webhook_deliveries
            SET status = 'delivered',
                http_status_code = $2,
                response_body = $3,
                delivered_at = NOW(),
                last_attempt_at = NOW()
            WHERE id = $1
            RETURNING *
            "#,
        )
        .bind(webhook_id)
        .bind(http_status)
        .bind(response_body)
        .fetch_one(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)
    }

    pub async fn mark_failed(
        &self,
        webhook_id: Uuid,
        http_status: Option<i32>,
        error_message: &str,
    ) -> Result<WebhookDelivery, DatabaseError> {
        sqlx::query_as::<_, WebhookDelivery>(
            r#"
            UPDATE merchant_webhook_deliveries
            SET retry_count = retry_count + 1,
                http_status_code = $2,
                error_message = $3,
                last_attempt_at = NOW(),
                next_retry_at = NOW() + (POWER(2, retry_count + 1) || ' seconds')::INTERVAL,
                status = CASE 
                    WHEN retry_count + 1 >= 5 THEN 'abandoned'
                    ELSE 'pending'
                END
            WHERE id = $1
            RETURNING *
            "#,
        )
        .bind(webhook_id)
        .bind(http_status)
        .bind(error_message)
        .fetch_one(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)
    }

    pub async fn find_pending_for_retry(
        &self,
        limit: i64,
    ) -> Result<Vec<WebhookDelivery>, DatabaseError> {
        sqlx::query_as::<_, WebhookDelivery>(
            r#"
            SELECT * FROM merchant_webhook_deliveries
            WHERE status = 'pending'
              AND (next_retry_at IS NULL OR next_retry_at <= NOW())
              AND retry_count < 5
            ORDER BY created_at ASC
            LIMIT $1
            "#,
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)
    }

    pub async fn list_by_payment_intent(
        &self,
        payment_intent_id: Uuid,
    ) -> Result<Vec<WebhookDelivery>, DatabaseError> {
        sqlx::query_as::<_, WebhookDelivery>(
            "SELECT * FROM merchant_webhook_deliveries WHERE payment_intent_id = $1 ORDER BY created_at DESC",
        )
        .bind(payment_intent_id)
        .fetch_all(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)
    }
}

// ============================================================================
// REFUND REPOSITORY
// ============================================================================

pub struct RefundRepository {
    pool: PgPool,
}

impl RefundRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn create(
        &self,
        payment_intent_id: Uuid,
        merchant_id: Uuid,
        amount_cngn: Decimal,
        reason: Option<&str>,
        refund_reference: &str,
        initiated_by: &str,
    ) -> Result<MerchantRefund, DatabaseError> {
        sqlx::query_as::<_, MerchantRefund>(
            r#"
            INSERT INTO merchant_refunds (
                payment_intent_id, merchant_id, amount_cngn, reason, refund_reference, initiated_by
            )
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING *
            "#,
        )
        .bind(payment_intent_id)
        .bind(merchant_id)
        .bind(amount_cngn)
        .bind(reason)
        .bind(refund_reference)
        .bind(initiated_by)
        .fetch_one(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)
    }

    pub async fn find_by_id(&self, refund_id: Uuid) -> Result<Option<MerchantRefund>, DatabaseError> {
        sqlx::query_as::<_, MerchantRefund>("SELECT * FROM merchant_refunds WHERE id = $1")
            .bind(refund_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(DatabaseError::from_sqlx)
    }

    pub async fn update_status(
        &self,
        refund_id: Uuid,
        status: RefundStatus,
        stellar_tx_hash: Option<&str>,
    ) -> Result<MerchantRefund, DatabaseError> {
        sqlx::query_as::<_, MerchantRefund>(
            r#"
            UPDATE merchant_refunds
            SET status = $2,
                stellar_tx_hash = $3,
                completed_at = CASE WHEN $2 = 'completed' THEN NOW() ELSE completed_at END
            WHERE id = $1
            RETURNING *
            "#,
        )
        .bind(refund_id)
        .bind(status.to_string())
        .bind(stellar_tx_hash)
        .fetch_one(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)
    }

    pub async fn find_pending(&self, limit: i64) -> Result<Vec<MerchantRefund>, DatabaseError> {
        sqlx::query_as::<_, MerchantRefund>(
            "SELECT * FROM merchant_refunds WHERE status = 'pending' ORDER BY created_at ASC LIMIT $1",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)
    }
}
