use crate::chains::stellar::client::StellarClient;
use crate::error::AppError;
use crate::pos::models::{PaymentNotification, PosPaymentIntent, PosPaymentStatus};
use chrono::Utc;
use rust_decimal::Decimal;
use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, RwLock};
use tokio::time::interval;
use tracing::{error, info, instrument, warn};
use uuid::Uuid;

/// Real-time payment monitoring service
/// Listens to Stellar ledger for payment confirmations and notifies merchants via WebSocket
pub struct LobbyService {
    db: PgPool,
    stellar_client: Arc<StellarClient>,
    /// Map of memo -> broadcast channel for real-time notifications
    active_payments: Arc<RwLock<HashMap<String, broadcast::Sender<PaymentNotification>>>>,
    poll_interval: Duration,
}

impl LobbyService {
    pub fn new(
        db: PgPool,
        stellar_client: Arc<StellarClient>,
        poll_interval_secs: u64,
    ) -> Self {
        Self {
            db,
            stellar_client,
            active_payments: Arc::new(RwLock::new(HashMap::new())),
            poll_interval: Duration::from_secs(poll_interval_secs),
        }
    }

    /// Register a payment intent for monitoring
    #[instrument(skip(self))]
    pub async fn register_payment(
        &self,
        payment_id: Uuid,
        memo: String,
    ) -> Result<broadcast::Receiver<PaymentNotification>, AppError> {
        let mut payments = self.active_payments.write().await;
        
        let (tx, rx) = broadcast::channel(16);
        payments.insert(memo.clone(), tx);
        
        info!(
            payment_id = %payment_id,
            memo = %memo,
            "Payment registered for monitoring"
        );
        
        Ok(rx)
    }

    /// Unregister a payment intent (called after confirmation or timeout)
    #[instrument(skip(self))]
    pub async fn unregister_payment(&self, memo: &str) {
        let mut payments = self.active_payments.write().await;
        payments.remove(memo);
        info!(memo = %memo, "Payment unregistered from monitoring");
    }

    /// Start the background polling worker
    /// Monitors Stellar ledger for payments matching active memos
    pub async fn start_polling_worker(self: Arc<Self>) {
        let mut ticker = interval(self.poll_interval);
        
        info!("POS lobby service polling worker started");
        
        loop {
            ticker.tick().await;
            
            if let Err(e) = self.poll_pending_payments().await {
                error!(error = %e, "Error polling pending payments");
            }
        }
    }

    /// Poll all pending payments and check Stellar for confirmations
    #[instrument(skip(self))]
    async fn poll_pending_payments(&self) -> Result<(), AppError> {
        // Fetch all pending POS payments from database
        let pending_payments = sqlx::query_as::<_, PosPaymentIntent>(
            r#"
            SELECT * FROM pos_payment_intents
            WHERE status = 'pending' OR status = 'submitted'
            ORDER BY created_at DESC
            LIMIT 100
            "#
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?;

        info!(count = pending_payments.len(), "Polling pending POS payments");

        for payment in pending_payments {
            // Check if payment has expired
            if payment.expires_at < Utc::now() {
                self.mark_payment_failed(payment.id, "Payment expired").await?;
                continue;
            }

            // Query Stellar for transactions to this merchant with matching memo
            match self.check_stellar_payment(&payment).await {
                Ok(Some((tx_hash, amount, customer_address))) => {
                    self.confirm_payment(payment, tx_hash, amount, customer_address).await?;
                }
                Ok(None) => {
                    // No matching transaction yet, continue monitoring
                }
                Err(e) => {
                    warn!(
                        payment_id = %payment.id,
                        error = %e,
                        "Error checking Stellar payment"
                    );
                }
            }
        }

        Ok(())
    }

    /// Check Stellar ledger for a payment matching the intent
    #[instrument(skip(self, payment))]
    async fn check_stellar_payment(
        &self,
        payment: &PosPaymentIntent,
    ) -> Result<Option<(String, Decimal, String)>, AppError> {
        // Query Stellar Horizon for recent transactions to the merchant address
        // Filter by memo to match the specific payment intent
        
        // Note: In production, this would use Stellar Horizon's /accounts/{account}/payments endpoint
        // with cursor-based pagination and memo filtering
        
        // For now, we'll use the account transactions endpoint
        let account_info = self.stellar_client
            .get_account(&payment.destination_address)
            .await
            .map_err(|e| AppError::InternalError(format!("Failed to fetch account: {}", e)))?;

        // In a real implementation, we would:
        // 1. Query /accounts/{account}/transactions with cursor
        // 2. Filter by memo matching payment.memo
        // 3. Verify asset is cNGN
        // 4. Extract amount and source address
        
        // Placeholder: Return None for now (no matching transaction found)
        // This will be replaced with actual Horizon API calls
        
        Ok(None)
    }

    /// Confirm a payment and notify the merchant
    #[instrument(skip(self, payment))]
    async fn confirm_payment(
        &self,
        payment: PosPaymentIntent,
        tx_hash: String,
        actual_amount: Decimal,
        customer_address: String,
    ) -> Result<(), AppError> {
        let start = std::time::Instant::now();
        
        // Check for amount discrepancy
        let expected_amount = payment.amount_cngn;
        let status = if (actual_amount - expected_amount).abs() < Decimal::new(1, 2) {
            // Within 0.01 cNGN tolerance
            PosPaymentStatus::Confirmed
        } else {
            PosPaymentStatus::Discrepancy
        };

        // Update payment in database
        sqlx::query(
            r#"
            UPDATE pos_payment_intents
            SET status = $1,
                stellar_tx_hash = $2,
                actual_amount_received = $3,
                customer_address = $4,
                confirmed_at = $5,
                updated_at = $6
            WHERE id = $7
            "#
        )
        .bind(&status)
        .bind(&tx_hash)
        .bind(actual_amount)
        .bind(&customer_address)
        .bind(Utc::now())
        .bind(Utc::now())
        .bind(payment.id)
        .execute(&self.db)
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?;

        // Send real-time notification via WebSocket
        let notification = PaymentNotification {
            payment_id: payment.id,
            order_id: payment.order_id.clone(),
            status: status.clone(),
            amount_expected: expected_amount,
            amount_received: Some(actual_amount),
            stellar_tx_hash: Some(tx_hash.clone()),
            timestamp: Utc::now(),
        };

        let payments = self.active_payments.read().await;
        if let Some(tx) = payments.get(&payment.memo) {
            let _ = tx.send(notification.clone());
        }

        let elapsed = start.elapsed();
        info!(
            payment_id = %payment.id,
            tx_hash = %tx_hash,
            elapsed_ms = elapsed.as_millis(),
            status = ?status,
            "Payment confirmed and notification sent"
        );

        // Ensure we meet the <3s confirmation SLA
        if elapsed.as_secs() > 3 {
            warn!(
                payment_id = %payment.id,
                elapsed_secs = elapsed.as_secs(),
                "Payment confirmation exceeded 3s target"
            );
        }

        // Unregister from active monitoring
        drop(payments);
        self.unregister_payment(&payment.memo).await;

        Ok(())
    }

    /// Mark a payment as failed
    #[instrument(skip(self))]
    async fn mark_payment_failed(
        &self,
        payment_id: Uuid,
        reason: &str,
    ) -> Result<(), AppError> {
        sqlx::query(
            r#"
            UPDATE pos_payment_intents
            SET status = 'failed',
                updated_at = $1
            WHERE id = $2
            "#
        )
        .bind(Utc::now())
        .bind(payment_id)
        .execute(&self.db)
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?;

        info!(payment_id = %payment_id, reason = %reason, "Payment marked as failed");
        Ok(())
    }

    /// Get payment status for a specific order
    #[instrument(skip(self))]
    pub async fn get_payment_status(
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lobby_service_creation() {
        // Basic compilation test
        // Full integration tests require database and Stellar testnet
    }
}
