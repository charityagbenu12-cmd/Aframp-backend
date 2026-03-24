use crate::chains::stellar::client::StellarClient;
use crate::database::bill_payment_repository::{BillPaymentRepository, BillPayment};
use crate::database::transaction_repository::TransactionRepository;
use crate::database::repository::Repository;
use crate::services::notification::{NotificationService, NotificationType};
use crate::workers::bill_processor::providers::BillProviderFactory;
use crate::workers::bill_processor::types::*;
use crate::workers::bill_processor::account_verification::AccountVerifier;
use crate::workers::bill_processor::payment_executor::PaymentExecutor;
use crate::workers::bill_processor::refund_handler::RefundHandler;
use crate::workers::bill_processor::token_manager::TokenManager;
use sqlx::PgPool;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use tracing::{debug, error, info, instrument, warn};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct BillProcessorConfig {
    pub poll_interval: Duration,
    pub batch_size: i64,
    pub retry_config: RetryConfig,
}

impl Default for BillProcessorConfig {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_secs(10),
            batch_size: 50,
            retry_config: RetryConfig::default(),
        }
    }
}

impl BillProcessorConfig {
    pub fn from_env() -> Self {
        let mut cfg = Self::default();
        cfg.poll_interval = Duration::from_secs(
            std::env::var("BILL_PROCESSOR_POLL_INTERVAL_SECONDS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(10),
        );
        cfg
    }
}

pub struct BillProcessorWorker {
    pool: PgPool,
    stellar_client: StellarClient,
    provider_factory: Arc<BillProviderFactory>,
    notification_service: Arc<NotificationService>,
    config: BillProcessorConfig,
}

impl BillProcessorWorker {
    pub fn new(
        pool: PgPool,
        stellar_client: StellarClient,
        provider_factory: Arc<BillProviderFactory>,
        notification_service: Arc<NotificationService>,
        config: BillProcessorConfig,
    ) -> Self {
        Self {
            pool,
            stellar_client,
            provider_factory,
            notification_service,
            config,
        }
    }

    pub async fn run(self, mut shutdown_rx: watch::Receiver<bool>) {
        info!("Starting bill processor worker...");
        let mut interval = tokio::time::interval(self.config.poll_interval);

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    if let Err(e) = self.run_cycle().await {
                        error!(error = %e, "bill processor cycle failed");
                    }
                }
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        info!("Bill processor worker received shutdown signal");
                        break;
                    }
                }
            }
        }

        info!("Bill processor worker stopped");
    }

    #[instrument(skip(self), name = "bill_processor_cycle")]
    async fn run_cycle(&self) -> anyhow::Result<()> {
        let bill_repo = BillPaymentRepository::new(self.pool.clone());
        let pending = bill_repo.find_pending_processing(self.config.batch_size).await?;

        for bill in pending {
            if let Err(e) = self.process_bill(bill).await {
                error!(error = %e, "failed to process bill transaction");
            }
        }

        Ok(())
    }

    async fn process_bill(&self, bill: BillPayment) -> anyhow::Result<()> {
        let state = BillProcessingState::from_str(&bill.status).unwrap_or(BillProcessingState::PendingPayment);

        match state {
            BillProcessingState::CngnReceived => self.handle_cngn_received(bill).await,
            BillProcessingState::VerifyingAccount => self.handle_verifying_account(bill).await,
            BillProcessingState::ProcessingBill => self.handle_processing_bill(bill).await,
            BillProcessingState::ProviderProcessing => self.handle_provider_processing(bill).await,
            BillProcessingState::RetryScheduled => self.handle_retry_scheduled(bill).await,
            BillProcessingState::RefundInitiated => self.handle_refund_initiated(bill).await,
            _ => Ok(()),
        }
    }

    async fn handle_cngn_received(&self, mut bill: BillPayment) -> anyhow::Result<()> {
        info!(bill_id = %bill.id, "Handling received cNGN for bill");
        
        // In a real implementation, we would verify the amount against Stellar here
        // For this worker, we transition to verification stage
        
        bill.status = BillProcessingState::VerifyingAccount.as_str().to_string();
        let repo = BillPaymentRepository::new(self.pool.clone());
        repo.update(&bill.id.to_string(), &bill).await?;
        
        Ok(())
    }

    async fn handle_verifying_account(&self, mut bill: BillPayment) -> anyhow::Result<()> {
        info!(bill_id = %bill.id, "Verifying account for bill");
        
        let provider = self.provider_factory.get_provider(&bill.provider_name);
        let request = VerificationRequest {
            provider_code: bill.provider_name.clone(), // This might need mapping
            account_number: bill.account_number.clone(),
            account_type: "prepaid".to_string(), // Default
            bill_type: bill.bill_type.clone(),
        };

        match AccountVerifier::verify(provider, &request).await {
            Ok(info) => {
                info!(bill_id = %bill.id, customer = %info.customer_name, "Account verified successfully");
                bill.status = BillProcessingState::ProcessingBill.as_str().to_string();
                bill.account_verified = true;
                bill.verification_data = Some(serde_json::to_value(info).unwrap_or_default());
            }
            Err(e) => {
                warn!(bill_id = %bill.id, error = %e, "Account verification failed");
                bill.status = BillProcessingState::RefundInitiated.as_str().to_string();
                bill.error_message = Some(e.to_string());
            }
        }

        let repo = BillPaymentRepository::new(self.pool.clone());
        repo.update(&bill.id.to_string(), &bill).await?;
        Ok(())
    }

    async fn handle_processing_bill(&self, mut bill: BillPayment) -> anyhow::Result<()> {
        info!(bill_id = %bill.id, "Executing bill payment");

        let provider = self.provider_factory.get_provider(&bill.provider_name);
        let request = BillPaymentRequest {
            transaction_id: bill.transaction_id.to_string(),
            provider_code: bill.provider_name.clone(),
            account_number: bill.account_number.clone(),
            account_type: "prepaid".to_string(),
            bill_type: bill.bill_type.clone(),
            amount: (bill.paid_with_afri as i64), // Placeholder for actual amount logic
            phone_number: None,
            variation_code: None,
        };

        match PaymentExecutor::execute(provider, request).await {
            Ok(response) => {
                info!(bill_id = %bill.id, ref = %response.provider_reference, "Payment executed successfully");
                bill.provider_reference = Some(response.provider_reference);
                bill.token = response.token;
                bill.status = if response.status == "completed" {
                    BillProcessingState::Completed.as_str().to_string()
                } else {
                    BillProcessingState::ProviderProcessing.as_str().to_string()
                };
                
                if bill.status == "completed" {
                    self.send_completion_notification(&bill).await;
                }
            }
            Err(e) => {
                warn!(bill_id = %bill.id, error = %e, "Payment execution failed");
                bill.status = BillProcessingState::RetryScheduled.as_str().to_string();
                bill.error_message = Some(e.to_string());
                bill.last_retry_at = Some(chrono::Utc::now());
            }
        }

        let repo = BillPaymentRepository::new(self.pool.clone());
        repo.update(&bill.id.to_string(), &bill).await?;
        Ok(())
    }

    async fn handle_provider_processing(&self, mut bill: BillPayment) -> anyhow::Result<()> {
        info!(bill_id = %bill.id, "Monitoring provider processing");

        let provider = self.provider_factory.get_provider(&bill.provider_name);
        let reference = bill.provider_reference.as_deref().unwrap_or("");

        match provider.query_status(reference).await {
            Ok(status) => {
                if status.status == "completed" {
                    info!(bill_id = %bill.id, "Payment confirmed completed");
                    bill.status = BillProcessingState::Completed.as_str().to_string();
                    bill.token = status.token;
                    self.send_completion_notification(&bill).await;
                } else if status.status == "failed" {
                    warn!(bill_id = %bill.id, "Payment failed at provider");
                    bill.status = BillProcessingState::RetryScheduled.as_str().to_string();
                    bill.error_message = status.message;
                }
            }
            Err(e) => {
                warn!(bill_id = %bill.id, error = %e, "Failed to query status");
            }
        }

        let repo = BillPaymentRepository::new(self.pool.clone());
        repo.update(&bill.id.to_string(), &bill).await?;
        Ok(())
    }

    async fn handle_retry_scheduled(&self, mut bill: BillPayment) -> anyhow::Result<()> {
        let retry_count = bill.retry_count as u32;
        if retry_count >= self.config.retry_config.max_attempts {
            info!(bill_id = %bill.id, "Max retries reached, initiating refund");
            bill.status = BillProcessingState::RefundInitiated.as_str().to_string();
        } else {
            let last_retry = bill.last_retry_at.unwrap_or(bill.created_at);
            let backoff = self.config.retry_config.backoff_seconds.get(retry_count as usize).copied().unwrap_or(300);
            
            if chrono::Utc::now() > last_retry + Duration::from_secs(backoff) {
                info!(bill_id = %bill.id, attempt = retry_count + 1, "Retrying payment");
                bill.status = BillProcessingState::ProcessingBill.as_str().to_string();
                bill.retry_count += 1;
            }
        }

        let repo = BillPaymentRepository::new(self.pool.clone());
        repo.update(&bill.id.to_string(), &bill).await?;
        Ok(())
    }

    async fn handle_refund_initiated(&self, mut bill: BillPayment) -> anyhow::Result<()> {
        info!(bill_id = %bill.id, "Processing refund");
        
        bill.status = BillProcessingState::RefundProcessing.as_str().to_string();
        let repo = BillPaymentRepository::new(self.pool.clone());
        repo.update(&bill.id.to_string(), &bill).await?;

        // Simulate Stellar refund
        let wallet = "G...".to_string(); // In real world, get from transaction
        let amount = 0.0; // In real world, get from transaction
        
        match RefundHandler::process_refund(&self.stellar_client, bill.transaction_id, &wallet, amount, "Bill payment failed").await {
            Ok(hash) => {
                info!(bill_id = %bill.id, hash = %hash, "Refund successful");
                bill.status = BillProcessingState::Refunded.as_str().to_string();
                bill.refund_tx_hash = Some(hash);
            }
            Err(e) => {
                error!(bill_id = %bill.id, error = %e, "Refund failed");
                bill.status = BillProcessingState::ProviderFailed.as_str().to_string();
            }
        }

        repo.update(&bill.id.to_string(), &bill).await?;
        Ok(())
    }

    async fn send_completion_notification(&self, bill: &BillPayment) {
        let tx_repo = TransactionRepository::new(self.pool.clone());
        if let Ok(Some(tx)) = tx_repo.find_by_id(&bill.transaction_id.to_string()).await {
            let message = if let Some(token) = &bill.token {
                format!("Payment successful. Token: {}", TokenManager::format_token(token, &bill.bill_type))
            } else {
                "Payment successful".to_string()
            };
            
            self.notification_service.send_notification(&tx, NotificationType::OfframpCompleted, &message).await;
        }
    }
}
