use crate::chains::stellar::client::StellarClient;
use crate::chains::stellar::payment::{CngnMemo, CngnPaymentBuilder};
use crate::database::error::DatabaseError;
use crate::database::transaction_repository::{TransactionRepository, Transaction};
use crate::payments::error::PaymentError;
use crate::payments::factory::PaymentProviderFactory;
use crate::services::notification::{NotificationService, NotificationType};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use sqlx::PgPool;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use tracing::{debug, error, info, instrument, warn};

// ---------------------------------------------------------------------------
// Error Types
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum OfframpError {
    #[error("database error: {0}")]
    Database(#[from] DatabaseError),

    #[error("stellar error: {0}")]
    Stellar(String),

    #[error("payment provider error: {0}")]
    Provider(#[from] PaymentError),

    #[error("invalid bank details: {0}")]
    InvalidBankDetails(String),

    #[error("retry limit exceeded for transaction {tx_id}")]
    RetryLimitExceeded { tx_id: String },

    #[error("lock acquisition timeout for transaction {tx_id}")]
    LockTimeout { tx_id: String },

    #[error("refund failed: {0}")]
    RefundFailed(String),

    #[error("internal error: {0}")]
    Internal(String),
}

impl From<anyhow::Error> for OfframpError {
    fn from(e: anyhow::Error) -> Self {
        OfframpError::Internal(e.to_string())
    }
}

// ---------------------------------------------------------------------------
// State Machine
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OfframpState {
    PendingPayment,
    CngnReceived,
    VerifyingAmount,
    ProcessingWithdrawal,
    TransferPending,
    Completed,
    RefundInitiated,
    Refunding,
    Refunded,
    Failed,
    Expired,
}

impl OfframpState {
    pub fn as_str(&self) -> &'static str {
        match self {
            OfframpState::PendingPayment => "pending_payment",
            OfframpState::CngnReceived => "cngn_received",
            OfframpState::VerifyingAmount => "verifying_amount",
            OfframpState::ProcessingWithdrawal => "processing_withdrawal",
            OfframpState::TransferPending => "transfer_pending",
            OfframpState::Completed => "completed",
            OfframpState::RefundInitiated => "refund_initiated",
            OfframpState::Refunding => "refunding",
            OfframpState::Refunded => "refunded",
            OfframpState::Failed => "failed",
            OfframpState::Expired => "expired",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "pending_payment" => Some(OfframpState::PendingPayment),
            "cngn_received" => Some(OfframpState::CngnReceived),
            "verifying_amount" => Some(OfframpState::VerifyingAmount),
            "processing_withdrawal" => Some(OfframpState::ProcessingWithdrawal),
            "transfer_pending" => Some(OfframpState::TransferPending),
            "completed" => Some(OfframpState::Completed),
            "refund_initiated" => Some(OfframpState::RefundInitiated),
            "refunding" => Some(OfframpState::Refunding),
            "refunded" => Some(OfframpState::Refunded),
            "failed" => Some(OfframpState::Failed),
            "expired" => Some(OfframpState::Expired),
            _ => None,
        }
    }

    /// Validates if a state transition is allowed
    pub fn can_transition_to(&self, next: &OfframpState) -> bool {
        match (self, next) {
            // Normal flow
            (OfframpState::PendingPayment, OfframpState::CngnReceived) => true,
            (OfframpState::CngnReceived, OfframpState::VerifyingAmount) => true,
            (OfframpState::VerifyingAmount, OfframpState::ProcessingWithdrawal) => true,
            (OfframpState::ProcessingWithdrawal, OfframpState::TransferPending) => true,
            (OfframpState::TransferPending, OfframpState::Completed) => true,

            // Failure/Refund flow
            (_, OfframpState::RefundInitiated)
                if self != &OfframpState::Completed && self != &OfframpState::Refunded =>
            {
                true
            }
            (OfframpState::RefundInitiated, OfframpState::Refunding) => true,
            (OfframpState::Refunding, OfframpState::Refunded) => true,
            (OfframpState::Refunding, OfframpState::Failed) => true,

            // Expiration
            (OfframpState::PendingPayment, OfframpState::Expired) => true,

            _ => false,
        }
    }
}

// ---------------------------------------------------------------------------
// Metadata Structure
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OfframpMetadata {
    // Bank details
    pub account_name: String,
    pub account_number: String,
    pub bank_code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bank_name: Option<String>,

    // Stellar tracking
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stellar_tx_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stellar_confirmed_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stellar_ledger: Option<i64>,

    // Provider tracking
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_reference: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_response: Option<JsonValue>,

    // Retry tracking
    #[serde(default)]
    pub retry_count: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_retry_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_retry_after: Option<String>,

    // Failure tracking
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_reason: Option<String>,
    #[serde(default)]
    pub is_retryable: bool,

    // Refund tracking
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refund_tx_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refund_confirmed_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refund_amount: Option<String>,

    // Locking
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locked_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locked_by: Option<String>,
}

impl OfframpMetadata {
    pub fn new(account_name: String, account_number: String, bank_code: String) -> Self {
        Self {
            account_name,
            account_number,
            bank_code,
            bank_name: None,
            stellar_tx_hash: None,
            stellar_confirmed_at: None,
            stellar_ledger: None,
            provider_name: None,
            provider_reference: None,
            provider_response: None,
            retry_count: 0,
            last_retry_at: None,
            next_retry_after: None,
            failure_reason: None,
            is_retryable: false,
            refund_tx_hash: None,
            refund_confirmed_at: None,
            refund_amount: None,
            locked_at: None,
            locked_by: None,
        }
    }

    pub fn to_json(&self) -> JsonValue {
        serde_json::to_value(self).unwrap_or_else(|_| serde_json::json!({}))
    }

    pub fn from_json(value: &JsonValue) -> Result<Self, OfframpError> {
        serde_json::from_value(value.clone())
            .map_err(|e| OfframpError::Internal(format!("failed to parse metadata: {}", e)))
    }
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct OfframpProcessorConfig {
    pub poll_interval: Duration,
    pub batch_size: i64,
    pub max_retries: u32,
    pub retry_timeout: Duration,
    pub lock_timeout: Duration,
    pub hot_wallet_secret: String,
    pub system_wallet_address: String,
}

impl Default for OfframpProcessorConfig {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_secs(10),
            batch_size: 50,
            max_retries: 5,
            retry_timeout: Duration::from_secs(24 * 60 * 60), // 24 hours
            lock_timeout: Duration::from_secs(30),
            hot_wallet_secret: String::new(),
            system_wallet_address: String::new(),
        }
    }
}

impl OfframpProcessorConfig {
    pub fn from_env() -> Self {
        let mut cfg = Self::default();

        cfg.poll_interval = Duration::from_secs(
            std::env::var("OFFRAMP_POLL_INTERVAL_SECONDS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(cfg.poll_interval.as_secs()),
        );

        cfg.batch_size = std::env::var("OFFRAMP_BATCH_SIZE")
            .ok()
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(cfg.batch_size);

        cfg.max_retries = std::env::var("OFFRAMP_MAX_RETRIES")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(cfg.max_retries);

        cfg.retry_timeout = Duration::from_secs(
            std::env::var("OFFRAMP_RETRY_TIMEOUT_HOURS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .map(|h| h * 60 * 60)
                .unwrap_or(cfg.retry_timeout.as_secs()),
        );

        cfg.lock_timeout = Duration::from_secs(
            std::env::var("OFFRAMP_LOCK_TIMEOUT_SECONDS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(cfg.lock_timeout.as_secs()),
        );

        cfg.hot_wallet_secret = std::env::var("HOT_WALLET_SECRET_KEY").unwrap_or_default();
        cfg.system_wallet_address = std::env::var("SYSTEM_WALLET_ADDRESS").unwrap_or_default();

        cfg
    }

    pub fn validate(&self) -> Result<(), OfframpError> {
        if self.hot_wallet_secret.is_empty() {
            return Err(OfframpError::Internal(
                "HOT_WALLET_SECRET_KEY is required".to_string(),
            ));
        }
        if self.system_wallet_address.is_empty() {
            return Err(OfframpError::Internal(
                "SYSTEM_WALLET_ADDRESS is required".to_string(),
            ));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Worker Implementation
// ---------------------------------------------------------------------------

pub struct OfframpProcessorWorker {
    pool: PgPool,
    stellar_client: StellarClient,
    provider_factory: Arc<PaymentProviderFactory>,
    notification_service: Arc<NotificationService>,
    config: OfframpProcessorConfig,
}

impl OfframpProcessorWorker {
    pub fn new(
        pool: PgPool,
        stellar_client: StellarClient,
        provider_factory: Arc<PaymentProviderFactory>,
        notification_service: Arc<NotificationService>,
        config: OfframpProcessorConfig,
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
        info!("Starting offramp processor worker...");

        let mut interval = tokio::time::interval(self.config.poll_interval);

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    if let Err(e) = self.run_cycle().await {
                        error!(error = %e, "offramp processor cycle failed");
                    }
                }
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        info!("Offramp processor worker received shutdown signal");
                        break;
                    }
                }
            }
        }

        info!("Offramp processor worker stopped");
    }

    #[instrument(skip(self), name = "offramp_processor_cycle")]
    pub async fn run_cycle(&self) -> Result<(), OfframpError> {
        debug!("Running offramp processor cycle");

        let _timer = crate::metrics::worker::cycle_duration_seconds()
            .with_label_values(&["offramp_processor"])
            .start_timer();
        crate::metrics::worker::cycles_total()
            .with_label_values(&["offramp_processor"])
            .inc();

        // Stage 1: Receipt Verification
        if let Err(e) = self.process_received_payments().await {
            error!(error = %e, "failed to process received payments");
        }

        // Stage 2: Withdrawal Initiation
        if let Err(e) = self.process_withdrawal_initiations().await {
            error!(error = %e, "failed to process withdrawal initiations");
        }

        // Stage 3: Transfer Monitoring
        if let Err(e) = self.process_transfer_monitoring().await {
            error!(error = %e, "failed to process transfer monitoring");
        }

        // Stage 4: Refund Processing
        if let Err(e) = self.process_refunds().await {
            error!(error = %e, "failed to process refunds");
        }

        Ok(())
    }

    /// Stage 1: Receipt Verification
    /// Selects transactions with 'cngn_received' status and verifies the amount.
    async fn process_received_payments(&self) -> Result<(), OfframpError> {
        let repo = TransactionRepository::new(self.pool.clone());
        let transactions = repo
            .find_offramps_by_status("cngn_received", self.config.batch_size)
            .await?;

        for tx in transactions {
            let tx_id = tx.transaction_id.to_string();
            info!(transaction_id = %tx_id, "verifying received cNGN payment");

            let mut metadata = OfframpMetadata::from_json(&tx.metadata)?;

            // 1. Get incoming tx hash from metadata
            let incoming_hash = metadata.stellar_tx_hash.as_deref().or_else(|| {
                // fallback to checking the generic incoming_hash field set by monitor
                tx.metadata.get("incoming_hash").and_then(|v| v.as_str())
            });

            let hash = match incoming_hash {
                Some(h) => h,
                None => {
                    error!(transaction_id = %tx_id, "no incoming hash found in metadata for cngn_received state");
                    metadata.failure_reason = Some("Missing incoming hash".to_string());
                    repo.update_status_with_metadata(&tx_id, OfframpState::RefundInitiated.as_str(), metadata.to_json()).await?;
                    continue;
                }
            };

            // 2. Fetch actual amount received on Stellar
            let distribution_account = std::env::var("SYSTEM_WALLET_ADDRESS").unwrap_or_default();
            let cngn_issuer = std::env::var("CNGN_ISSUER_TESTNET")
                .or_else(|_| std::env::var("CNGN_ISSUER_MAINNET"))
                .unwrap_or_default();

            let operations = match self.stellar_client.get_transaction_operations(hash).await {
                Ok(ops) => ops,
                Err(e) => {
                    warn!(transaction_id = %tx_id, error = %e, "failed to get transaction operations from stellar, retrying next cycle");
                    continue;
                }
            };

            let mut actual_amount_str = None;
            for op in operations {
                let op_type = op.get("type").and_then(|v| v.as_str()).unwrap_or("");
                if op_type != "payment" { continue; }
                
                let destination = op.get("to").and_then(|v| v.as_str()).unwrap_or("");
                let asset_code = op.get("asset_code").and_then(|v| v.as_str()).unwrap_or("");
                let asset_issuer = op.get("asset_issuer").and_then(|v| v.as_str()).unwrap_or("");
                
                if destination == distribution_account && asset_code.eq_ignore_ascii_case("cngn") {
                    if cngn_issuer.is_empty() || asset_issuer == cngn_issuer {
                        actual_amount_str = op.get("amount").and_then(|v| v.as_str()).map(|s| s.to_string());
                        break;
                    }
                }
            }

            let actual_amount_str = match actual_amount_str {
                Some(amt) => amt,
                None => {
                    error!(transaction_id = %tx_id, "could not find cNGN payment operation in transaction {}", hash);
                    metadata.failure_reason = Some("No cNGN payment found in tx".to_string());
                    repo.update_status_with_metadata(&tx_id, OfframpState::RefundInitiated.as_str(), metadata.to_json()).await?;
                    continue;
                }
            };

            // 3. Strict verification using BigDecimal (Zero tolerance)
            use bigdecimal::BigDecimal;
            use std::str::FromStr;

            let expected_amount = match BigDecimal::from_str(&tx.from_amount.to_string()) {
                Ok(amt) => amt,
                Err(_) => {
                    error!(transaction_id = %tx_id, "invalid expected amount format in DB");
                    metadata.failure_reason = Some("Invalid expected amount format in DB".to_string());
                    repo.update_status_with_metadata(&tx_id, OfframpState::RefundInitiated.as_str(), metadata.to_json()).await?;
                    continue;
                }
            };

            let actual_amount = match BigDecimal::from_str(&actual_amount_str) {
                Ok(amt) => amt,
                Err(_) => {
                    error!(transaction_id = %tx_id, "invalid actual amount format from Stellar");
                    metadata.failure_reason = Some("Invalid actual amount format from Stellar".to_string());
                    repo.update_status_with_metadata(&tx_id, OfframpState::RefundInitiated.as_str(), metadata.to_json()).await?;
                    continue;
                }
            };

            if expected_amount != actual_amount {
                error!(
                    transaction_id = %tx_id, 
                    expected = %expected_amount, 
                    actual = %actual_amount, 
                    "strict amount mismatch detected"
                );
                metadata.failure_reason = Some(format!("Amount mismatch. Expected {}, got {}", expected_amount, actual_amount));
                
                // Transition to refund
                repo.update_status_with_metadata(&tx_id, OfframpState::RefundInitiated.as_str(), metadata.to_json()).await?;
                self.notification_service.send_notification(&tx, NotificationType::OfframpFailed, "Received amount does not precisely match expected amount, initiating refund").await;
                continue;
            }

            // Amounts matched perfectly, proceed to transfer
            let next_status = OfframpState::ProcessingWithdrawal;
            repo.update_status(&tx_id, next_status.as_str()).await?;
            info!(transaction_id = %tx_id, "cNGN payment verified perfectly, moving to withdrawal initiation");
            
            self.notification_service.send_notification(&tx, NotificationType::CngnReceived, "Stellar payment received and precisely verified, processing bank transfer").await;
        }

        Ok(())
    }

    /// Stage 2: Withdrawal Initiation
    /// Selects transactions with 'processing_withdrawal' status and initiates the bank transfer.
    async fn process_withdrawal_initiations(&self) -> Result<(), OfframpError> {
        let repo = TransactionRepository::new(self.pool.clone());
        let transactions = repo
            .find_offramps_by_status("processing_withdrawal", self.config.batch_size)
            .await?;

        for tx in transactions {
            let tx_id = tx.transaction_id.to_string();
            info!(transaction_id = %tx_id, "initiating withdrawal for transaction");

            let mut metadata = OfframpMetadata::from_json(&tx.metadata)?;

            // Prepare withdrawal request
            let recipient = crate::payments::types::WithdrawalRecipient {
                account_name: Some(metadata.account_name.clone()),
                account_number: Some(metadata.account_number.clone()),
                bank_code: Some(metadata.bank_code.clone()),
                phone_number: None,
            };

            let amount = crate::payments::types::Money {
                amount: tx.to_amount.to_string(),
                currency: tx.to_currency.clone(),
            };

            let request = crate::payments::types::WithdrawalRequest {
                amount,
                recipient,
                withdrawal_method: crate::payments::types::WithdrawalMethod::BankTransfer,
                transaction_reference: tx_id.clone(),
                reason: Some(format!("Withdrawal for transaction {}", tx_id)),
                metadata: Some(tx.metadata.clone()),
            };

            // Provide failover logic explicitly. Attempt 1-2 on Flutterwave, fallback to Paystack on 3
            let attempt = metadata.retry_count + 1;
            let max_retries = 3; 
            
            let provider_name = if attempt <= 2 {
                crate::payments::types::ProviderName::Flutterwave
            } else {
                crate::payments::types::ProviderName::Paystack
            };

            info!(transaction_id = %tx_id, provider = %provider_name, attempt = attempt, "attempting withdrawal initiation");

            let provider = match self.provider_factory.get_provider(provider_name.clone()) {
                Ok(p) => p,
                Err(e) => {
                    warn!(transaction_id = %tx_id, provider = %provider_name, error = %e, "failed to get provider from factory");
                    // Force failure logic below if we can't even load a provider
                    metadata.failure_reason = Some(format!("Provider {} not configured", provider_name));
                    repo.update_status_with_metadata(&tx_id, OfframpState::RefundInitiated.as_str(), metadata.to_json()).await?;
                    continue;
                }
            };

            match provider.process_withdrawal(request.clone()).await {
                Ok(response) => {
                    info!(transaction_id = %tx_id, provider = %provider_name, reference = ?response.provider_reference, "withdrawal initiated successfully");

                    metadata.provider_name = Some(provider_name.to_string());
                    metadata.provider_reference = response.provider_reference;
                    metadata.provider_response = response.provider_data;
                    metadata.retry_count = 0; // Reset active retries for the monitoring phase

                    repo.update_status_with_metadata(
                        &tx_id,
                        OfframpState::TransferPending.as_str(),
                        metadata.to_json(),
                    )
                    .await?;
                }
                Err(e) => {
                    warn!(transaction_id = %tx_id, provider = %provider_name, error = %e, "provider withdrawal initiation failed");
                    
                    let is_recoverable = match &e {
                        crate::payments::error::PaymentError::NetworkError { .. } => true,
                        crate::payments::error::PaymentError::RateLimitError { .. } => true,
                        crate::payments::error::PaymentError::ProviderError { retryable, .. } => *retryable,
                        // Could expand with more specific error matching here
                        _ => false,
                    };

                    if attempt >= max_retries || !is_recoverable {
                        error!(transaction_id = %tx_id, "withdrawal initiation failed permanently");
                        metadata.failure_reason = Some(e.to_string());
                        repo.update_status_with_metadata(
                            &tx_id,
                            OfframpState::RefundInitiated.as_str(),
                            metadata.to_json(),
                        )
                        .await?;
                        self.notification_service.send_notification(&tx, NotificationType::OfframpFailed, "Bank transfer initiation failed, initiating refund").await;
                    } else {
                        // Schedule retry
                        metadata.retry_count = attempt;
                        metadata.last_retry_at = Some(chrono::Utc::now().to_rfc3339());
                        metadata.failure_reason = Some(e.to_string());
                        
                        repo.update_status_with_metadata(
                            &tx_id,
                            OfframpState::ProcessingWithdrawal.as_str(), // Keep in same state for next loop
                            metadata.to_json(),
                        )
                        .await?;
                        info!(transaction_id = %tx_id, attempt = attempt, "scheduled withdrawal initiation retry");
                    }
                }
            }
        }

        Ok(())
    }

    /// Stage 3: Transfer Monitoring
    /// Selects transactions with 'transfer_pending' status and polls for completion.
    async fn process_transfer_monitoring(&self) -> Result<(), OfframpError> {
        let repo = TransactionRepository::new(self.pool.clone());
        let transactions = repo
            .find_offramps_by_status("transfer_pending", self.config.batch_size)
            .await?;

        for tx in transactions {
            let tx_id = tx.transaction_id.to_string();
            info!(transaction_id = %tx_id, "monitoring transfer status");

            let mut metadata = OfframpMetadata::from_json(&tx.metadata)?;
            let provider_name_str = metadata.provider_name.as_ref().ok_or_else(|| {
                OfframpError::Internal(format!("missing provider name for transaction {}", tx_id))
            })?;
            let provider_name = crate::payments::types::ProviderName::from_str(provider_name_str)?;

            // Respect exponential backoff delay if scheduled
            if let Some(next_retry) = &metadata.next_retry_after {
                if let Ok(next_dt) = chrono::DateTime::parse_from_rfc3339(next_retry) {
                    if chrono::Utc::now() < next_dt.with_timezone(&chrono::Utc) {
                        debug!(transaction_id = %tx_id, "skipping transfer monitoring, waiting for next retry window");
                        continue;
                    }
                }
            }

            let provider = self.provider_factory.get_provider(provider_name.clone())?;

            let status_request = crate::payments::types::StatusRequest {
                transaction_reference: Some(tx_id.clone()),
                provider_reference: metadata.provider_reference.clone(),
            };

            match provider.get_payment_status(status_request).await {
                Ok(response) => {
                    match response.status {
                        crate::payments::types::PaymentState::Success => {
                            info!(transaction_id = %tx_id, "transfer confirmed successful by provider");
                            repo.update_status_with_metadata(&tx_id, OfframpState::Completed.as_str(), metadata.to_json()).await?;
                            self.notification_service.send_notification(&tx, NotificationType::OfframpCompleted, "Funds have been sent to your bank account").await;
                        }
                        crate::payments::types::PaymentState::Failed => {
                            error!(transaction_id = %tx_id, "transfer failed at provider");
                            metadata.failure_reason = response
                                .failure_reason
                                .or(Some("Provider reported failure".to_string()));
                            repo.update_status_with_metadata(
                                &tx_id,
                                OfframpState::RefundInitiated.as_str(),
                                metadata.to_json(),
                            )
                            .await?;
                            self.notification_service.send_notification(&tx, NotificationType::OfframpFailed, "Bank transfer failed, initiating refund").await;
                        }
                        crate::payments::types::PaymentState::Pending
                        | crate::payments::types::PaymentState::Processing => {
                            debug!(transaction_id = %tx_id, "transfer still pending at provider");
                            // Keep in transfer_pending, we'll check again in next cycle.

                            // Check for timeout
                            let created_at = tx.created_at;
                            let duration = chrono::Utc::now().signed_duration_since(created_at);
                            if duration.num_seconds() > self.config.retry_timeout.as_secs() as i64 {
                                error!(transaction_id = %tx_id, "transfer timed out at provider");
                                metadata.failure_reason = Some("Transfer timeout".to_string());
                                repo.update_status_with_metadata(
                                    &tx_id,
                                    OfframpState::RefundInitiated.as_str(),
                                    metadata.to_json(),
                                )
                                .await?;
                            }
                        }
                        _ => {
                            warn!(transaction_id = %tx_id, status = ?response.status, "received unexpected status from provider");
                        }
                    }
                }
                Err(e) => {
                    warn!(transaction_id = %tx_id, error = %e, "failed to poll provider status");
                    
                    // Implement exponential backoff for polling
                    let attempt = metadata.retry_count + 1;
                    let max_retries = 3;
                    
                    if attempt > max_retries {
                        error!(transaction_id = %tx_id, "max retries exceeded while polling provider status");
                        metadata.failure_reason = Some(format!("Failed to poll provider status after {} attempts: {}", max_retries, e));
                        repo.update_status_with_metadata(
                            &tx_id,
                            OfframpState::RefundInitiated.as_str(),
                            metadata.to_json(),
                        )
                        .await?;
                        self.notification_service.send_notification(&tx, NotificationType::OfframpFailed, "Bank transfer monitoring failed, initiating refund").await;
                    } else {
                        // Delay mapping: Attempt 1 = 30s, Attempt 2 = 120s (2m), Attempt 3 = 600s (10m)
                        let delay_secs = match attempt {
                            1 => 30,
                            2 => 120,
                            _ => 600,
                        };
                        
                        metadata.retry_count = attempt;
                        metadata.last_retry_at = Some(chrono::Utc::now().to_rfc3339());
                        
                        let next_retry = chrono::Utc::now() + chrono::Duration::seconds(delay_secs);
                        metadata.next_retry_after = Some(next_retry.to_rfc3339());
                        
                        repo.update_status_with_metadata(
                            &tx_id,
                            OfframpState::TransferPending.as_str(), // Keep in pending, but metadata updated with next retry
                            metadata.to_json(),
                        )
                        .await?;
                        info!(transaction_id = %tx_id, attempt = attempt, next_retry = %next_retry, "scheduled transfer monitoring retry");
                    }
                }
            }
        }

        Ok(())
    }

    /// Stage 4: Refund Processing
    /// Selects transactions with 'refund_initiated' status and processes the Stellar refund.
    async fn process_refunds(&self) -> Result<(), OfframpError> {
        let repo = TransactionRepository::new(self.pool.clone());
        let transactions = repo
            .find_offramps_by_status("refund_initiated", self.config.batch_size)
            .await?;

        for tx in transactions {
            let tx_id = tx.transaction_id.to_string();
            info!(transaction_id = %tx_id, "processing refund for transaction");

            let mut metadata = OfframpMetadata::from_json(&tx.metadata)?;

            // Build refund payment on Stellar
            let builder = CngnPaymentBuilder::new(self.stellar_client.clone());

            let amount_str = tx.cngn_amount.to_string();
            // The user req is: `REFUND-{original_memo}`. Here the original memo used was either the tx_id or WD-{tx_id}.
            // We ensure it fits the 28 char Stellar text memo limit.
            let memo_str = format!("REFUND-{}", tx_id);
            let memo_str = if memo_str.len() > 28 {
                memo_str[..28].to_string()
            } else {
                memo_str
            };
            
            let memo = CngnMemo::Text(memo_str);

            repo.update_status(&tx_id, OfframpState::Refunding.as_str())
                .await?;

            match builder
                .build_payment(
                    &self.config.system_wallet_address,
                    &tx.wallet_address,
                    &amount_str,
                    memo,
                    None,
                )
                .await
            {
                Ok(draft) => match builder.sign_payment(draft, &self.config.hot_wallet_secret) {
                    Ok(signed) => {
                        match builder
                            .submit_signed_payment(&signed.signed_envelope_xdr)
                            .await
                        {
                            Ok(response) => {
                                info!(transaction_id = %tx_id, "refund submitted successfully to Stellar");

                                metadata.refund_tx_hash = Some(signed.draft.transaction_hash);
                                metadata.refund_amount = Some(amount_str);
                                metadata.refund_confirmed_at =
                                    Some(chrono::Utc::now().to_rfc3339());

                                repo.update_status_with_metadata(
                                    &tx_id,
                                    OfframpState::Refunded.as_str(),
                                    metadata.to_json(),
                                )
                                .await?;
                                self.notification_service.send_notification(&tx, NotificationType::OfframpRefunded, "Refund successful on Stellar").await;
                            }
                            Err(e) => {
                                error!(transaction_id = %tx_id, error = %e, "failed to submit refund transaction");
                                metadata.failure_reason =
                                    Some(format!("Stellar submission error: {}", e));
                                repo.update_status_with_metadata(
                                    &tx_id,
                                    OfframpState::Failed.as_str(),
                                    metadata.to_json(),
                                )
                                .await?;
                            }
                        }
                    }
                    Err(e) => {
                        error!(transaction_id = %tx_id, error = %e, "failed to sign refund transaction");
                        metadata.failure_reason = Some(format!("Stellar signing error: {}", e));
                        repo.update_status_with_metadata(
                            &tx_id,
                            OfframpState::Failed.as_str(),
                            metadata.to_json(),
                        )
                        .await?;
                    }
                },
                Err(e) => {
                    error!(transaction_id = %tx_id, error = %e, "failed to build refund transaction");
                    metadata.failure_reason = Some(format!("Stellar build error: {}", e));
                    repo.update_status_with_metadata(
                        &tx_id,
                        OfframpState::Failed.as_str(),
                        metadata.to_json(),
                    )
                    .await?;
                }
            }
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offramp_state_transitions_are_validated() {
        // Valid transitions
        assert!(OfframpState::PendingPayment.can_transition_to(&OfframpState::CngnReceived));
        assert!(OfframpState::CngnReceived.can_transition_to(&OfframpState::VerifyingAmount));
        assert!(
            OfframpState::VerifyingAmount.can_transition_to(&OfframpState::ProcessingWithdrawal)
        );
        assert!(
            OfframpState::ProcessingWithdrawal.can_transition_to(&OfframpState::TransferPending)
        );
        assert!(OfframpState::TransferPending.can_transition_to(&OfframpState::Completed));
        assert!(
            OfframpState::ProcessingWithdrawal.can_transition_to(&OfframpState::RefundInitiated)
        );
        assert!(OfframpState::RefundInitiated.can_transition_to(&OfframpState::Refunding));
        assert!(OfframpState::Refunding.can_transition_to(&OfframpState::Refunded));
        assert!(OfframpState::PendingPayment.can_transition_to(&OfframpState::Expired));

        // Invalid transitions
        assert!(
            !OfframpState::PendingPayment.can_transition_to(&OfframpState::ProcessingWithdrawal)
        );
        assert!(!OfframpState::CngnReceived.can_transition_to(&OfframpState::Completed));
        assert!(!OfframpState::Completed.can_transition_to(&OfframpState::Failed));
        assert!(!OfframpState::Refunded.can_transition_to(&OfframpState::PendingPayment));
    }

    #[test]
    fn offramp_state_string_conversion() {
        assert_eq!(OfframpState::PendingPayment.as_str(), "pending_payment");
        assert_eq!(OfframpState::CngnReceived.as_str(), "cngn_received");
        assert_eq!(OfframpState::Completed.as_str(), "completed");
        assert_eq!(OfframpState::RefundInitiated.as_str(), "refund_initiated");
        assert_eq!(OfframpState::Refunding.as_str(), "refunding");
        assert_eq!(OfframpState::Refunded.as_str(), "refunded");
        assert_eq!(OfframpState::Failed.as_str(), "failed");
        assert_eq!(OfframpState::Expired.as_str(), "expired");

        assert_eq!(
            OfframpState::from_str("pending_payment"),
            Some(OfframpState::PendingPayment)
        );
        assert_eq!(
            OfframpState::from_str("cngn_received"),
            Some(OfframpState::CngnReceived)
        );
        assert_eq!(OfframpState::from_str("invalid"), None);
    }

    #[test]
    fn offramp_metadata_json_roundtrip() {
        let metadata = OfframpMetadata::new(
            "John Doe".to_string(),
            "0123456789".to_string(),
            "058".to_string(),
        );

        let json = metadata.to_json();
        let parsed = OfframpMetadata::from_json(&json).unwrap();

        assert_eq!(parsed.account_name, "John Doe");
        assert_eq!(parsed.account_number, "0123456789");
        assert_eq!(parsed.bank_code, "058");
        assert_eq!(parsed.retry_count, 0);
    }

    #[test]
    fn config_validation_requires_secrets() {
        let mut config = OfframpProcessorConfig::default();
        assert!(config.validate().is_err());

        config.hot_wallet_secret = "SECRET".to_string();
        assert!(config.validate().is_err());

        config.system_wallet_address = "GADDRESS".to_string();
        assert!(config.validate().is_ok());
    }
}
