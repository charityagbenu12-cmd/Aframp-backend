//! Merchant Payment Monitor Worker
//! Monitors Stellar blockchain for incoming payments to merchant addresses
//! Matches payments to payment intents via memo field

use crate::chains::stellar::client::StellarClient;
use crate::merchant_gateway::repository::PaymentIntentRepository;
use crate::merchant_gateway::service::MerchantGatewayService;
use rust_decimal::Decimal;
use sqlx::PgPool;
use std::collections::HashSet;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use tokio::time::interval;
use tracing::{error, info, instrument, warn};

// ============================================================================
// CONFIGURATION
// ============================================================================

#[derive(Debug, Clone)]
pub struct MerchantPaymentMonitorConfig {
    pub poll_interval: Duration,
    pub batch_size: i64,
    pub confirmation_threshold: u32,
}

impl Default for MerchantPaymentMonitorConfig {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_secs(10), // Fast polling for merchant payments
            batch_size: 100,
            confirmation_threshold: 1,
        }
    }
}

impl MerchantPaymentMonitorConfig {
    pub fn from_env() -> Self {
        let mut config = Self::default();
        
        if let Ok(val) = std::env::var("MERCHANT_PAYMENT_POLL_INTERVAL_SECS") {
            if let Ok(secs) = val.parse() {
                config.poll_interval = Duration::from_secs(secs);
            }
        }
        
        if let Ok(val) = std::env::var("MERCHANT_PAYMENT_BATCH_SIZE") {
            if let Ok(size) = val.parse() {
                config.batch_size = size;
            }
        }
        
        if let Ok(val) = std::env::var("MERCHANT_PAYMENT_CONFIRMATION_THRESHOLD") {
            if let Ok(threshold) = val.parse() {
                config.confirmation_threshold = threshold;
            }
        }
        
        config
    }
}

// ============================================================================
// WORKER
// ============================================================================

pub struct MerchantPaymentMonitorWorker {
    pool: PgPool,
    stellar_client: Arc<StellarClient>,
    gateway_service: Arc<MerchantGatewayService>,
    payment_intent_repo: Arc<PaymentIntentRepository>,
    config: MerchantPaymentMonitorConfig,
}

impl MerchantPaymentMonitorWorker {
    pub fn new(
        pool: PgPool,
        stellar_client: Arc<StellarClient>,
        gateway_service: Arc<MerchantGatewayService>,
        config: MerchantPaymentMonitorConfig,
    ) -> Self {
        Self {
            payment_intent_repo: Arc::new(PaymentIntentRepository::new(pool.clone())),
            pool,
            stellar_client,
            gateway_service,
            config,
        }
    }

    pub async fn run(self, mut shutdown_rx: watch::Receiver<bool>) {
        info!(
            poll_interval_secs = self.config.poll_interval.as_secs(),
            batch_size = self.config.batch_size,
            "Merchant payment monitor worker started"
        );

        let mut ticker = interval(self.config.poll_interval);
        ticker.tick().await; // Skip first immediate tick

        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        info!("Merchant payment monitor: shutdown signal received");
                        break;
                    }
                }
                _ = ticker.tick() => {
                    if let Err(e) = self.monitor_cycle().await {
                        error!(error = %e, "Merchant payment monitor cycle failed");
                    }
                }
            }
        }

        info!("Merchant payment monitor worker stopped");
    }

    #[instrument(skip(self))]
    async fn monitor_cycle(&self) -> anyhow::Result<()> {
        // Fetch pending payment intents
        let pending_intents = self
            .payment_intent_repo
            .find_pending_for_monitoring(self.config.batch_size)
            .await?;

        if pending_intents.is_empty() {
            return Ok(());
        }

        info!(count = pending_intents.len(), "Monitoring pending payment intents");

        // Group by destination address for efficient querying
        let mut addresses_to_check: HashSet<String> = HashSet::new();
        for intent in &pending_intents {
            addresses_to_check.insert(intent.destination_address.clone());
        }

        // Check each address for recent payments
        for address in addresses_to_check {
            if let Err(e) = self.check_address_payments(&address, &pending_intents).await {
                warn!(
                    address = %address,
                    error = %e,
                    "Failed to check payments for address"
                );
            }
        }

        Ok(())
    }

    #[instrument(skip(self, pending_intents))]
    async fn check_address_payments(
        &self,
        address: &str,
        pending_intents: &[crate::merchant_gateway::models::MerchantPaymentIntent],
    ) -> anyhow::Result<()> {
        // Fetch recent payments to this address from Stellar
        let payments = self
            .stellar_client
            .get_payments_for_account(address, Some(50))
            .await?;

        // Build memo -> payment intent lookup
        let mut memo_map = std::collections::HashMap::new();
        for intent in pending_intents {
            if intent.destination_address == address {
                memo_map.insert(intent.memo.clone(), intent.clone());
            }
        }

        // Match payments to intents
        for payment in payments {
            // Extract memo from payment
            let memo = match payment.memo.as_ref() {
                Some(m) => m,
                None => continue,
            };

            // Find matching payment intent
            if let Some(intent) = memo_map.get(memo) {
                // Parse amount
                let amount = match Decimal::from_str(&payment.amount) {
                    Ok(amt) => amt,
                    Err(e) => {
                        warn!(error = %e, "Failed to parse payment amount");
                        continue;
                    }
                };

                // Verify asset is cNGN
                if payment.asset_code.as_deref() != Some("cNGN") {
                    warn!(
                        memo = %memo,
                        asset = ?payment.asset_code,
                        "Payment with wrong asset type"
                    );
                    continue;
                }

                // Process the payment
                info!(
                    payment_intent_id = %intent.id,
                    memo = %memo,
                    amount = %amount,
                    tx_hash = %payment.transaction_hash,
                    "Matched payment to intent"
                );

                if let Err(e) = self
                    .gateway_service
                    .process_stellar_payment(
                        memo,
                        &payment.transaction_hash,
                        amount,
                        &payment.from,
                    )
                    .await
                {
                    error!(
                        payment_intent_id = %intent.id,
                        error = %e,
                        "Failed to process payment"
                    );
                }
            }
        }

        Ok(())
    }
}

// ============================================================================
// EXPIRY WORKER
// ============================================================================

pub struct PaymentIntentExpiryWorker {
    payment_intent_repo: Arc<PaymentIntentRepository>,
    poll_interval: Duration,
    batch_size: i64,
}

impl PaymentIntentExpiryWorker {
    pub fn new(pool: PgPool) -> Self {
        let poll_interval_secs = std::env::var("PAYMENT_INTENT_EXPIRY_CHECK_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(60);

        Self {
            payment_intent_repo: Arc::new(PaymentIntentRepository::new(pool)),
            poll_interval: Duration::from_secs(poll_interval_secs),
            batch_size: 100,
        }
    }

    pub async fn run(self, mut shutdown_rx: watch::Receiver<bool>) {
        info!(
            poll_interval_secs = self.poll_interval.as_secs(),
            "Payment intent expiry worker started"
        );

        let mut ticker = interval(self.poll_interval);
        ticker.tick().await;

        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        info!("Payment intent expiry worker: shutdown signal received");
                        break;
                    }
                }
                _ = ticker.tick() => {
                    if let Err(e) = self.expire_old_intents().await {
                        error!(error = %e, "Failed to expire payment intents");
                    }
                }
            }
        }

        info!("Payment intent expiry worker stopped");
    }

    async fn expire_old_intents(&self) -> anyhow::Result<()> {
        let expired = self
            .payment_intent_repo
            .find_expired(self.batch_size)
            .await?;

        if expired.is_empty() {
            return Ok(());
        }

        info!(count = expired.len(), "Expiring payment intents");

        for intent in expired {
            if let Err(e) = self.payment_intent_repo.mark_expired(intent.id).await {
                warn!(
                    payment_intent_id = %intent.id,
                    error = %e,
                    "Failed to mark intent as expired"
                );
            } else {
                info!(
                    payment_intent_id = %intent.id,
                    merchant_id = %intent.merchant_id,
                    "Payment intent expired"
                );
            }
        }

        Ok(())
    }
}
