use crate::chains::stellar::client::StellarClient;
use crate::chains::stellar::payment::{CngnMemo, CngnPaymentBuilder};
use crate::database::transaction_repository::TransactionRepository;
use crate::services::mint_queue::{MintQueueService, MintRequest};
use sqlx::PgPool;
use std::sync::Arc;
use tokio::sync::watch;
use tokio::time::{interval, Duration, sleep};
use tracing::{debug, error, info, warn, instrument};
use bigdecimal::BigDecimal;

pub struct SubmitterConfig {
    pub poll_interval: Duration,
    pub batch_size: usize,
    pub system_wallet_address: String,
    pub system_wallet_secret: String,
    pub fee_threshold_stroops: u32,
}

impl Default for SubmitterConfig {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_secs(5),
            batch_size: 100,
            system_wallet_address: String::new(),
            system_wallet_secret: String::new(),
            fee_threshold_stroops: 5000, // Example threshold
        }
    }
}

pub struct StellarSubmitterWorker {
    db: Arc<PgPool>,
    stellar: Arc<StellarClient>,
    queue: Arc<MintQueueService>,
    config: SubmitterConfig,
}

impl StellarSubmitterWorker {
    pub fn new(
        db: PgPool,
        stellar: StellarClient,
        queue: MintQueueService,
        config: SubmitterConfig,
    ) -> Self {
        Self {
            db: Arc::new(db),
            stellar: Arc::new(stellar),
            queue: Arc::new(queue),
            config,
        }
    }

    pub async fn run(&self, mut shutdown_rx: watch::Receiver<bool>) {
        info!("Stellar Submitter Worker started");
        let mut ticker = interval(self.config.poll_interval);

        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    info!("Stellar Submitter Worker shutting down");
                    break;
                }
                _ = ticker.tick() => {
                    if let Err(e) = self.process_batch().await {
                        error!(error = %e, "Error in submitter worker cycle");
                    }
                }
            }
        }
    }

    #[instrument(skip(self))]
    pub async fn process_batch(&self) -> Result<(), String> {
        // 1. Check backpressure (fees)
        if let Err(e) = self.check_backpressure().await {
            warn!(error = %e, "Backpressure triggered - slowing down");
            return Ok(());
        }

        // 2. Collect requests from queue (up to batch_size)
        let mut requests = Vec::new();
        while requests.len() < self.config.batch_size {
            match self.queue.pop_next().await {
                Ok(Some(req)) => requests.push(req),
                Ok(None) => break, // Queue empty
                Err(e) => {
                    error!(error = %e, "Failed to pop from queue");
                    break;
                }
            }
        }

        if requests.is_empty() {
            return Ok(());
        }

        info!(count = requests.len(), "Processing batch of mint requests");

        // 3. Fetch transaction details from DB
        let repo = TransactionRepository::new((*self.db).clone());
        let mut payments = Vec::new();
        let mut valid_requests = Vec::new();

        for req in &requests {
            match repo.find_by_id(&req.transaction_id.to_string()).await {
                Ok(Some(tx)) => {
                    if tx.status == "payment_received" || tx.status == "processing" {
                        payments.push((tx.wallet_address.clone(), tx.cngn_amount.to_string()));
                        valid_requests.push(req.clone());
                    } else {
                        warn!(tx_id = %tx.transaction_id, status = %tx.status, "Skipping tx - invalid status");
                    }
                }
                _ => {
                    error!(tx_id = %req.transaction_id, "Transaction not found in DB");
                }
            }
        }

        if payments.is_empty() {
            return Ok(());
        }

        // 4. Build and submit multi-op transaction
        let builder = CngnPaymentBuilder::new((*self.stellar).clone());
        let memo = CngnMemo::Text(format!("batch:{}", Uuid::new_v4()));

        match builder.build_multi_payment(
            &self.config.system_wallet_address,
            &payments,
            memo,
            None
        ).await {
            Ok(draft) => {
                match builder.sign_payment(draft, &self.config.system_wallet_secret) {
                    Ok(signed) => {
                        match builder.submit_signed_payment(&signed.signed_envelope_xdr).await {
                            Ok(result) => {
                                let hash = result.get("hash").and_then(|h| h.as_str()).unwrap_or("");
                                info!(hash = %hash, "Batch submitted successfully");
                                
                                // Update status for all transactions in batch
                                for req in &valid_requests {
                                    let next_status = match req.mint_type {
                                        crate::services::mint_queue::MintType::Refund => "refunding",
                                        _ => "processing",
                                    };

                                    let _ = sqlx::query(
                                        "UPDATE transactions SET status = $1, blockchain_tx_hash = $2, updated_at = NOW() WHERE transaction_id = $3"
                                    )
                                    .bind(next_status)
                                    .bind(hash)
                                    .bind(req.transaction_id)
                                    .execute((*self.db).as_ref())
                                    .await;
                                }
                            }
                            Err(e) => {
                                error!(error = %e, "Failed to submit batch transaction");
                                // TODO: Handle partial failures or requeue
                            }
                        }
                    }
                    Err(e) => error!(error = %e, "Failed to sign batch transaction"),
                }
            }
            Err(e) => error!(error = %e, "Failed to build batch transaction"),
        }

        Ok(())
    }

    async fn check_backpressure(&self) -> Result<(), String> {
        // Placeholder for fee check logic
        // self.stellar.get_latest_ledger_fees()...
        // If current fee > threshold, return Err
        Ok(())
    }
}
