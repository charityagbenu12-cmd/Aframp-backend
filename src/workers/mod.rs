use chrono::Utc;
use tracing::{info_span, Instrument};
use uuid::Uuid;

use crate::services::transaction::TransactionService;

/// The transaction monitor worker watches for Stellar blockchain confirmations
/// and updates transaction status accordingly.
///
/// Every worker cycle emits:
/// * A root span labelled `worker.cycle` with `worker.name` and `worker.cycle_at`.
/// * A child span per transaction processed labelled `worker.process_transaction`.
/// * A child span per external API call within the cycle.
pub struct TransactionMonitorWorker {
    pub tx_service: TransactionService,
    pub stellar_url: String,
    pub http_client: reqwest::Client,
pub mod maintenance;
pub mod offramp_processor;
pub mod onramp_processor;
pub mod payment_poller;
pub mod transaction_monitor;
pub mod webhook_retry;
pub mod bill_processor;
pub mod batch_processor;
pub mod bill_processor {
    pub mod account_verification;
    pub mod payment_executor;
    pub mod providers;
    pub mod refund_handler;
    pub mod token_manager;
    pub mod types;
}

impl TransactionMonitorWorker {
    pub fn new(tx_service: TransactionService, stellar_url: String) -> Self {
        Self {
            tx_service,
            stellar_url,
            http_client: reqwest::Client::new(),
        }
    }

    /// Run one cycle of the transaction monitor.
    pub async fn run_cycle(&self) {
        let cycle_at = Utc::now().to_rfc3339();

        // Root span for the entire worker cycle.
        let cycle_span = info_span!(
            "worker.cycle",
            worker.name = "transaction_monitor",
            worker.cycle_at = %cycle_at,
        );

        async {
            tracing::info!("Transaction monitor worker cycle started");

            // Fetch pending transactions (simulated).
            let pending = self.fetch_pending_transactions().await;

            for tx_id in pending {
                self.process_transaction(tx_id).await;
            }

            tracing::info!("Transaction monitor worker cycle complete");
        }
        .instrument(cycle_span)
        .await;
    }

    /// Process a single transaction within a worker cycle.
    ///
    /// This emits a child span under the cycle's root span.
    async fn process_transaction(&self, tx_id: Uuid) {
        let span = info_span!(
            "worker.process_transaction",
            tx_id = %tx_id,
        );

        async {
            tracing::info!(%tx_id, "Processing transaction");

            // Check on-chain status via Horizon API — emits its own child span.
            let confirmed = self.check_onchain_status(&tx_id.to_string()).await;

            if confirmed {
                if let Err(e) = self.tx_service.update_status(tx_id, "confirmed").await {
                    tracing::error!(%tx_id, error = %e, "Failed to update transaction status");
                } else {
                    tracing::info!(%tx_id, "Transaction confirmed and status updated");
                }
            }
        }
        .instrument(span)
        .await;
    }

    /// Call the Stellar Horizon API to check on-chain confirmation status.
    ///
    /// Emits a child span labelled `worker.external_api_call`.
    async fn check_onchain_status(&self, tx_hash: &str) -> bool {
        let url = format!("{}/transactions/{}", self.stellar_url, tx_hash);

        let span = info_span!(
            "worker.external_api_call",
            otel.kind = "client",
            peer.service = "stellar_horizon",
            http.method = "GET",
            http.url = %url,
        );

        async {
            tracing::debug!(%tx_hash, "Checking on-chain status via Horizon");
            // Simulated confirmation.
            true
        }
        .instrument(span)
        .await
    }

    /// Fetch pending transaction IDs from the database.
    async fn fetch_pending_transactions(&self) -> Vec<Uuid> {
        let span = info_span!(
            "db.query",
            otel.kind = "client",
            db.system = "postgresql",
            db.operation = "SELECT",
            db.sql.table = "transactions",
            db.sql.filter = "status=pending",
        );

        async {
            tracing::debug!("Fetching pending transactions from database");
            // Simulated result.
            vec![Uuid::new_v4(), Uuid::new_v4()]
        }
        .instrument(span)
        .await
    }
}

/// Payment processor worker polls provider webhooks for payment confirmations.
pub struct PaymentProcessorWorker {
    pub http_client: reqwest::Client,
}

impl PaymentProcessorWorker {
    pub fn new() -> Self {
        Self {
            http_client: reqwest::Client::new(),
        }
    }

    /// Run one cycle of the payment processor worker.
    pub async fn run_cycle(&self) {
        let cycle_at = Utc::now().to_rfc3339();

        let cycle_span = info_span!(
            "worker.cycle",
            worker.name = "payment_processor",
            worker.cycle_at = %cycle_at,
        );

        async {
            tracing::info!("Payment processor worker cycle started");
            // Poll provider APIs and process queued payment events.
            tracing::info!("Payment processor worker cycle complete");
        }
        .instrument(cycle_span)
        .await;
    }
}