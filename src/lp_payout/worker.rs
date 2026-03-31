//! LP Payout Worker
//!
//! Two loops:
//!   1. Hourly snapshot loop  — polls Stellar Horizon for pool balances.
//!   2. Epoch disbursement loop — fires at epoch end, calculates rewards,
//!      builds & submits cNGN payment transactions for each LP.

use crate::chains::stellar::client::StellarClient;
use crate::lp_payout::{
    engine::RewardEngine,
    models::LpPayout,
    repository::LpPayoutRepository,
};
use crate::services::cngn_payment_builder::{CngnPaymentBuilder, PaymentMemo, PaymentOperation};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use tracing::{error, info, warn};
use uuid::Uuid;

pub struct LpPayoutWorkerConfig {
    pub snapshot_interval: Duration,
    pub disbursement_check_interval: Duration,
    pub pool_id: String,
    pub cngn_issuer: String,
    pub system_wallet_secret: String,
    pub system_wallet_address: String,
}

impl LpPayoutWorkerConfig {
    pub fn from_env() -> Self {
        Self {
            snapshot_interval: Duration::from_secs(
                std::env::var("LP_SNAPSHOT_INTERVAL_SECS")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(3600),
            ),
            disbursement_check_interval: Duration::from_secs(
                std::env::var("LP_DISBURSEMENT_CHECK_SECS")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(300),
            ),
            pool_id: std::env::var("LP_STELLAR_POOL_ID").unwrap_or_default(),
            cngn_issuer: std::env::var("CNGN_ISSUER_ADDRESS")
                .or_else(|_| std::env::var("CNGN_ISSUER_MAINNET"))
                .unwrap_or_default(),
            system_wallet_secret: std::env::var("SYSTEM_WALLET_SECRET").unwrap_or_default(),
            system_wallet_address: std::env::var("SYSTEM_WALLET_ADDRESS").unwrap_or_default(),
        }
    }
}

pub struct LpPayoutWorker {
    repo: Arc<LpPayoutRepository>,
    engine: Arc<RewardEngine>,
    stellar_client: StellarClient,
    config: LpPayoutWorkerConfig,
}

impl LpPayoutWorker {
    pub fn new(
        repo: Arc<LpPayoutRepository>,
        stellar_client: StellarClient,
        config: LpPayoutWorkerConfig,
    ) -> Self {
        let engine = Arc::new(RewardEngine::new(repo.clone()));
        Self {
            repo,
            engine,
            stellar_client,
            config,
        }
    }

    pub async fn run(self, mut shutdown_rx: watch::Receiver<bool>) {
        info!("LP Payout worker started");

        let mut snapshot_ticker = tokio::time::interval(self.config.snapshot_interval);
        let mut disburse_ticker =
            tokio::time::interval(self.config.disbursement_check_interval);

        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        info!("LP Payout worker stopping");
                        break;
                    }
                }
                _ = snapshot_ticker.tick() => {
                    if let Err(e) = self.run_snapshot_cycle().await {
                        error!(error = %e, "LP snapshot cycle failed");
                    }
                }
                _ = disburse_ticker.tick() => {
                    if let Err(e) = self.run_disbursement_cycle().await {
                        error!(error = %e, "LP disbursement cycle failed");
                    }
                }
            }
        }
    }

    // ── Snapshot cycle ────────────────────────────────────────────────────────

    async fn run_snapshot_cycle(&self) -> anyhow::Result<()> {
        if self.config.pool_id.is_empty() {
            warn!("LP_STELLAR_POOL_ID not set — skipping snapshot");
            return Ok(());
        }

        let providers = self.repo.list_active_providers().await?;
        if providers.is_empty() {
            return Ok(());
        }

        let now = chrono::Utc::now();
        let total_pool = self.fetch_pool_total_stroops().await.unwrap_or(0);
        let volume = self.fetch_pool_volume_stroops().await.unwrap_or(0);

        let mut pool_data = Vec::new();

        for provider in &providers {
            // Fetch raw Horizon account to get liquidity_pool_shares balance
            let lp_balance = self
                .fetch_lp_balance_stroops(&provider.stellar_address)
                .await
                .unwrap_or(0);

            pool_data.push((
                self.config.pool_id.clone(),
                provider.id,
                lp_balance,
                total_pool,
                volume,
            ));
        }

        self.engine.record_snapshots(now, pool_data).await?;
        info!(snapshot_at = %now, providers = providers.len(), "LP pool snapshots recorded");
        Ok(())
    }

    // ── Disbursement cycle ────────────────────────────────────────────────────

    async fn run_disbursement_cycle(&self) -> anyhow::Result<()> {
        let epochs = self.repo.get_unfinalized_epochs().await?;

        for epoch in epochs {
            info!(epoch_id = %epoch.id, "Processing LP epoch disbursement");

            self.engine
                .calculate_epoch_rewards(
                    epoch.id,
                    epoch.epoch_start,
                    epoch.epoch_end,
                    epoch.total_fees_stroops,
                    epoch.total_volume_stroops,
                )
                .await?;

            // Aggregate per-LP totals and create payout records
            let accrued = self.repo.accrued_rewards_for_epoch(epoch.id).await?;
            let providers = self.repo.list_active_providers().await?;
            let provider_map: std::collections::HashMap<Uuid, String> = providers
                .into_iter()
                .map(|p| (p.id, p.stellar_address))
                .collect();

            // Group by provider: (total_stroops, compliance_withheld, reason)
            let mut by_provider: std::collections::HashMap<Uuid, (i64, bool, Option<String>)> =
                std::collections::HashMap::new();
            for reward in &accrued {
                let entry = by_provider
                    .entry(reward.lp_provider_id)
                    .or_insert((0, false, None));
                entry.0 += reward.accrued_stroops;
                if reward.compliance_flagged {
                    entry.1 = true;
                    entry.2 = reward.compliance_reason.clone();
                }
            }

            for (lp_id, (total_stroops, compliance_withheld, compliance_reason)) in &by_provider {
                if *total_stroops == 0 {
                    continue;
                }
                let stellar_address = match provider_map.get(lp_id) {
                    Some(a) => a.clone(),
                    None => continue,
                };

                let payout = LpPayout {
                    id: Uuid::new_v4(),
                    epoch_id: epoch.id,
                    lp_provider_id: *lp_id,
                    stellar_address,
                    total_stroops: *total_stroops,
                    status: if *compliance_withheld {
                        "flagged".to_string()
                    } else {
                        "pending".to_string()
                    },
                    stellar_tx_hash: None,
                    compliance_withheld: *compliance_withheld,
                    compliance_reason: compliance_reason.clone(),
                    attempted_at: None,
                    completed_at: None,
                    created_at: chrono::Utc::now(),
                };
                self.repo.create_payout(&payout).await?;
            }

            self.dispatch_pending_payouts().await?;
            self.repo.finalize_epoch(epoch.id).await?;
            info!(epoch_id = %epoch.id, "Epoch finalized and payouts dispatched");
        }

        Ok(())
    }

    async fn dispatch_pending_payouts(&self) -> anyhow::Result<()> {
        if self.config.system_wallet_secret.is_empty() || self.config.cngn_issuer.is_empty() {
            warn!("SYSTEM_WALLET_SECRET or CNGN_ISSUER_ADDRESS not set — skipping payout dispatch");
            return Ok(());
        }

        let pending = self.repo.pending_payouts().await?;
        let builder = CngnPaymentBuilder::new(self.stellar_client.clone());

        for payout in pending {
            // Stellar amounts use 7 decimal places
            let amount_cngn = format!("{:.7}", payout.total_stroops as f64 / 1e7);

            let op = PaymentOperation {
                source: self.config.system_wallet_address.clone(),
                destination: payout.stellar_address.clone(),
                amount: amount_cngn,
                asset_code: "cNGN".to_string(),
                asset_issuer: self.config.cngn_issuer.clone(),
            };
            let memo = PaymentMemo::Text(format!("LP reward {}", payout.epoch_id));

            let draft = match builder.build_payment(op, memo, None).await {
                Ok(d) => d,
                Err(e) => {
                    error!(lp = %payout.stellar_address, error = %e, "Failed to build payout tx");
                    self.repo.mark_payout_failed(payout.id).await?;
                    continue;
                }
            };

            let signed = match builder.sign_transaction(draft, &self.config.system_wallet_secret) {
                Ok(s) => s,
                Err(e) => {
                    error!(lp = %payout.stellar_address, error = %e, "Failed to sign payout tx");
                    self.repo.mark_payout_failed(payout.id).await?;
                    continue;
                }
            };

            match self
                .stellar_client
                .submit_transaction_xdr(&signed.envelope_xdr)
                .await
            {
                Ok(resp) => {
                    let tx_hash = resp["hash"]
                        .as_str()
                        .unwrap_or(&signed.hash)
                        .to_string();
                    self.repo.mark_payout_completed(payout.id, &tx_hash).await?;
                    info!(
                        lp = %payout.stellar_address,
                        stroops = payout.total_stroops,
                        tx_hash = %tx_hash,
                        "LP payout completed"
                    );
                }
                Err(e) => {
                    error!(lp = %payout.stellar_address, error = %e, "Stellar submission failed");
                    self.repo.mark_payout_failed(payout.id).await?;
                }
            }
        }

        Ok(())
    }

    // ── Stellar helpers ───────────────────────────────────────────────────────

    /// Fetch LP's share of the pool via raw Horizon account endpoint.
    async fn fetch_lp_balance_stroops(&self, address: &str) -> anyhow::Result<i64> {
        let url = format!(
            "{}/accounts/{}",
            self.stellar_client.config().horizon_url(),
            address
        );
        let resp: serde_json::Value = reqwest::get(&url).await?.json().await?;
        let balance = resp["balances"]
            .as_array()
            .and_then(|balances| {
                balances.iter().find(|b| {
                    b["asset_type"].as_str() == Some("liquidity_pool_shares")
                        && b["liquidity_pool_id"].as_str() == Some(&self.config.pool_id)
                })
            })
            .and_then(|b| b["balance"].as_str())
            .and_then(|s| s.parse::<f64>().ok())
            .unwrap_or(0.0);
        Ok((balance * 1e7) as i64)
    }

    async fn fetch_pool_total_stroops(&self) -> anyhow::Result<i64> {
        let url = format!(
            "{}/liquidity_pools/{}",
            self.stellar_client.config().horizon_url(),
            self.config.pool_id
        );
        let resp: serde_json::Value = reqwest::get(&url).await?.json().await?;
        let total = resp["total_shares"]
            .as_str()
            .and_then(|s| s.parse::<f64>().ok())
            .unwrap_or(0.0);
        Ok((total * 1e7) as i64)
    }

    async fn fetch_pool_volume_stroops(&self) -> anyhow::Result<i64> {
        let url = format!(
            "{}/liquidity_pools/{}/trades?limit=200&order=desc",
            self.stellar_client.config().horizon_url(),
            self.config.pool_id
        );
        let resp: serde_json::Value = reqwest::get(&url).await?.json().await?;
        let volume: f64 = resp["_embedded"]["records"]
            .as_array()
            .map(|records| {
                records
                    .iter()
                    .filter_map(|r| r["base_amount"].as_str()?.parse::<f64>().ok())
                    .sum()
            })
            .unwrap_or(0.0);
        Ok((volume * 1e7) as i64)
    }
}
