//! Balance poller — fetches cleared/pending balances from partner bank APIs
//! every 15 minutes (ISO 20022 / MT940 compatible).

use super::shadow_ledger::ShadowLedger;
use reqwest::Client;
use serde::Deserialize;
use sqlx::types::BigDecimal;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use tracing::{error, info};

/// Configuration for a single bank API endpoint
#[derive(Debug, Clone)]
pub struct BankApiConfig {
    pub account_id: uuid::Uuid,
    pub base_url: String,
    pub api_key: String,
    /// ISO 20022 or MT940
    pub protocol: String,
}

#[derive(Debug, Deserialize)]
struct BankBalanceResponse {
    cleared_balance: String,
    pending_balance: String,
}

pub struct BalancePoller {
    bank_configs: Vec<BankApiConfig>,
    shadow_ledger: Arc<ShadowLedger>,
    http: Client,
    poll_interval: Duration,
}

impl BalancePoller {
    pub fn new(
        bank_configs: Vec<BankApiConfig>,
        shadow_ledger: Arc<ShadowLedger>,
        poll_interval_secs: u64,
    ) -> Self {
        Self {
            bank_configs,
            shadow_ledger,
            http: Client::new(),
            poll_interval: Duration::from_secs(poll_interval_secs),
        }
    }

    /// Start the polling loop. Runs until shutdown signal received.
    pub async fn run(&self, mut shutdown: watch::Receiver<bool>) {
        info!(
            interval_secs = %self.poll_interval.as_secs(),
            accounts = %self.bank_configs.len(),
            "Nostro balance poller started"
        );

        loop {
            tokio::select! {
                _ = tokio::time::sleep(self.poll_interval) => {
                    self.poll_all().await;
                }
                _ = shutdown.changed() => {
                    info!("Nostro balance poller shutting down");
                    break;
                }
            }
        }
    }

    async fn poll_all(&self) {
        for config in &self.bank_configs {
            if let Err(e) = self.poll_account(config).await {
                error!(
                    account_id = %config.account_id,
                    error = %e,
                    "Failed to poll Nostro balance"
                );
            }
        }
    }

    async fn poll_account(&self, config: &BankApiConfig) -> Result<(), anyhow::Error> {
        if config.api_key.is_empty() {
            // No bank API configured — skip (dev/test mode)
            return Ok(());
        }

        let resp = self
            .http
            .get(format!("{}/balance", config.base_url))
            .bearer_auth(&config.api_key)
            .send()
            .await?
            .json::<BankBalanceResponse>()
            .await?;

        let cleared = BigDecimal::from_str(&resp.cleared_balance)?;
        let pending = BigDecimal::from_str(&resp.pending_balance)?;

        info!(
            account_id = %config.account_id,
            cleared = %cleared,
            pending = %pending,
            "Nostro balance polled"
        );

        self.shadow_ledger
            .update_balance(config.account_id, cleared, pending, "bank_api")
            .await?;

        Ok(())
    }
}
