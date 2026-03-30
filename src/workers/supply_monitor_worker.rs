use crate::chains::stellar::client::StellarClient;
use crate::services::notification::{NotificationService, NotificationType};
use sqlx::{PgPool, types::BigDecimal};
use std::time::Duration;
use tokio::sync::watch;
use tracing::{error, info, warn, instrument};
use std::str::FromStr;

#[derive(Debug, Clone)]
pub struct SupplyMonitorConfig {
    pub poll_interval: Duration,
    pub asset_code: String,
    pub asset_issuer: String,
    pub authorized_limit: Option<BigDecimal>,
    pub whale_threshold_percent: f64,
}

impl Default for SupplyMonitorConfig {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_secs(300), // 5 minutes
            asset_code: "cNGN".to_string(),
            asset_issuer: "".to_string(), // Must be provided
            authorized_limit: None,
            whale_threshold_percent: 5.0,
        }
    }
}

pub struct SupplyMonitorWorker {
    pool: PgPool,
    stellar_client: StellarClient,
    notification_service: std::sync::Arc<NotificationService>,
    config: SupplyMonitorConfig,
}

impl SupplyMonitorWorker {
    pub fn new(
        pool: PgPool,
        stellar_client: StellarClient,
        notification_service: std::sync::Arc<NotificationService>,
        asset_issuer: String,
    ) -> Self {
        let mut config = SupplyMonitorConfig::default();
        config.asset_issuer = asset_issuer;
        
        // Load limit from env if available
        if let Ok(limit_str) = std::env::var("CNGN_AUTHORIZED_LIMIT") {
            if let Ok(limit) = BigDecimal::from_str(&limit_str) {
                config.authorized_limit = Some(limit);
            }
        }

        Self {
            pool,
            stellar_client,
            notification_service,
            config,
        }
    }

    pub async fn run(self, mut shutdown_rx: watch::Receiver<bool>) {
        info!(
            interval_secs = self.config.poll_interval.as_secs(),
            asset = %format!("{}:{}", self.config.asset_code, self.config.asset_issuer),
            "cNGN supply monitoring worker started"
        );

        let mut ticker = tokio::time::interval(self.config.poll_interval);

        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        info!("cNGN supply monitoring worker stopping");
                        break;
                    }
                }
                _ = ticker.tick() => {
                    if let Err(e) = self.run_cycle().await {
                        error!(error = %e, "supply monitoring cycle failed");
                    }
                }
            }
        }
    }

    #[instrument(skip(self), name = "supply_monitor_cycle")]
    async fn run_cycle(&self) -> anyhow::Result<()> {
        info!("polling cNGN supply metrics from Stellar...");

        // 1. Get Asset Stats
        let stats = self.stellar_client.get_asset_stats(&self.config.asset_code, &self.config.asset_issuer).await?;
        
        let amount_str = stats.get("amount").and_then(|v| v.as_str()).unwrap_or("0");
        let num_accounts = stats.get("num_accounts").and_then(|v| v.as_u64()).unwrap_or(0) as i32;
        
        // In Stellar, 'amount' is the total issued minus what's held by the issuer? 
        // Actually, Horizon 'amount' for an asset is the sum of all balances held by non-issuer accounts.
        // This IS the circulating supply.
        let circulating_supply = BigDecimal::from_str(amount_str).unwrap_or_else(|_| BigDecimal::from(0));
        
        // 2. We don't have a direct "Total Ever Issued" in Horizon's /assets endpoint easily.
        // But we can approximate or just track Circulating Supply as requested.
        // "Total Issued" could be cumulative mints, but for the dashboard, "Amount" is what matters.
        // Let's assume Total Issued = Circulating Supply + Burned (if we tracked burns separately).
        // Since we don't have easy Burned stats from Horizon directly without crawling all txs,
        // we'll report Circulating as the primary metric.
        
        // 3. Holders & Whales
        let holders = self.stellar_client.list_asset_holders(&self.config.asset_code, &self.config.asset_issuer, 50).await?;
        
        let mut whale_records = Vec::new();
        if circulating_supply > BigDecimal::from(0) {
            for holder in holders {
                let address = holder.get("account_id").and_then(|v| v.as_str()).unwrap_or("");
                let balances = holder.get("balances").and_then(|v| v.as_array());
                
                if let Some(balances) = balances {
                    for b in balances {
                        let code = b.get("asset_code").and_then(|v| v.as_str()).unwrap_or("");
                        let issuer = b.get("asset_issuer").and_then(|v| v.as_str()).unwrap_or("");
                        
                        if code == self.config.asset_code && issuer == self.config.asset_issuer {
                            let balance_str = b.get("balance").and_then(|v| v.as_str()).unwrap_or("0");
                            let balance = BigDecimal::from_str(balance_str).unwrap_or_else(|_| BigDecimal::from(0));
                            
                            // Calculate percentage
                            // percentage = (balance / circulating_supply) * 100
                            let percentage = (&balance * &BigDecimal::from(100)) / &circulating_supply;
                            let percentage_f64 = percentage.to_string().parse::<f64>().unwrap_or(0.0);
                            
                            if percentage_f64 >= self.config.whale_threshold_percent {
                                whale_records.push((address.to_string(), balance, percentage_f64));
                            }
                        }
                    }
                }
            }
        }

        // 4. Persistence
        let mut tx = self.pool.begin().await?;
        
        let snapshot_id = sqlx::query_scalar::<_, uuid::Uuid>(
            "INSERT INTO cngn_supply_snapshots 
             (total_issued, total_burned, circulating_supply, authorized_limit, num_holders, metadata) 
             VALUES ($1, $2, $3, $4, $5, $6) 
             RETURNING id"
        )
        .bind(&circulating_supply) // Use circulating as total for now if not crawling
        .bind(&BigDecimal::from(0))
        .bind(&circulating_supply)
        .bind(&self.config.authorized_limit)
        .bind(num_accounts)
        .bind(serde_json::to_value(&stats)?)
        .fetch_one(&mut *tx)
        .await?;

        for (address, balance, percentage) in whale_records {
            sqlx::query(
                "INSERT INTO cngn_whales (snapshot_id, wallet_address, balance, supply_percentage) 
                 VALUES ($1, $2, $3, $4)"
            )
            .bind(snapshot_id)
            .bind(address)
            .bind(balance)
            .bind(percentage)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;

        // 5. Supply Cap Alert
        if let Some(limit) = &self.config.authorized_limit {
            if limit > &BigDecimal::from(0) {
                let usage_ratio = &circulating_supply / limit;
                let usage_percent = usage_ratio.to_string().parse::<f64>().unwrap_or(0.0) * 100.0;
                
                if usage_percent >= 90.0 {
                    warn!(
                        circulating = %circulating_supply,
                        limit = %limit,
                        usage = %format!("{:.2}%", usage_percent),
                        "cNGN circulating supply is reaching authorized limit!"
                    );
                    
                    self.notification_service.send_system_alert(
                        "TREASURY_ALERT_SUPPLY_CAP",
                        &format!(
                            "cNGN supply is at {:.2}% of limit. Current: {} cNGN, Limit: {} cNGN",
                            usage_percent, circulating_supply, limit
                        )
                    ).await;
                }
            }
        }

        info!(
            circulating = %circulating_supply,
            holders = num_accounts,
            "supply snapshot captured successfully"
        );

        Ok(())
    }
}
