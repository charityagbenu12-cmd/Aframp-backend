/// Background worker — polls the Stellar DEX order book every 60 seconds.
use crate::liquidity_monitor::engine::LiquidityEngine;
use crate::services::exchange_rate::ExchangeRateService;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use tracing::{error, info};

pub struct LiquidityMonitorWorker {
    engine: Arc<LiquidityEngine>,
    exchange_rate: Arc<ExchangeRateService>,
}

impl LiquidityMonitorWorker {
    pub fn new(engine: Arc<LiquidityEngine>, exchange_rate: Arc<ExchangeRateService>) -> Self {
        Self { engine, exchange_rate }
    }

    pub async fn run(self, mut shutdown: watch::Receiver<bool>) {
        info!("Liquidity monitor worker started (60s interval)");
        let mut interval = tokio::time::interval(Duration::from_secs(60));

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let oracle_price = self.fetch_oracle_price().await;
                    match self.engine.run_cycle(oracle_price).await {
                        Ok(snap) => info!(
                            slippage_pct = snap.slippage_pct,
                            alert_level = snap.alert_level.as_str(),
                            "Liquidity cycle complete"
                        ),
                        Err(e) => error!(error = %e, "Liquidity monitor cycle failed"),
                    }
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        info!("Liquidity monitor worker shutting down");
                        break;
                    }
                }
            }
        }
    }

    async fn fetch_oracle_price(&self) -> f64 {
        // Fetch NGN/cNGN oracle price; fall back to 1.0 (perfect peg) on error.
        self.exchange_rate
            .get_rate("NGN", "cNGN")
            .await
            .ok()
            .and_then(|rate| rate.to_string().parse().ok())
            .unwrap_or(1.0)
    }
}
