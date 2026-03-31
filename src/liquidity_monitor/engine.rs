/// Slippage Calculation & Rebalancing Engine
///
/// Every 60 seconds:
///   1. Fetch the Stellar DEX order book for cNGN
///   2. Simulate a market buy of `probe_amount_cngn`
///   3. Compute slippage vs the oracle price
///   4. Classify as Healthy / Warning / Critical
///   5. If Critical → build a rebalancing vault transfer request (multi-sig)
///   6. Monitor Stellar AMM constant-product k for pool exhaustion
///   7. Alert via webhook within 30 s of detection
use crate::liquidity_monitor::types::{
    AlertLevel, DepthSnapshot, HorizonLiquidityPool, HorizonOrderBook, MarketDepthSummary,
    RebalanceTrigger, REBALANCE_COOLDOWN_SECS, SLIPPAGE_CRITICAL_PCT,
};
use chrono::Utc;
use reqwest::Client;
use sqlx::PgPool;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tracing::{error, info, warn};
use uuid::Uuid;

const POOL_EXHAUSTION_THRESHOLD: f64 = 0.10;

pub struct LiquidityEngine {
    db: PgPool,
    http: Client,
    horizon_url: String,
    cngn_asset: String,
    counter_asset: String,
    probe_amount: f64,
    alert_webhook: Option<String>,
    last_rebalance: Arc<Mutex<Option<Instant>>>,
    baseline_k: Arc<Mutex<Option<f64>>>,
}

impl LiquidityEngine {
    pub fn new(db: PgPool, horizon_url: String, cngn_asset: String, counter_asset: String) -> Self {
        let probe_amount = std::env::var("LIQUIDITY_PROBE_AMOUNT_CNGN")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(10_000_000.0);

        Self {
            db,
            http: Client::builder().timeout(Duration::from_secs(10)).build().unwrap(),
            horizon_url,
            cngn_asset,
            counter_asset,
            probe_amount,
            alert_webhook: std::env::var("LIQUIDITY_ALERT_WEBHOOK_URL").ok(),
            last_rebalance: Arc::new(Mutex::new(None)),
            baseline_k: Arc::new(Mutex::new(None)),
        }
    }

    /// Run one full monitoring cycle. Called every 60 seconds by the worker.
    pub async fn run_cycle(&self, oracle_price: f64) -> Result<DepthSnapshot, String> {
        let order_book = self.fetch_order_book().await?;
        let (execution_price, bid_depth, ask_depth) =
            self.simulate_market_buy(&order_book, oracle_price);

        let slippage_pct = if oracle_price > 0.0 {
            ((execution_price - oracle_price) / oracle_price * 100.0).abs()
        } else {
            0.0
        };

        let alert_level = AlertLevel::from_slippage(slippage_pct);
        let (amm_k, pool_exhaustion_risk) = self.check_amm_pool().await;

        let snapshot_id = Uuid::new_v4();
        let now = Utc::now();
        let rebalance_needed = alert_level == AlertLevel::Critical;

        sqlx::query!(
            r#"
            INSERT INTO liquidity_depth_snapshots
                (id, sampled_at, probe_amount_cngn, oracle_price, execution_price,
                 slippage_pct, alert_level, bid_depth_cngn, ask_depth_cngn,
                 amm_k_value, rebalance_triggered)
            VALUES ($1,$2,$3,$4,$5,$6,$7::liquidity_alert_level,$8,$9,$10,$11)
            "#,
            snapshot_id, now,
            self.probe_amount.to_string(),
            oracle_price.to_string(),
            execution_price.to_string(),
            slippage_pct,
            alert_level.as_str(),
            bid_depth.to_string(),
            ask_depth.to_string(),
            amm_k.map(|k| k.to_string()),
            rebalance_needed,
        )
        .execute(&self.db)
        .await
        .map_err(|e| format!("DB insert failed: {e}"))?;

        if alert_level != AlertLevel::Healthy || pool_exhaustion_risk {
            self.send_alert(alert_level, slippage_pct, bid_depth, ask_depth, pool_exhaustion_risk)
                .await;
        }

        if rebalance_needed {
            self.maybe_rebalance(snapshot_id, bid_depth, ask_depth).await;
        }

        Ok(DepthSnapshot {
            id: snapshot_id,
            sampled_at: now,
            probe_amount_cngn: self.probe_amount.to_string(),
            oracle_price: oracle_price.to_string(),
            execution_price: execution_price.to_string(),
            slippage_pct,
            alert_level,
            bid_depth_cngn: bid_depth.to_string(),
            ask_depth_cngn: ask_depth.to_string(),
            amm_k_value: amm_k.map(|k| k.to_string()),
            rebalance_triggered: rebalance_needed,
        })
    }

    async fn fetch_order_book(&self) -> Result<HorizonOrderBook, String> {
        let (selling_type, selling_code, selling_issuer) = parse_asset(&self.cngn_asset);
        let (buying_type, buying_code, buying_issuer) = parse_asset(&self.counter_asset);

        let mut url = format!(
            "{}/order_book?selling_asset_type={}&buying_asset_type={}&limit=200",
            self.horizon_url, selling_type, buying_type
        );
        if let Some(c) = selling_code   { url.push_str(&format!("&selling_asset_code={c}")); }
        if let Some(i) = selling_issuer { url.push_str(&format!("&selling_asset_issuer={i}")); }
        if let Some(c) = buying_code    { url.push_str(&format!("&buying_asset_code={c}")); }
        if let Some(i) = buying_issuer  { url.push_str(&format!("&buying_asset_issuer={i}")); }

        self.http.get(&url).send().await
            .map_err(|e| format!("Horizon request failed: {e}"))?
            .json::<HorizonOrderBook>().await
            .map_err(|e| format!("Order book parse failed: {e}"))
    }

    /// Walk the ask side to fill `probe_amount`. Returns (execution_price, bid_depth, ask_depth).
    fn simulate_market_buy(&self, book: &HorizonOrderBook, oracle_price: f64) -> (f64, f64, f64) {
        let bid_depth: f64 = book.bids.iter().filter_map(|o| o.amount.parse::<f64>().ok()).sum();
        let ask_depth: f64 = book.asks.iter().filter_map(|o| o.amount.parse::<f64>().ok()).sum();

        let mut remaining = self.probe_amount;
        let mut total_cost = 0.0_f64;

        for offer in &book.asks {
            if remaining <= 0.0 { break; }
            let amount: f64 = offer.amount.parse().unwrap_or(0.0);
            let price: f64  = offer.price.parse().unwrap_or(oracle_price);
            let fill = remaining.min(amount);
            total_cost += fill * price;
            remaining  -= fill;
        }

        // Remainder beyond order book depth — penalise at critical slippage rate.
        if remaining > 0.0 {
            total_cost += remaining * oracle_price * (1.0 + SLIPPAGE_CRITICAL_PCT / 100.0);
        }

        let execution_price = if self.probe_amount > 0.0 {
            total_cost / self.probe_amount
        } else {
            oracle_price
        };

        (execution_price, bid_depth, ask_depth)
    }

    /// Fetch Stellar AMM pool and compute k = x * y. Returns (k, exhaustion_risk).
    async fn check_amm_pool(&self) -> (Option<f64>, bool) {
        let pool_id = match std::env::var("CNGN_LIQUIDITY_POOL_ID") {
            Ok(id) => id,
            Err(_) => return (None, false),
        };

        let url = format!("{}/liquidity_pools/{}", self.horizon_url, pool_id);
        let pool: HorizonLiquidityPool = match self.http.get(&url).send().await {
            Ok(r) => match r.json().await { Ok(p) => p, Err(_) => return (None, false) },
            Err(_) => return (None, false),
        };

        if pool.reserves.len() < 2 { return (None, false); }

        let x: f64 = pool.reserves[0].amount.parse().unwrap_or(0.0);
        let y: f64 = pool.reserves[1].amount.parse().unwrap_or(0.0);
        let k = x * y;

        let mut baseline = self.baseline_k.lock().await;
        let exhaustion_risk = match *baseline {
            None => { *baseline = Some(k); false }
            Some(k0) => k0 > 0.0 && (k / k0) < POOL_EXHAUSTION_THRESHOLD,
        };

        (Some(k), exhaustion_risk)
    }

    /// Trigger a rebalancing event if not in cool-down (anti-oscillation).
    async fn maybe_rebalance(&self, snapshot_id: Uuid, bid_depth: f64, ask_depth: f64) {
        let mut last = self.last_rebalance.lock().await;
        if let Some(t) = *last {
            if t.elapsed().as_secs() < REBALANCE_COOLDOWN_SECS {
                info!(
                    remaining_secs = REBALANCE_COOLDOWN_SECS - t.elapsed().as_secs(),
                    "Rebalance suppressed — cool-down active"
                );
                return;
            }
        }
        *last = Some(Instant::now());
        drop(last);

        let trigger = if bid_depth < ask_depth {
            RebalanceTrigger::Deficit
        } else {
            RebalanceTrigger::Surplus
        };

        let event_id = Uuid::new_v4();
        if let Err(e) = sqlx::query!(
            r#"
            INSERT INTO liquidity_rebalance_events (id, trigger, amount_cngn, snapshot_id, created_at)
            VALUES ($1, $2::rebalance_trigger_type, $3, $4, NOW())
            "#,
            event_id,
            match trigger { RebalanceTrigger::Deficit => "deficit", RebalanceTrigger::Surplus => "surplus" },
            self.probe_amount.to_string(),
            snapshot_id,
        )
        .execute(&self.db)
        .await
        {
            error!(error = %e, "Failed to persist rebalance event");
            return;
        }

        warn!(
            event_id = %event_id,
            trigger = ?trigger,
            amount_cngn = self.probe_amount,
            "Rebalancing event triggered — vault transfer request queued for multi-sig"
        );
    }

    async fn send_alert(
        &self,
        level: AlertLevel,
        slippage_pct: f64,
        bid_depth: f64,
        ask_depth: f64,
        pool_exhaustion: bool,
    ) {
        let emoji = match level {
            AlertLevel::Warning  => "⚠️",
            AlertLevel::Critical => "🚨",
            AlertLevel::Healthy  => "ℹ️",
        };
        let text = format!(
            "{emoji} *cNGN Liquidity Alert* | level={} | slippage={:.3}% | bid={:.0} | ask={:.0}{}",
            level.as_str(), slippage_pct, bid_depth, ask_depth,
            if pool_exhaustion { " | ⚠️ AMM POOL EXHAUSTION RISK" } else { "" }
        );

        warn!(alert_level = level.as_str(), slippage_pct, "{}", text);

        if let Some(url) = &self.alert_webhook {
            let payload = serde_json::json!({ "text": text });
            let client = self.http.clone();
            let url = url.clone();
            tokio::spawn(async move {
                if let Err(e) = client.post(&url).json(&payload).send().await {
                    error!(error = %e, "Failed to send liquidity alert webhook");
                }
            });
        }
    }

    /// Latest depth summary for the Market Operations Dashboard.
    pub async fn latest_summary(&self) -> Result<MarketDepthSummary, String> {
        let row = sqlx::query!(
            r#"
            SELECT sampled_at, slippage_pct, alert_level AS "alert_level: AlertLevel",
                   bid_depth_cngn, ask_depth_cngn, oracle_price, execution_price, amm_k_value
            FROM liquidity_depth_snapshots ORDER BY sampled_at DESC LIMIT 1
            "#
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| format!("No snapshots yet: {e}"))?;

        let baseline_k = *self.baseline_k.lock().await;
        let pool_exhaustion_risk = match (baseline_k, row.amm_k_value.as_ref()) {
            (Some(k0), Some(k_str)) => {
                let k: f64 = k_str.parse().unwrap_or(0.0);
                k0 > 0.0 && (k / k0) < POOL_EXHAUSTION_THRESHOLD
            }
            _ => false,
        };

        Ok(MarketDepthSummary {
            sampled_at: row.sampled_at,
            slippage_pct: row.slippage_pct,
            alert_level: row.alert_level,
            bid_depth_cngn: row.bid_depth_cngn,
            ask_depth_cngn: row.ask_depth_cngn,
            oracle_price: row.oracle_price,
            execution_price: row.execution_price,
            amm_pool_exhaustion_risk: pool_exhaustion_risk,
        })
    }
}

fn parse_asset(asset: &str) -> (&str, Option<&str>, Option<&str>) {
    if asset == "native" {
        return ("native", None, None);
    }
    let mut parts = asset.splitn(2, ':');
    let code = parts.next().unwrap_or("");
    let issuer = parts.next();
    let asset_type = if code.len() <= 4 { "credit_alphanum4" } else { "credit_alphanum12" };
    (asset_type, Some(code), issuer)
}
