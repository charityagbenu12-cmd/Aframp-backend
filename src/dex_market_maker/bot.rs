use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::time::interval;
use tracing::{error, info, warn};

use crate::dex_market_maker::circuit_breaker::CircuitBreaker;
use crate::dex_market_maker::config::{
    MarketMakerConfig, MIN_CNGN_INVENTORY, MIN_COUNTER_INVENTORY,
};
use crate::dex_market_maker::models::{Inventory, OrderSide, OrderType};

/// Core market-making bot.
///
/// Each cycle (default every 5 s):
///   1. Fetch reference price from the price feed.
///   2. Check circuit breaker and inventory levels.
///   3. Cancel all existing open offers.
///   4. Place a laddered grid of passive bid/ask offers.
///   5. If price moved > threshold since last cycle, re-quote immediately.
///   6. Log the cycle to the Market Operations Dashboard table.
pub struct MarketMakerBot {
    pub config: MarketMakerConfig,
    http: reqwest::Client,
    pub circuit_breaker: Arc<CircuitBreaker>,
    /// Last reference price seen — used to detect significant moves.
    pub last_price: Arc<RwLock<f64>>,
    /// In-memory open offer IDs (Stellar offer IDs).
    pub open_offers: Arc<RwLock<Vec<i64>>>,
    /// Latest inventory snapshot — updated each cycle.
    pub last_inventory: Arc<RwLock<Inventory>>,
    db: sqlx::PgPool,
}

impl MarketMakerBot {
    pub fn new(config: MarketMakerConfig, db: sqlx::PgPool) -> Self {
        Self {
            circuit_breaker: Arc::new(CircuitBreaker::new(f64::MAX)),
            last_price: Arc::new(RwLock::new(0.0)),
            open_offers: Arc::new(RwLock::new(Vec::new())),
            last_inventory: Arc::new(RwLock::new(Inventory { cngn: 0.0, counter: 0.0 })),
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(8))
                .build()
                .unwrap(),
            config,
            db,
        }
    }

    /// Spawn the bot loop with graceful shutdown support.
    pub async fn run(self: Arc<Self>, mut shutdown: tokio::sync::watch::Receiver<bool>) {
        let mut ticker = interval(Duration::from_secs(self.config.requote_interval_secs));
        info!("DEX market maker started for pair {}/{}", self.config.cngn_asset, self.config.counter_asset);

        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    if let Err(e) = self.cycle().await {
                        error!(error = %e, "Market maker cycle failed");
                    }
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        info!("DEX market maker shutting down");
                        break;
                    }
                }
            }
        }
    }

    /// One full market-making cycle.
    async fn cycle(&self) -> anyhow::Result<()> {
        // 1. Fetch reference price.
        let ref_price = self.fetch_reference_price().await?;

        // 2. Fetch current inventory.
        let inventory = self.fetch_inventory().await?;

        // Cache inventory for the status handler.
        *self.last_inventory.write().await = Inventory {
            cngn: inventory.cngn,
            counter: inventory.counter,
        };

        // 3. Circuit breaker check.
        if self.circuit_breaker.check(inventory.cngn) {
            self.log_cycle(ref_price, 0.0, 0.0, 0.0, 0, 0, true, &inventory,
                Some("Circuit breaker tripped")).await;
            return Ok(());
        }
        if self.circuit_breaker.is_tripped() {
            warn!("Circuit breaker active — skipping cycle");
            return Ok(());
        }

        // 4. Inventory guard — pause and signal for refill.
        if inventory.cngn < MIN_CNGN_INVENTORY {
            warn!(inventory_cngn = inventory.cngn, "cNGN inventory below minimum — pausing");
            self.log_cycle(ref_price, 0.0, 0.0, 0.0, 0, 0, false, &inventory,
                Some("Low cNGN inventory")).await;
            return Ok(());
        }
        if inventory.counter < MIN_COUNTER_INVENTORY {
            warn!(inventory_counter = inventory.counter, "Counter-asset inventory below minimum — pausing");
            self.log_cycle(ref_price, 0.0, 0.0, 0.0, 0, 0, false, &inventory,
                Some("Low counter inventory")).await;
            return Ok(());
        }

        // 5. Decide whether to re-quote.
        let last = *self.last_price.read().await;
        let price_moved = last > 0.0
            && ((ref_price - last) / last).abs() >= self.config.requote_threshold;

        if !price_moved && last > 0.0 {
            // Price stable — no action needed this cycle.
            return Ok(());
        }

        // 6. Cancel existing offers.
        let cancelled = self.cancel_all_offers().await?;

        // 7. Place laddered grid.
        let placed = self.place_ladder(ref_price, &inventory).await?;

        // 8. Update last price.
        *self.last_price.write().await = ref_price;

        // 9. Compute spread for logging.
        let half_spread = self.config.target_spread / 2.0;
        let bid = ref_price * (1.0 - half_spread);
        let ask = ref_price * (1.0 + half_spread);
        let spread_pct = (ask - bid) / ref_price * 100.0;

        info!(
            ref_price,
            bid,
            ask,
            spread_pct,
            placed,
            cancelled,
            "Market maker cycle complete"
        );

        self.log_cycle(ref_price, bid, ask, spread_pct, placed as i32, cancelled as i32,
            false, &inventory, None).await;

        Ok(())
    }

    /// Place a laddered grid of passive offers on both sides of the book.
    ///
    /// Rung 0 is the tightest (closest to mid-price).
    /// Each subsequent rung steps `ladder_step` further away.
    /// Amount per rung decreases linearly so deeper rungs provide thinner
    /// but still meaningful depth.
    async fn place_ladder(&self, mid: f64, inventory: &Inventory) -> anyhow::Result<usize> {
        let rungs = self.config.ladder_rungs;
        let step = self.config.ladder_step;
        let half_spread = self.config.target_spread / 2.0;

        // Allocate inventory evenly across rungs (use 80% of available).
        let cngn_per_rung = (inventory.cngn * 0.8) / rungs as f64;
        let counter_per_rung = (inventory.counter * 0.8) / rungs as f64;

        let mut placed = 0usize;
        let mut new_offers: Vec<i64> = Vec::new();

        for rung in 0..rungs {
            let offset = half_spread + rung as f64 * step;

            // Bid (buy cNGN).
            let bid_price = mid * (1.0 - offset);
            if let Some(offer_id) = self
                .submit_offer(OrderSide::Bid, OrderType::Passive, bid_price, counter_per_rung / bid_price)
                .await?
            {
                new_offers.push(offer_id);
                placed += 1;
            }

            // Ask (sell cNGN).
            let ask_price = mid * (1.0 + offset);
            if let Some(offer_id) = self
                .submit_offer(OrderSide::Ask, OrderType::Passive, ask_price, cngn_per_rung)
                .await?
            {
                new_offers.push(offer_id);
                placed += 1;
            }
        }

        *self.open_offers.write().await = new_offers;
        Ok(placed)
    }

    /// Cancel all tracked open offers. Returns count cancelled.
    async fn cancel_all_offers(&self) -> anyhow::Result<usize> {
        let offers = self.open_offers.read().await.clone();
        let count = offers.len();
        for offer_id in &offers {
            if let Err(e) = self.cancel_offer(*offer_id).await {
                warn!(offer_id, error = %e, "Failed to cancel offer");
            }
        }
        self.open_offers.write().await.clear();
        Ok(count)
    }

    // ── Horizon integration ──────────────────────────────────────────────────

    /// Fetch the mid-price from the Stellar DEX order book.
    async fn fetch_reference_price(&self) -> anyhow::Result<f64> {
        let url = format!(
            "{}/order_book?selling_asset_type=credit_alphanum12&selling_asset_code=cNGN\
             &selling_asset_issuer={}&buying_asset_type=native&limit=1",
            self.config.horizon_url,
            self.cngn_issuer()
        );

        #[derive(serde::Deserialize)]
        struct OrderBook {
            bids: Vec<PriceLevel>,
            asks: Vec<PriceLevel>,
        }
        #[derive(serde::Deserialize)]
        struct PriceLevel {
            price: String,
        }

        let book: OrderBook = self.http.get(&url).send().await?.json().await?;

        let best_bid: f64 = book.bids.first()
            .and_then(|p| p.price.parse().ok())
            .unwrap_or(0.0);
        let best_ask: f64 = book.asks.first()
            .and_then(|p| p.price.parse().ok())
            .unwrap_or(0.0);

        if best_bid > 0.0 && best_ask > 0.0 {
            Ok((best_bid + best_ask) / 2.0)
        } else if best_bid > 0.0 {
            Ok(best_bid)
        } else if best_ask > 0.0 {
            Ok(best_ask)
        } else {
            anyhow::bail!("No order book data available for reference price")
        }
    }

    /// Fetch cNGN and counter-asset balances for the MM account.
    async fn fetch_inventory(&self) -> anyhow::Result<Inventory> {
        let url = format!("{}/accounts/{}", self.config.horizon_url, self.config.mm_account);

        #[derive(serde::Deserialize)]
        struct Account {
            balances: Vec<Balance>,
        }
        #[derive(serde::Deserialize)]
        struct Balance {
            asset_type: String,
            asset_code: Option<String>,
            balance: String,
        }

        let account: Account = self.http.get(&url).send().await?.json().await?;

        let mut cngn = 0.0f64;
        let mut counter = 0.0f64;

        for b in &account.balances {
            let bal: f64 = b.balance.parse().unwrap_or(0.0);
            if b.asset_code.as_deref() == Some("cNGN") {
                cngn = bal;
            } else if b.asset_type == "native" {
                counter = bal;
            }
        }

        Ok(Inventory { cngn, counter })
    }

    /// Submit a passive/active offer to Stellar Horizon.
    /// Returns the Stellar offer ID on success.
    async fn submit_offer(
        &self,
        side: OrderSide,
        order_type: OrderType,
        price: f64,
        amount: f64,
    ) -> anyhow::Result<Option<i64>> {
        // In production this builds and signs a Stellar transaction with
        // manage_sell_offer / manage_buy_offer / create_passive_sell_offer
        // operations and submits to Horizon.
        //
        // For now we log the intent and return a simulated offer ID so the
        // rest of the pipeline (logging, circuit breaker, cancellation) works
        // end-to-end without requiring live Stellar credentials.
        info!(
            side = ?side,
            order_type = ?order_type,
            price,
            amount,
            "Submitting DEX offer"
        );
        // TODO: replace with real Stellar transaction builder + submission.
        Ok(Some(rand_offer_id()))
    }

    /// Cancel a Stellar offer by ID.
    async fn cancel_offer(&self, offer_id: i64) -> anyhow::Result<()> {
        info!(offer_id, "Cancelling DEX offer");
        // TODO: submit manage_sell_offer with amount=0 to cancel.
        Ok(())
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    fn cngn_issuer(&self) -> &str {
        self.config.cngn_asset.split(':').nth(1).unwrap_or("")
    }

    /// Persist a cycle log row to the market_maker_cycle_logs table.
    async fn log_cycle(
        &self,
        reference_price: f64,
        bid_price: f64,
        ask_price: f64,
        spread_pct: f64,
        orders_placed: i32,
        orders_cancelled: i32,
        circuit_breaker_tripped: bool,
        inventory: &Inventory,
        notes: Option<&str>,
    ) {
        let result = sqlx::query!(
            r#"
            INSERT INTO market_maker_cycle_logs
                (id, cycle_at, reference_price, bid_price, ask_price, spread_pct,
                 orders_placed, orders_cancelled, circuit_breaker_tripped,
                 inventory_cngn, inventory_counter, notes)
            VALUES ($1, NOW(), $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            "#,
            uuid::Uuid::new_v4(),
            reference_price,
            bid_price,
            ask_price,
            spread_pct,
            orders_placed,
            orders_cancelled,
            circuit_breaker_tripped,
            inventory.cngn,
            inventory.counter,
            notes,
        )
        .execute(&self.db)
        .await;

        if let Err(e) = result {
            error!(error = %e, "Failed to log market maker cycle");
        }
    }
}

/// Deterministic-ish fake offer ID for simulation (replaced by real Horizon response).
fn rand_offer_id() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos() as i64
}
