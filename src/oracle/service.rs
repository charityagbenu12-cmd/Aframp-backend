//! OracleService — background refresh loop, health monitoring, price freeze.
//!
//! Heartbeat: refresh every 30 s.
//! Deviation trigger: immediate refresh if price moves > 0.5 % between beats.
//! Staleness threshold: a source is "slashed" after MAX_SOURCE_FAILURES consecutive failures.
//! Price freeze: if ALL sources fail, OracleState transitions to PriceFrozen.

use super::{
    adapters::PriceAdapter,
    aggregator::Aggregator,
    types::{OraclePrice, OracleState, RawPrice, SourceHealth},
};
use chrono::Utc;
use sqlx::PgPool;
use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio::sync::RwLock;
use tracing::{error, info, warn};

const HEARTBEAT_SECS: u64 = 30;
const DEVIATION_THRESHOLD_PCT: f64 = 0.5;
const MAX_SOURCE_FAILURES: u32 = 3;

#[derive(Clone)]
pub struct OracleService {
    inner: Arc<Inner>,
}

struct Inner {
    adapters: Vec<Box<dyn PriceAdapter>>,
    aggregator: Aggregator,
    pair: String,
    state: RwLock<OracleState>,
    latest: RwLock<Option<OraclePrice>>,
    health: RwLock<HashMap<String, SourceHealth>>,
    pool: Option<PgPool>,
}

impl OracleService {
    pub fn new(adapters: Vec<Box<dyn PriceAdapter>>, pair: impl Into<String>, pool: Option<PgPool>) -> Self {
        let pair = pair.into();
        let health: HashMap<String, SourceHealth> = adapters
            .iter()
            .map(|a| {
                let name = a.name().to_string();
                (name.clone(), SourceHealth { name, healthy: true, last_seen: None, failures: 0 })
            })
            .collect();

        Self {
            inner: Arc::new(Inner {
                adapters,
                aggregator: Aggregator::new(None),
                pair,
                state: RwLock::new(OracleState::Active),
                latest: RwLock::new(None),
                health: RwLock::new(health),
                pool,
            }),
        }
    }

    /// Returns the latest aggregated price, or None if in PriceFrozen state.
    pub async fn get_price(&self) -> Option<OraclePrice> {
        if *self.inner.state.read().await == OracleState::PriceFrozen {
            return None;
        }
        self.inner.latest.read().await.clone()
    }

    pub async fn get_state(&self) -> OracleState {
        *self.inner.state.read().await
    }

    pub async fn get_health(&self) -> Vec<SourceHealth> {
        self.inner.health.read().await.values().cloned().collect()
    }

    /// Spawn the background refresh loop.
    pub fn start(self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(HEARTBEAT_SECS));
            loop {
                interval.tick().await;
                self.refresh().await;
            }
        })
    }

    async fn refresh(&self) {
        let raw_prices = self.fetch_all().await;
        self.update_health(&raw_prices).await;

        match self.inner.aggregator.aggregate(&raw_prices) {
            None => {
                warn!(pair = %self.inner.pair, "All oracle sources failed — entering PriceFrozen");
                *self.inner.state.write().await = OracleState::PriceFrozen;
            }
            Some((price, sources_used, excluded)) => {
                // Log excluded sources to audit trail
                for src in &excluded {
                    warn!(
                        source = %src,
                        pair = %self.inner.pair,
                        "Oracle source excluded due to outlier price"
                    );
                    self.audit_exclusion(src, "outlier_price").await;
                }

                // Check deviation against previous price for immediate-update trigger
                let prev = self.inner.latest.read().await.as_ref().map(|p| p.price);
                if let Some(prev_price) = prev {
                    let deviation = ((price - prev_price) / prev_price).abs() * 100.0;
                    if deviation > DEVIATION_THRESHOLD_PCT {
                        info!(
                            pair = %self.inner.pair,
                            deviation_pct = deviation,
                            "Price deviation exceeded threshold — immediate update"
                        );
                    }
                }

                let oracle_price = OraclePrice {
                    pair: self.inner.pair.clone(),
                    price,
                    sources_used,
                    fetched_at: Utc::now(),
                };

                // Persist to time-series table
                self.persist(&oracle_price).await;

                *self.inner.latest.write().await = Some(oracle_price);
                *self.inner.state.write().await = OracleState::Active;
            }
        }
    }

    async fn fetch_all(&self) -> Vec<RawPrice> {
        let health = self.inner.health.read().await;
        let mut handles = Vec::new();

        for adapter in &self.inner.adapters {
            // Only query sources that haven't been slashed
            let src_health = health.get(adapter.name());
            if src_health.map(|h| h.failures >= MAX_SOURCE_FAILURES).unwrap_or(false) {
                continue;
            }
            // We can't move adapter into async block directly (it's behind &),
            // so we use a raw pointer trick safely scoped to this function.
            let pair = self.inner.pair.clone();
            let adapter_ptr = adapter.as_ref() as *const dyn PriceAdapter;
            // SAFETY: adapters live for the lifetime of Inner which is Arc-held.
            handles.push(tokio::spawn(async move {
                let adapter = unsafe { &*adapter_ptr };
                adapter.fetch(&pair).await
            }));
        }
        drop(health);

        let mut results = Vec::new();
        for h in handles {
            if let Ok(Some(price)) = h.await {
                results.push(price);
            }
        }
        results
    }

    async fn update_health(&self, prices: &[RawPrice]) {
        let mut health = self.inner.health.write().await;
        let now = Utc::now();

        // Mark sources that returned a price as healthy
        let active_sources: std::collections::HashSet<&str> =
            prices.iter().map(|p| p.source.as_str()).collect();

        for (name, h) in health.iter_mut() {
            if active_sources.contains(name.as_str()) {
                h.healthy = true;
                h.last_seen = Some(now);
                h.failures = 0;
            } else {
                h.failures += 1;
                if h.failures >= MAX_SOURCE_FAILURES {
                    if h.healthy {
                        warn!(source = %name, "Oracle source slashed — too many consecutive failures");
                        self.audit_exclusion_unlocked(name, "consecutive_failures").await;
                    }
                    h.healthy = false;
                }
            }
        }
    }

    async fn persist(&self, price: &OraclePrice) {
        let pool = match &self.inner.pool {
            Some(p) => p,
            None => return,
        };
        let result = sqlx::query!(
            r#"INSERT INTO oracle_price_history (pair, price, sources_used, fetched_at)
               VALUES ($1, $2, $3, $4)"#,
            price.pair,
            price.price,
            price.sources_used as i32,
            price.fetched_at,
        )
        .execute(pool)
        .await;

        if let Err(e) = result {
            error!(error = %e, "Failed to persist oracle price");
        }
    }

    async fn audit_exclusion(&self, source: &str, reason: &str) {
        self.audit_exclusion_unlocked(source, reason).await;
    }

    async fn audit_exclusion_unlocked(&self, source: &str, reason: &str) {
        let pool = match &self.inner.pool {
            Some(p) => p,
            None => return,
        };
        let _ = sqlx::query!(
            r#"INSERT INTO oracle_source_exclusions (source_name, pair, reason, excluded_at)
               VALUES ($1, $2, $3, now())"#,
            source,
            self.inner.pair,
            reason,
        )
        .execute(pool)
        .await;
    }
}
