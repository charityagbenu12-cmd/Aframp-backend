//! Level 1 — in-process memory cache using moka
//!
//! Stores high-frequency, low-volatility data (currency configs, fee structures,
//! supported provider lists) with per-category TTL and configurable max capacity.
//!
//! TTL justifications:
//! - fee_structures: 10 min — rarely change; admin invalidation covers updates
//! - currency_configs: 15 min — essentially static; refreshed on admin update
//! - provider_lists: 15 min — provider availability changes infrequently
//!
//! All entries are also subject to event-driven invalidation via `invalidate`.

use moka::future::Cache;
use serde::{de::DeserializeOwned, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info};

use crate::cache::metrics::L1Metrics;

/// Category labels used for metrics and logging
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum L1Category {
    FeeStructures,
    CurrencyConfigs,
    ProviderLists,
}

impl L1Category {
    pub fn as_str(self) -> &'static str {
        match self {
            L1Category::FeeStructures => "fee_structures",
            L1Category::CurrencyConfigs => "currency_configs",
            L1Category::ProviderLists => "provider_lists",
        }
    }

    /// TTL for each category — chosen to balance freshness vs. DB load.
    pub fn ttl(self) -> Duration {
        match self {
            // Fee structures: 10 min. Admin-triggered invalidation handles updates.
            L1Category::FeeStructures => Duration::from_secs(600),
            // Currency configs: 15 min. Near-static; invalidated on admin update.
            L1Category::CurrencyConfigs => Duration::from_secs(900),
            // Provider lists: 15 min. Provider availability changes infrequently.
            L1Category::ProviderLists => Duration::from_secs(900),
        }
    }

    /// Max entries per category — keeps memory bounded.
    pub fn max_capacity(self) -> u64 {
        match self {
            L1Category::FeeStructures => 256,
            L1Category::CurrencyConfigs => 128,
            L1Category::ProviderLists => 64,
        }
    }
}

/// A single typed in-process cache shard for one category.
#[derive(Clone)]
pub struct L1Shard {
    inner: Cache<String, Arc<Vec<u8>>>,
    category: L1Category,
    metrics: Arc<L1Metrics>,
}

impl L1Shard {
    pub fn new(category: L1Category, metrics: Arc<L1Metrics>) -> Self {
        let inner = Cache::builder()
            .max_capacity(category.max_capacity())
            .time_to_live(category.ttl())
            // Probabilistic early expiry: start refreshing at 90% of TTL to
            // prevent simultaneous expiry spikes across instances.
            .time_to_idle(Duration::from_secs(
                (category.ttl().as_secs() as f64 * 0.9) as u64,
            ))
            .build();

        Self {
            inner,
            category,
            metrics,
        }
    }

    /// Get a value, recording hit/miss metrics.
    pub async fn get<T: DeserializeOwned>(&self, key: &str) -> Option<T> {
        match self.inner.get(key).await {
            Some(bytes) => {
                self.metrics.record_hit(self.category.as_str());
                debug!(category = self.category.as_str(), key, "L1 cache hit");
                serde_json::from_slice(&bytes).ok()
            }
            None => {
                self.metrics.record_miss(self.category.as_str());
                debug!(category = self.category.as_str(), key, "L1 cache miss");
                None
            }
        }
    }

    /// Insert a value, serialising to JSON bytes.
    pub async fn insert<T: Serialize>(&self, key: String, value: &T) {
        if let Ok(bytes) = serde_json::to_vec(value) {
            self.inner.insert(key.clone(), Arc::new(bytes)).await;
            self.metrics.record_insert(self.category.as_str());
            debug!(category = self.category.as_str(), key, "L1 cache insert");
        }
    }

    /// Invalidate a specific key.
    pub async fn invalidate(&self, key: &str) {
        self.inner.invalidate(key).await;
        info!(
            category = self.category.as_str(),
            key, "L1 cache invalidated"
        );
    }

    /// Invalidate all entries in this shard.
    pub async fn invalidate_all(&self) {
        self.inner.invalidate_all();
        info!(
            category = self.category.as_str(),
            "L1 cache shard fully invalidated"
        );
    }

    /// Current number of entries (approximate).
    pub fn entry_count(&self) -> u64 {
        self.inner.entry_count()
    }
}

/// The full L1 cache, composed of per-category shards.
#[derive(Clone)]
pub struct L1Cache {
    pub fee_structures: L1Shard,
    pub currency_configs: L1Shard,
    pub provider_lists: L1Shard,
}

impl L1Cache {
    pub fn new(metrics: Arc<L1Metrics>) -> Self {
        Self {
            fee_structures: L1Shard::new(L1Category::FeeStructures, metrics.clone()),
            currency_configs: L1Shard::new(L1Category::CurrencyConfigs, metrics.clone()),
            provider_lists: L1Shard::new(L1Category::ProviderLists, metrics),
        }
    }

    /// Invalidate a key across all shards (used when the category is unknown).
    pub async fn invalidate_key_all_shards(&self, key: &str) {
        self.fee_structures.invalidate(key).await;
        self.currency_configs.invalidate(key).await;
        self.provider_lists.invalidate(key).await;
    }
}
