//! Multi-level cache manager.
//!
//! Promotion rules:
//! - L1 (moka, in-process): fee structures, currency configs, provider lists.
//!   Low volatility, high read frequency, process-local.
//! - L2 (Redis, distributed): exchange rates, wallet balances, quotes, history cursors.
//!   Shared across instances, moderate volatility.
//!
//! On a cache miss at L1, the manager checks L2 before hitting the database.
//! On a miss at both levels, a single-flight rebuild is triggered so only one
//! request rebuilds the entry while concurrent requests wait.
//!
//! Probabilistic early expiry (via moka's time_to_idle) prevents simultaneous
//! expiry spikes across multiple instances.

use std::future::Future;
use std::sync::Arc;
use serde::{de::DeserializeOwned, Serialize};
use tracing::{debug, info};

use crate::cache::l1::{L1Cache, L1Category};
use crate::cache::cache::{Cache as CacheTrait, RedisCache};
use crate::cache::metrics::{CacheSizeMetrics, L1Metrics, L2Metrics};
use crate::cache::single_flight::SingleFlight;

/// The unified multi-level cache handle. Clone-cheap (all fields are Arc).
#[derive(Clone)]
pub struct MultiLevelCache {
    pub l1: L1Cache,
    pub l2: RedisCache,
    pub l1_metrics: Arc<L1Metrics>,
    pub l2_metrics: Arc<L2Metrics>,
    pub size_metrics: Arc<CacheSizeMetrics>,
    /// Per-key single-flight guard (keyed by cache key string).
    sf: Arc<SingleFlight<Vec<u8>>>,
}

impl MultiLevelCache {
    pub fn new(
        l1: L1Cache,
        l2: RedisCache,
        l1_metrics: Arc<L1Metrics>,
        l2_metrics: Arc<L2Metrics>,
        size_metrics: Arc<CacheSizeMetrics>,
    ) -> Self {
        Self {
            l1,
            l2,
            l1_metrics,
            l2_metrics,
            size_metrics,
            sf: SingleFlight::new(),
        }
    }

    // -------------------------------------------------------------------------
    // L1-only helpers (fee structures, currency configs, provider lists)
    // -------------------------------------------------------------------------

    /// Get from L1 only (for low-volatility, process-local data).
    pub async fn l1_get<T: DeserializeOwned>(&self, category: L1Category, key: &str) -> Option<T> {
        let shard = self.l1_shard(category);
        shard.get(key).await
    }

    /// Insert into L1 only.
    pub async fn l1_insert<T: Serialize>(&self, category: L1Category, key: String, value: &T) {
        let shard = self.l1_shard(category);
        shard.insert(key, value).await;
    }

    /// Invalidate a key from L1 only.
    pub async fn l1_invalidate(&self, category: L1Category, key: &str) {
        let shard = self.l1_shard(category);
        shard.invalidate(key).await;
    }

    /// Invalidate all entries in an L1 category.
    pub async fn l1_invalidate_all(&self, category: L1Category) {
        let shard = self.l1_shard(category);
        shard.invalidate_all().await;
    }

    // -------------------------------------------------------------------------
    // L2-only helpers (exchange rates, wallet balances, quotes)
    // -------------------------------------------------------------------------

    /// Get from L2 (Redis) only.
    pub async fn l2_get<T: Serialize + DeserializeOwned + Send + Sync + 'static>(
        &self,
        category: &str,
        key: &str,
    ) -> Option<T> {
        match CacheTrait::<T>::get(&self.l2, key).await {
            Ok(Some(v)) => {
                self.l2_metrics.record_hit(category);
                debug!(category, key, "L2 cache hit");
                Some(v)
            }
            Ok(None) => {
                self.l2_metrics.record_miss(category);
                debug!(category, key, "L2 cache miss");
                None
            }
            Err(e) => {
                debug!(category, key, error = %e, "L2 cache error (degraded)");
                None
            }
        }
    }

    /// Set in L2 (Redis) only.
    pub async fn l2_set<T: Serialize + DeserializeOwned + Send + Sync + 'static>(
        &self,
        key: &str,
        value: &T,
        ttl: Option<std::time::Duration>,
    ) {
        if let Err(e) = self.l2.set(key, value, ttl).await {
            debug!(key, error = %e, "L2 cache set error (degraded)");
        }
    }

    /// Delete from L2 (Redis) only.
    pub async fn l2_invalidate<T>(&self, key: &str)
    where
        T: Serialize + DeserializeOwned + Send + Sync + 'static,
    {
        if let Err(e) = CacheTrait::<T>::delete(&self.l2, key).await {
            debug!(key, error = %e, "L2 cache delete error (degraded)");
        } else {
            info!(key, "L2 cache invalidated");
        }
    }

    /// Delete all L2 keys matching a pattern.
    pub async fn l2_invalidate_pattern<T>(&self, pattern: &str)
    where
        T: Serialize + DeserializeOwned + Send + Sync + 'static,
    {
        match CacheTrait::<T>::delete_pattern(&self.l2, pattern).await {
            Ok(n) => info!(pattern, deleted = n, "L2 cache pattern invalidated"),
            Err(e) => debug!(pattern, error = %e, "L2 pattern delete error (degraded)"),
        }
    }

    // -------------------------------------------------------------------------
    // Combined invalidation (admin-triggered config updates)
    // -------------------------------------------------------------------------

    /// Invalidate a key from both L1 and L2 simultaneously.
    pub async fn invalidate_both(&self, category: L1Category, l1_key: &str, l2_key: &str) {
        tokio::join!(
            self.l1_invalidate(category, l1_key),
            self.l2_invalidate::<serde_json::Value>(l2_key),
        );
        info!(l1_key, l2_key, "Both cache levels invalidated");
    }

    // -------------------------------------------------------------------------
    // Single-flight get-or-rebuild (stampede protection)
    // -------------------------------------------------------------------------

    /// Get from L2 with single-flight rebuild on miss.
    ///
    /// `rebuild` is called at most once per key regardless of concurrent callers.
    /// All concurrent waiters receive the same rebuilt value.
    pub async fn l2_get_or_rebuild<T, F, Fut>(
        &self,
        category: &str,
        key: &str,
        ttl: std::time::Duration,
        rebuild: F,
    ) -> Result<T, String>
    where
        T: Serialize + DeserializeOwned + Send + Sync + Clone + 'static,
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<T, String>>,
    {
        // Fast path: L2 hit
        if let Some(v) = self.l2_get::<T>(category, key).await {
            return Ok(v);
        }

        // Slow path: single-flight rebuild
        let l2 = self.l2.clone();
        let key_owned = key.to_string();
        let category_owned = category.to_string();
        let l2_metrics = self.l2_metrics.clone();

        let result_bytes = self
            .sf
            .get_or_rebuild(key, || async move {
                let value = rebuild().await?;
                let bytes = serde_json::to_vec(&value)
                    .map_err(|e| e.to_string())?;
                // Populate L2 after rebuild
                if let Err(e) = l2.set(&key_owned, &value, Some(ttl)).await {
                    debug!(key = key_owned, error = %e, "Failed to populate L2 after rebuild");
                }
                l2_metrics.record_miss(&category_owned);
                Ok(bytes)
            })
            .await?;

        serde_json::from_slice(&result_bytes).map_err(|e| e.to_string())
    }

    // -------------------------------------------------------------------------
    // Size metric updates (call periodically or after warming)
    // -------------------------------------------------------------------------

    pub fn update_size_metrics(&self) {
        self.size_metrics.set_l1_size(
            "fee_structures",
            self.l1.fee_structures.entry_count(),
        );
        self.size_metrics.set_l1_size(
            "currency_configs",
            self.l1.currency_configs.entry_count(),
        );
        self.size_metrics.set_l1_size(
            "provider_lists",
            self.l1.provider_lists.entry_count(),
        );
    }

    // -------------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------------

    fn l1_shard(&self, category: L1Category) -> &crate::cache::l1::L1Shard {
        match category {
            L1Category::FeeStructures => &self.l1.fee_structures,
            L1Category::CurrencyConfigs => &self.l1.currency_configs,
            L1Category::ProviderLists => &self.l1.provider_lists,
        }
    }
}
