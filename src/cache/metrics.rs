//! Prometheus metrics for the multi-level cache.
//!
//! Exposes per-category hit/miss/eviction/size counters for both L1 and L2.
//! Alert threshold: if L2 hit rate drops below CACHE_HIT_RATE_ALERT_THRESHOLD
//! (default 0.5), a warning is logged — wire this to your alerting system.

use prometheus::{
    register_counter_vec, register_gauge_vec, register_int_counter_vec, CounterVec, GaugeVec,
    IntCounterVec, Registry,
};
use std::sync::Arc;
use tracing::warn;

/// Metrics for the Level 1 in-process cache.
pub struct L1Metrics {
    hits: IntCounterVec,
    misses: IntCounterVec,
    inserts: IntCounterVec,
}

impl L1Metrics {
    pub fn new(registry: &Registry) -> Arc<Self> {
        let hits = IntCounterVec::new(
            prometheus::opts!("cache_l1_hits_total", "L1 cache hit count per category"),
            &["category"],
        )
        .expect("metric creation failed");

        let misses = IntCounterVec::new(
            prometheus::opts!("cache_l1_misses_total", "L1 cache miss count per category"),
            &["category"],
        )
        .expect("metric creation failed");

        let inserts = IntCounterVec::new(
            prometheus::opts!(
                "cache_l1_inserts_total",
                "L1 cache insert count per category"
            ),
            &["category"],
        )
        .expect("metric creation failed");

        registry.register(Box::new(hits.clone())).ok();
        registry.register(Box::new(misses.clone())).ok();
        registry.register(Box::new(inserts.clone())).ok();

        Arc::new(Self {
            hits,
            misses,
            inserts,
        })
    }

    pub fn record_hit(&self, category: &str) {
        self.hits.with_label_values(&[category]).inc();
    }

    pub fn record_miss(&self, category: &str) {
        self.misses.with_label_values(&[category]).inc();
    }

    pub fn record_insert(&self, category: &str) {
        self.inserts.with_label_values(&[category]).inc();
    }
}

/// Metrics for the Level 2 Redis cache.
pub struct L2Metrics {
    hits: IntCounterVec,
    misses: IntCounterVec,
    /// Tracks total requests per category for hit-rate calculation.
    requests: IntCounterVec,
    /// Alert threshold (0.0–1.0). Configurable via CACHE_HIT_RATE_ALERT_THRESHOLD env var.
    alert_threshold: f64,
}

impl L2Metrics {
    pub fn new(registry: &Registry) -> Arc<Self> {
        let hits = IntCounterVec::new(
            prometheus::opts!("cache_l2_hits_total", "L2 Redis cache hit count per category"),
            &["category"],
        )
        .expect("metric creation failed");

        let misses = IntCounterVec::new(
            prometheus::opts!(
                "cache_l2_misses_total",
                "L2 Redis cache miss count per category"
            ),
            &["category"],
        )
        .expect("metric creation failed");

        let requests = IntCounterVec::new(
            prometheus::opts!(
                "cache_l2_requests_total",
                "L2 Redis cache total requests per category"
            ),
            &["category"],
        )
        .expect("metric creation failed");

        registry.register(Box::new(hits.clone())).ok();
        registry.register(Box::new(misses.clone())).ok();
        registry.register(Box::new(requests.clone())).ok();

        let alert_threshold = std::env::var("CACHE_HIT_RATE_ALERT_THRESHOLD")
            .ok()
            .and_then(|v| v.parse::<f64>().ok())
            .unwrap_or(0.5);

        Arc::new(Self {
            hits,
            misses,
            requests,
            alert_threshold,
        })
    }

    pub fn record_hit(&self, category: &str) {
        self.hits.with_label_values(&[category]).inc();
        self.requests.with_label_values(&[category]).inc();
    }

    pub fn record_miss(&self, category: &str) {
        self.misses.with_label_values(&[category]).inc();
        self.requests.with_label_values(&[category]).inc();
        self.check_hit_rate_alert(category);
    }

    /// Emit a warning if the rolling hit rate drops below the configured threshold.
    /// In production, wire this to your alerting pipeline.
    fn check_hit_rate_alert(&self, category: &str) {
        let total = self
            .requests
            .with_label_values(&[category])
            .get();
        let hits = self.hits.with_label_values(&[category]).get();

        // Only alert after a minimum sample size to avoid false positives at startup.
        if total >= 20 {
            let hit_rate = hits as f64 / total as f64;
            if hit_rate < self.alert_threshold {
                warn!(
                    category,
                    hit_rate,
                    threshold = self.alert_threshold,
                    "⚠️  L2 cache hit rate below alert threshold — possible caching regression"
                );
            }
        }
    }
}

/// Gauge metrics for cache sizes (updated periodically by the warmer).
pub struct CacheSizeMetrics {
    l1_size: GaugeVec,
}

impl CacheSizeMetrics {
    pub fn new(registry: &Registry) -> Arc<Self> {
        let l1_size = GaugeVec::new(
            prometheus::opts!("cache_l1_size_entries", "Current L1 cache entry count"),
            &["category"],
        )
        .expect("metric creation failed");

        registry.register(Box::new(l1_size.clone())).ok();

        Arc::new(Self { l1_size })
    }

    pub fn set_l1_size(&self, category: &str, count: u64) {
        self.l1_size
            .with_label_values(&[category])
            .set(count as f64);
    }
}
