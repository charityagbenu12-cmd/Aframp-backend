//! Prometheus metrics for advanced rate limiting (Issue #175)

use prometheus::{
    register_counter_vec, register_histogram_vec, CounterVec, HistogramVec, IntCounterVec,
    Opts, Registry
};
use once_cell::sync::Lazy;
use std::sync::Arc;

/// Global metrics registry (shared with main.rs)
pub static REGISTRY: Lazy<Registry> = Lazy::new(prometheus::default_registry);

/// Rate limit checks total (per dimension/consumer_type)
pub static RATE_LIMIT_CHECKS: Lazy<IntCounterVec> = Lazy::new(|| {
    register_counter_vec!(
        REGISTRY,
        Opts::new("aframp_rate_limit_checks_total", "Rate limit checks performed")
            .namespace("aframp")
            .subsystem("rate_limit"),
        &["dimension", "consumer_type", "endpoint_sensitivity"]
    ).unwrap()
});

/// Rate limit hits (throttles)
pub static RATE_LIMIT_HITS: Lazy<IntCounterVec> = Lazy::new(|| {
    register_counter_vec!(
        REGISTRY,
        Opts::new("aframp_rate_limit_hits_total", "Rate limit exceeded")
            .namespace("aframp")
            .subsystem("rate_limit"),
        &["dimension", "consumer_type", "endpoint_sensitivity"]
    ).unwrap()
});

/// Rate limit utilisation (histogram % of limit used)
pub static RATE_LIMIT_UTILISATION: Lazy<HistogramVec> = Lazy::new(|| {
    register_histogram_vec!(
        REGISTRY,
        prometheus::HistogramOpts::new("aframp_rate_limit_utilisation_percent", "Rate limit utilisation %")
            .namespace("aframp")
            .subsystem("rate_limit")
            .buckets(vec![0.0, 10.0, 25.0, 50.0, 75.0, 90.0, 100.0]),
        &["consumer_type", "dimension"]
    ).unwrap()
});

/// 429 responses per consumer (alert threshold)
pub static RATE_LIMIT_429_RESPONSES: Lazy<IntCounterVec> = Lazy::new(|| {
    register_counter_vec!(
        REGISTRY,
        Opts::new("aframp_rate_limit_429_responses_total", "429 responses per consumer")
            .namespace("aframp")
            .subsystem("rate_limit"),
        &["consumer_id_short", "dimension"]
    ).unwrap()
});

pub fn init_metrics() {
    // Called on startup - ensures all metrics registered
    let _ = *RATE_LIMIT_CHECKS;
    let _ = *RATE_LIMIT_HITS;
    let _ = *RATE_LIMIT_UTILISATION;
    let _ = *RATE_LIMIT_429_RESPONSES;
}

/// Record a rate limit check
pub fn record_check(dimension: &str, consumer_type: &str, sensitivity: &str) {
    RATE_LIMIT_CHECKS.with_label_values(&[dimension, consumer_type, sensitivity]).inc();
}

/// Record a rate limit hit (throttle)
pub fn record_hit(dimension: &str, consumer_type: &str, sensitivity: &str) {
    RATE_LIMIT_HITS.with_label_values(&[dimension, consumer_type, sensitivity]).inc();
}

/// Record utilisation %
pub fn record_utilisation(consumer_type: &str, dimension: &str, pct: f64) {
    RATE_LIMIT_UTILISATION.with_label_values(&[consumer_type, dimension]).observe(pct / 100.0);
}

/// Record 429 for consumer (truncated ID for cardinality)
pub fn record_429(consumer_id: Uuid, dimension: &str) {
    let short_id = &consumer_id.to_string()[0..8];
    RATE_LIMIT_429_RESPONSES.with_label_values(&[short_id, dimension]).inc();
}

