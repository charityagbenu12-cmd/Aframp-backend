//! Geo-Restriction Metrics
//!
//! Prometheus metrics for geo-restriction observability.

use lazy_static::lazy_static;
use prometheus::{
    register_counter_vec, register_histogram_vec, register_int_gauge_vec, CounterVec, Encoder,
    HistogramVec, IntGaugeVec, TextEncoder,
};
use std::collections::HashMap;

/// Geo-restriction policy evaluation metrics
lazy_static! {
    pub static ref GEO_POLICY_EVALUATIONS: CounterVec = register_counter_vec!(
        "geo_restriction_policy_evaluations_total",
        "Total number of geo-restriction policy evaluations",
        &["result", "country_code", "policy_type"]
    )
    .expect("Can't create geo policy evaluations metric");

    pub static ref GEO_POLICY_EVALUATION_DURATION: HistogramVec = register_histogram_vec!(
        "geo_restriction_policy_evaluation_duration_seconds",
        "Time spent evaluating geo-restriction policies",
        &["result"]
    )
    .expect("Can't create geo policy evaluation duration metric");

    pub static ref GEO_GEOLOCATION_LOOKUPS: CounterVec = register_counter_vec!(
        "geo_restriction_geolocation_lookups_total",
        "Total number of IP geolocation lookups",
        &["result", "cache_hit"]
    )
    .expect("Can't create geolocation lookups metric");

    pub static ref GEO_GEOLOCATION_CACHE_SIZE: IntGaugeVec = register_int_gauge_vec!(
        "geo_restriction_geolocation_cache_size",
        "Number of entries in geolocation cache",
        &[]
    )
    .expect("Can't create geolocation cache size metric");

    pub static ref GEO_POLICY_CACHE_SIZE: IntGaugeVec = register_int_gauge_vec!(
        "geo_restriction_policy_cache_size",
        "Number of entries in policy evaluation cache",
        &[]
    )
    .expect("Can't create policy cache size metric");

    pub static ref GEO_AUDIT_EVENTS: CounterVec = register_counter_vec!(
        "geo_restriction_audit_events_total",
        "Total number of geo-restriction audit events logged",
        &["action", "result"]
    )
    .expect("Can't create audit events metric");

    pub static ref GEO_BLOCKED_REQUESTS: CounterVec = register_counter_vec!(
        "geo_restriction_blocked_requests_total",
        "Total number of requests blocked by geo-restriction",
        &["country_code", "reason"]
    )
    .expect("Can't create blocked requests metric");

    pub static ref GEO_RESTRICTED_REQUESTS: CounterVec = register_counter_vec!(
        "geo_restriction_restricted_requests_total",
        "Total number of requests restricted by geo-restriction",
        &["country_code", "reason"]
    )
    .expect("Can't create restricted requests metric");

    pub static ref GEO_VERIFICATION_REQUIRED: CounterVec = register_counter_vec!(
        "geo_restriction_verification_required_total",
        "Total number of requests requiring enhanced verification",
        &["country_code"]
    )
    .expect("Can't create verification required metric");
}

/// Metrics collector for geo-restriction
pub struct GeoRestrictionMetrics {
    policy_cache_size: HashMap<String, i64>,
    geolocation_cache_size: i64,
}

impl GeoRestrictionMetrics {
    pub fn new() -> Self {
        Self {
            policy_cache_size: HashMap::new(),
            geolocation_cache_size: 0,
        }
    }

    /// Record policy evaluation result
    pub fn record_policy_evaluation(
        &self,
        result: &str,
        country_code: Option<&str>,
        policy_type: Option<&str>,
    ) {
        let country = country_code.unwrap_or("unknown");
        let policy = policy_type.unwrap_or("unknown");

        GEO_POLICY_EVALUATIONS
            .with_label_values(&[result, country, policy])
            .inc();
    }

    /// Record policy evaluation duration
    pub fn record_policy_evaluation_duration(&self, result: &str, duration_secs: f64) {
        GEO_POLICY_EVALUATION_DURATION
            .with_label_values(&[result])
            .observe(duration_secs);
    }

    /// Record geolocation lookup
    pub fn record_geolocation_lookup(&self, result: &str, cache_hit: bool) {
        let cache_hit_str = if cache_hit { "true" } else { "false" };
        GEO_GEOLOCATION_LOOKUPS
            .with_label_values(&[result, cache_hit_str])
            .inc();
    }

    /// Update geolocation cache size
    pub fn update_geolocation_cache_size(&self, size: i64) {
        GEO_GEOLOCATION_CACHE_SIZE
            .with_label_values(&[])
            .set(size);
    }

    /// Update policy cache size
    pub fn update_policy_cache_size(&self, size: i64) {
        GEO_POLICY_CACHE_SIZE
            .with_label_values(&[])
            .set(size);
    }

    /// Record audit event
    pub fn record_audit_event(&self, action: &str, result: &str) {
        GEO_AUDIT_EVENTS
            .with_label_values(&[action, result])
            .inc();
    }

    /// Record blocked request
    pub fn record_blocked_request(&self, country_code: Option<&str>, reason: &str) {
        let country = country_code.unwrap_or("unknown");
        GEO_BLOCKED_REQUESTS
            .with_label_values(&[country, reason])
            .inc();
    }

    /// Record restricted request
    pub fn record_restricted_request(&self, country_code: Option<&str>, reason: &str) {
        let country = country_code.unwrap_or("unknown");
        GEO_RESTRICTED_REQUESTS
            .with_label_values(&[country, reason])
            .inc();
    }

    /// Record verification required
    pub fn record_verification_required(&self, country_code: Option<&str>) {
        let country = country_code.unwrap_or("unknown");
        GEO_VERIFICATION_REQUIRED
            .with_label_values(&[country])
            .inc();
    }

    /// Get metrics in Prometheus format
    pub fn gather_metrics(&self) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let encoder = TextEncoder::new();
        let metric_families = prometheus::gather();
        let mut buffer = Vec::new();
        encoder.encode(&metric_families, &mut buffer)?;
        Ok(String::from_utf8(buffer)?)
    }
}

impl Default for GeoRestrictionMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Convenience macro for timing policy evaluations
#[macro_export]
macro_rules! time_geo_policy_evaluation {
    ($metrics:expr, $result:expr, $code:block) => {{
        let start = std::time::Instant::now();
        let result = $code;
        let duration = start.elapsed().as_secs_f64();
        $metrics.record_policy_evaluation_duration($result, duration);
        result
    }};
}