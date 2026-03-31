//! Prometheus metrics for the gateway layer.

use prometheus::{register_counter_vec_with_registry, register_histogram_vec_with_registry, CounterVec, HistogramVec, Registry};
use std::sync::OnceLock;

static GATEWAY_REQUESTS_TOTAL: OnceLock<CounterVec> = OnceLock::new();
static GATEWAY_REJECTIONS_TOTAL: OnceLock<CounterVec> = OnceLock::new();
static GATEWAY_UPSTREAM_DURATION: OnceLock<HistogramVec> = OnceLock::new();
static GATEWAY_TLS_FAILURES_TOTAL: OnceLock<CounterVec> = OnceLock::new();

pub fn register(registry: &Registry) {
    GATEWAY_REQUESTS_TOTAL
        .set(
            register_counter_vec_with_registry!(
                "aframp_gateway_requests_total",
                "Total requests processed by the gateway",
                &["method", "path_prefix"],
                registry
            )
            .unwrap(),
        )
        .ok();

    GATEWAY_REJECTIONS_TOTAL
        .set(
            register_counter_vec_with_registry!(
                "aframp_gateway_rejections_total",
                "Total requests rejected by the gateway per rejection reason",
                &["reason"],
                registry
            )
            .unwrap(),
        )
        .ok();

    GATEWAY_UPSTREAM_DURATION
        .set(
            register_histogram_vec_with_registry!(
                "aframp_gateway_upstream_duration_seconds",
                "Upstream service response time as seen by the gateway",
                &["path_prefix"],
                vec![0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0],
                registry
            )
            .unwrap(),
        )
        .ok();

    GATEWAY_TLS_FAILURES_TOTAL
        .set(
            register_counter_vec_with_registry!(
                "aframp_gateway_tls_failures_total",
                "Total TLS handshake failures at the gateway",
                &["reason"],
                registry
            )
            .unwrap(),
        )
        .ok();
}

pub fn record_request(method: &str, path: &str) {
    let prefix = path_prefix(path);
    if let Some(c) = GATEWAY_REQUESTS_TOTAL.get() {
        c.with_label_values(&[method, prefix]).inc();
    }
}

pub fn record_rejection(reason: &str) {
    if let Some(c) = GATEWAY_REJECTIONS_TOTAL.get() {
        c.with_label_values(&[reason]).inc();
    }
}

pub fn record_tls_failure(reason: &str) {
    if let Some(c) = GATEWAY_TLS_FAILURES_TOTAL.get() {
        c.with_label_values(&[reason]).inc();
    }
}

fn path_prefix(path: &str) -> &'static str {
    if path.starts_with("/api/admin") { "/api/admin" }
    else if path.starts_with("/api/v1/onramp") { "/api/v1/onramp" }
    else if path.starts_with("/api/v1/offramp") { "/api/v1/offramp" }
    else if path.starts_with("/api/v1/wallet") { "/api/v1/wallet" }
    else if path.starts_with("/api/v1/auth") { "/api/v1/auth" }
    else if path.starts_with("/api/developer") { "/api/developer" }
    else { "/other" }
}
