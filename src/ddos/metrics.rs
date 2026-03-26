//! Prometheus metrics for DDoS protection.

use prometheus::{
    register_counter_vec_with_registry, register_gauge_vec_with_registry,
    CounterVec, GaugeVec, Registry,
};
use std::sync::OnceLock;

static REQUEST_RATE: OnceLock<GaugeVec> = OnceLock::new();
static ENDPOINT_REQUEST_RATE: OnceLock<GaugeVec> = OnceLock::new();
static CONNECTION_COUNT: OnceLock<GaugeVec> = OnceLock::new();
static QUEUE_DEPTH: OnceLock<GaugeVec> = OnceLock::new();
static DROPPED_REQUESTS: OnceLock<CounterVec> = OnceLock::new();
static CHALLENGES_ISSUED: OnceLock<CounterVec> = OnceLock::new();
static CHALLENGES_SOLVED: OnceLock<CounterVec> = OnceLock::new();
static CDN_UNDER_ATTACK_ACTIVATIONS: OnceLock<CounterVec> = OnceLock::new();
static LOCKDOWN_ACTIVATIONS: OnceLock<CounterVec> = OnceLock::new();

pub fn register(r: &Registry) {
    REQUEST_RATE
        .set(
            register_gauge_vec_with_registry!(
                "aframp_ddos_request_rate",
                "Current platform-wide request rate (req/s)",
                &[],
                r
            )
            .unwrap(),
        )
        .ok();

    ENDPOINT_REQUEST_RATE
        .set(
            register_gauge_vec_with_registry!(
                "aframp_ddos_endpoint_request_rate",
                "Per-endpoint request rate (req/s)",
                &["endpoint"],
                r
            )
            .unwrap(),
        )
        .ok();

    CONNECTION_COUNT
        .set(
            register_gauge_vec_with_registry!(
                "aframp_ddos_connection_count",
                "Current connection count",
                &["dimension"], // "total", "per_ip", "per_consumer"
                r
            )
            .unwrap(),
        )
        .ok();

    QUEUE_DEPTH
        .set(
            register_gauge_vec_with_registry!(
                "aframp_ddos_queue_depth",
                "Processing queue depth per priority tier",
                &["tier"],
                r
            )
            .unwrap(),
        )
        .ok();

    DROPPED_REQUESTS
        .set(
            register_counter_vec_with_registry!(
                "aframp_ddos_dropped_requests_total",
                "Total dropped requests by reason",
                &["reason"],
                r
            )
            .unwrap(),
        )
        .ok();

    CHALLENGES_ISSUED
        .set(
            register_counter_vec_with_registry!(
                "aframp_ddos_challenges_issued_total",
                "Total proof-of-work challenges issued",
                &["difficulty"],
                r
            )
            .unwrap(),
        )
        .ok();

    CHALLENGES_SOLVED
        .set(
            register_counter_vec_with_registry!(
                "aframp_ddos_challenges_solved_total",
                "Total proof-of-work challenges solved",
                &[],
                r
            )
            .unwrap(),
        )
        .ok();

    CDN_UNDER_ATTACK_ACTIVATIONS
        .set(
            register_counter_vec_with_registry!(
                "aframp_ddos_cdn_under_attack_activations_total",
                "Total CDN under-attack mode activations",
                &["provider"],
                r
            )
            .unwrap(),
        )
        .ok();

    LOCKDOWN_ACTIVATIONS
        .set(
            register_counter_vec_with_registry!(
                "aframp_ddos_lockdown_activations_total",
                "Total emergency lockdown activations",
                &["trigger"],
                r
            )
            .unwrap(),
        )
        .ok();
}

pub fn request_rate() -> &'static GaugeVec {
    REQUEST_RATE.get().expect("ddos metrics not initialised")
}

pub fn endpoint_request_rate() -> &'static GaugeVec {
    ENDPOINT_REQUEST_RATE.get().expect("ddos metrics not initialised")
}

pub fn connection_count() -> &'static GaugeVec {
    CONNECTION_COUNT.get().expect("ddos metrics not initialised")
}

pub fn queue_depth() -> &'static GaugeVec {
    QUEUE_DEPTH.get().expect("ddos metrics not initialised")
}

pub fn dropped_requests() -> &'static CounterVec {
    DROPPED_REQUESTS.get().expect("ddos metrics not initialised")
}

pub fn challenges_issued() -> &'static CounterVec {
    CHALLENGES_ISSUED.get().expect("ddos metrics not initialised")
}

pub fn challenges_solved() -> &'static CounterVec {
    CHALLENGES_SOLVED.get().expect("ddos metrics not initialised")
}

pub fn cdn_under_attack_activations() -> &'static CounterVec {
    CDN_UNDER_ATTACK_ACTIVATIONS.get().expect("ddos metrics not initialised")
}

pub fn lockdown_activations() -> &'static CounterVec {
    LOCKDOWN_ACTIVATIONS.get().expect("ddos metrics not initialised")
}
