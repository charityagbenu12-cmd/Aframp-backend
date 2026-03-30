use prometheus::{
    register_counter_vec_with_registry, register_gauge_vec_with_registry,
    register_histogram_vec_with_registry, register_int_gauge_with_registry,
    CounterVec, GaugeVec, HistogramVec, IntGauge, Registry,
};
use std::sync::OnceLock;

static SNAPSHOTS_GENERATED_TOTAL: OnceLock<CounterVec> = OnceLock::new();
static SNAPSHOT_GENERATION_DURATION_SECONDS: OnceLock<HistogramVec> = OnceLock::new();
static CONSUMER_HEALTH_SCORE: OnceLock<GaugeVec> = OnceLock::new();
static AT_RISK_CONSUMERS_TOTAL: OnceLock<IntGauge> = OnceLock::new();
static ANOMALIES_DETECTED_TOTAL: OnceLock<CounterVec> = OnceLock::new();
static ACTIVE_CONSUMERS_BY_TIER: OnceLock<GaugeVec> = OnceLock::new();
static PLATFORM_REQUEST_RATE: OnceLock<GaugeVec> = OnceLock::new();

pub fn snapshots_generated_total() -> &'static CounterVec {
    SNAPSHOTS_GENERATED_TOTAL
        .get()
        .expect("analytics metrics not initialised")
}

pub fn snapshot_generation_duration_seconds() -> &'static HistogramVec {
    SNAPSHOT_GENERATION_DURATION_SECONDS
        .get()
        .expect("analytics metrics not initialised")
}

pub fn consumer_health_score() -> &'static GaugeVec {
    CONSUMER_HEALTH_SCORE
        .get()
        .expect("analytics metrics not initialised")
}

pub fn at_risk_consumers_total() -> &'static IntGauge {
    AT_RISK_CONSUMERS_TOTAL
        .get()
        .expect("analytics metrics not initialised")
}

pub fn anomalies_detected_total() -> &'static CounterVec {
    ANOMALIES_DETECTED_TOTAL
        .get()
        .expect("analytics metrics not initialised")
}

pub fn active_consumers_by_tier() -> &'static GaugeVec {
    ACTIVE_CONSUMERS_BY_TIER
        .get()
        .expect("analytics metrics not initialised")
}

pub fn platform_request_rate() -> &'static GaugeVec {
    PLATFORM_REQUEST_RATE
        .get()
        .expect("analytics metrics not initialised")
}

pub fn register(r: &Registry) {
    SNAPSHOTS_GENERATED_TOTAL
        .set(
            register_counter_vec_with_registry!(
                "aframp_analytics_snapshots_generated_total",
                "Total usage snapshots generated per period and status",
                &["period", "status"],
                r
            )
            .unwrap(),
        )
        .ok();

    SNAPSHOT_GENERATION_DURATION_SECONDS
        .set(
            register_histogram_vec_with_registry!(
                "aframp_analytics_snapshot_generation_duration_seconds",
                "Duration of snapshot generation per period",
                &["period"],
                vec![0.1, 0.5, 1.0, 5.0, 10.0, 30.0, 60.0, 120.0],
                r
            )
            .unwrap(),
        )
        .ok();

    CONSUMER_HEALTH_SCORE
        .set(
            register_gauge_vec_with_registry!(
                "aframp_analytics_consumer_health_score",
                "Current health score per consumer (0-100)",
                &["consumer_id"],
                r
            )
            .unwrap(),
        )
        .ok();

    AT_RISK_CONSUMERS_TOTAL
        .set(
            register_int_gauge_with_registry!(
                "aframp_analytics_at_risk_consumers_total",
                "Number of consumers currently flagged as at-risk",
                r
            )
            .unwrap(),
        )
        .ok();

    ANOMALIES_DETECTED_TOTAL
        .set(
            register_counter_vec_with_registry!(
                "aframp_analytics_anomalies_detected_total",
                "Total usage anomalies detected per type and severity",
                &["anomaly_type", "severity"],
                r
            )
            .unwrap(),
        )
        .ok();

    ACTIVE_CONSUMERS_BY_TIER
        .set(
            register_gauge_vec_with_registry!(
                "aframp_analytics_active_consumers_by_tier",
                "Number of active consumers per tier",
                &["tier"],
                r
            )
            .unwrap(),
        )
        .ok();

    PLATFORM_REQUEST_RATE
        .set(
            register_gauge_vec_with_registry!(
                "aframp_analytics_platform_request_rate",
                "Platform-wide API request rate per minute",
                &["period"],
                r
            )
            .unwrap(),
        )
        .ok();
}
