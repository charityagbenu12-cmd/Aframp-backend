//! Prometheus metrics for abuse detection

use once_cell::sync::Lazy;
use prometheus::{
    register_counter_vec, register_gauge_vec, register_histogram_vec, CounterVec, GaugeVec,
    HistogramVec,
};

pub static ABUSE_SIGNALS_DETECTED: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        "aframp_abuse_signals_detected_total",
        "Total number of abuse signals detected by type",
        &["signal_type", "category"]
    )
    .unwrap()
});

pub static ABUSE_CONFIDENCE_SCORE: Lazy<HistogramVec> = Lazy::new(|| {
    register_histogram_vec!(
        "aframp_abuse_confidence_score",
        "Distribution of abuse confidence scores by consumer type",
        &["consumer_type"],
        vec![0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 0.95, 1.0]
    )
    .unwrap()
});

pub static ABUSE_RESPONSE_ACTIONS: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        "aframp_abuse_response_actions_total",
        "Total number of automated response actions by tier",
        &["tier"]
    )
    .unwrap()
});

pub static ABUSE_FALSE_POSITIVES: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        "aframp_abuse_false_positives_total",
        "Total number of false positive dismissals by signal type",
        &["signal_type"]
    )
    .unwrap()
});

pub static ABUSE_CASES_OPEN: Lazy<GaugeVec> = Lazy::new(|| {
    register_gauge_vec!(
        "aframp_abuse_cases_open",
        "Number of currently open abuse cases by tier",
        &["tier"]
    )
    .unwrap()
});

pub static ABUSE_CASES_RESOLVED: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        "aframp_abuse_cases_resolved_total",
        "Total number of resolved abuse cases",
        &["tier", "outcome"]
    )
    .unwrap()
});

pub static ABUSE_COORDINATED_ATTACKS: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        "aframp_abuse_coordinated_attacks_total",
        "Total number of coordinated attacks detected",
        &["attack_type"]
    )
    .unwrap()
});

pub static ABUSE_DETECTION_DURATION: Lazy<HistogramVec> = Lazy::new(|| {
    register_histogram_vec!(
        "aframp_abuse_detection_duration_seconds",
        "Time taken to process abuse detection checks",
        &["check_type"],
        vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0]
    )
    .unwrap()
});
