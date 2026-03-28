//! Prometheus metrics for mTLS certificate lifecycle and handshake events.

use prometheus::{
    register_counter_vec_with_registry, register_gauge_vec_with_registry,
    CounterVec, GaugeVec,
};
use std::sync::OnceLock;

static CERT_DAYS_UNTIL_EXPIRY: OnceLock<GaugeVec> = OnceLock::new();
static CERTS_WITHIN_ROTATION_THRESHOLD: OnceLock<GaugeVec> = OnceLock::new();
static CERTS_WITHIN_ALERT_THRESHOLD: OnceLock<GaugeVec> = OnceLock::new();
static MTLS_HANDSHAKE_TOTAL: OnceLock<CounterVec> = OnceLock::new();
static CERT_ROTATIONS_TOTAL: OnceLock<CounterVec> = OnceLock::new();
static CERT_REVOCATIONS_TOTAL: OnceLock<CounterVec> = OnceLock::new();
static CERT_ISSUANCES_TOTAL: OnceLock<CounterVec> = OnceLock::new();

pub fn register(r: &prometheus::Registry) {
    CERT_DAYS_UNTIL_EXPIRY
        .set(
            register_gauge_vec_with_registry!(
                "aframp_mtls_cert_days_until_expiry",
                "Days until service certificate expiry",
                &["service_name"],
                r
            )
            .unwrap(),
        )
        .ok();

    CERTS_WITHIN_ROTATION_THRESHOLD
        .set(
            register_gauge_vec_with_registry!(
                "aframp_mtls_certs_within_rotation_threshold",
                "Number of certificates within the rotation threshold",
                &["environment"],
                r
            )
            .unwrap(),
        )
        .ok();

    CERTS_WITHIN_ALERT_THRESHOLD
        .set(
            register_gauge_vec_with_registry!(
                "aframp_mtls_certs_within_alert_threshold",
                "Number of certificates within the alert threshold",
                &["environment"],
                r
            )
            .unwrap(),
        )
        .ok();

    MTLS_HANDSHAKE_TOTAL
        .set(
            register_counter_vec_with_registry!(
                "aframp_mtls_handshake_total",
                "Total mTLS handshake attempts",
                &["from_service", "to_service", "result"],
                r
            )
            .unwrap(),
        )
        .ok();

    CERT_ROTATIONS_TOTAL
        .set(
            register_counter_vec_with_registry!(
                "aframp_mtls_cert_rotations_total",
                "Total certificate rotations per service",
                &["service_name"],
                r
            )
            .unwrap(),
        )
        .ok();

    CERT_REVOCATIONS_TOTAL
        .set(
            register_counter_vec_with_registry!(
                "aframp_mtls_cert_revocations_total",
                "Total certificate revocations per service",
                &["service_name"],
                r
            )
            .unwrap(),
        )
        .ok();

    CERT_ISSUANCES_TOTAL
        .set(
            register_counter_vec_with_registry!(
                "aframp_mtls_cert_issuances_total",
                "Total certificate issuances per service",
                &["service_name"],
                r
            )
            .unwrap(),
        )
        .ok();
}

pub fn set_cert_days_until_expiry(service_name: &str, days: f64) {
    if let Some(g) = CERT_DAYS_UNTIL_EXPIRY.get() {
        g.with_label_values(&[service_name]).set(days);
    }
}

pub fn set_certs_within_rotation_threshold(environment: &str, count: f64) {
    if let Some(g) = CERTS_WITHIN_ROTATION_THRESHOLD.get() {
        g.with_label_values(&[environment]).set(count);
    }
}

pub fn set_certs_within_alert_threshold(environment: &str, count: f64) {
    if let Some(g) = CERTS_WITHIN_ALERT_THRESHOLD.get() {
        g.with_label_values(&[environment]).set(count);
    }
}

pub fn record_handshake(from_service: &str, to_service: &str, success: bool) {
    if let Some(c) = MTLS_HANDSHAKE_TOTAL.get() {
        let result = if success { "success" } else { "failure" };
        c.with_label_values(&[from_service, to_service, result]).inc();
    }
}

pub fn cert_rotations_total(service_name: &str) {
    if let Some(c) = CERT_ROTATIONS_TOTAL.get() {
        c.with_label_values(&[service_name]).inc();
    }
}

pub fn cert_revocations_total(service_name: &str) {
    if let Some(c) = CERT_REVOCATIONS_TOTAL.get() {
        c.with_label_values(&[service_name]).inc();
    }
}

pub fn cert_issuances_total(service_name: &str) {
    if let Some(c) = CERT_ISSUANCES_TOTAL.get() {
        c.with_label_values(&[service_name]).inc();
    }
}
