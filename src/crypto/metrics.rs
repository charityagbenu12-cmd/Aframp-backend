//! Prometheus metrics for payload encryption operations.

use prometheus::{CounterVec, Registry};
use std::sync::OnceLock;

static DECRYPTIONS_TOTAL: OnceLock<CounterVec> = OnceLock::new();
static DECRYPTION_FAILURES_TOTAL: OnceLock<CounterVec> = OnceLock::new();
static KEY_VERSION_USAGE_TOTAL: OnceLock<CounterVec> = OnceLock::new();
static PLAINTEXT_REJECTIONS_TOTAL: OnceLock<CounterVec> = OnceLock::new();

pub fn register(r: &Registry) {
    DECRYPTIONS_TOTAL
        .set(
            prometheus::register_counter_vec_with_registry!(
                "aframp_payload_decryptions_total",
                "Total encrypted field decryptions by field type",
                &["field_type"],
                r
            )
            .unwrap(),
        )
        .ok();

    DECRYPTION_FAILURES_TOTAL
        .set(
            prometheus::register_counter_vec_with_registry!(
                "aframp_payload_decryption_failures_total",
                "Encrypted field decryption failures by field type and reason",
                &["field_type", "reason"],
                r
            )
            .unwrap(),
        )
        .ok();

    KEY_VERSION_USAGE_TOTAL
        .set(
            prometheus::register_counter_vec_with_registry!(
                "aframp_payload_key_version_usage_total",
                "Decryption requests by key version",
                &["kid"],
                r
            )
            .unwrap(),
        )
        .ok();

    PLAINTEXT_REJECTIONS_TOTAL
        .set(
            prometheus::register_counter_vec_with_registry!(
                "aframp_payload_plaintext_rejections_total",
                "Requests rejected for submitting plaintext sensitive fields by endpoint",
                &["endpoint", "field"],
                r
            )
            .unwrap(),
        )
        .ok();
}

pub fn inc_decryption(field_type: &str) {
    if let Some(c) = DECRYPTIONS_TOTAL.get() {
        c.with_label_values(&[field_type]).inc();
    }
}

pub fn inc_decryption_failure(field_type: &str, reason: &str) {
    if let Some(c) = DECRYPTION_FAILURES_TOTAL.get() {
        c.with_label_values(&[field_type, reason]).inc();
    }
}

pub fn inc_key_version_usage(kid: &str) {
    if let Some(c) = KEY_VERSION_USAGE_TOTAL.get() {
        c.with_label_values(&[kid]).inc();
    }
}

pub fn inc_plaintext_rejection(endpoint: &str, field: &str) {
    if let Some(c) = PLAINTEXT_REJECTIONS_TOTAL.get() {
        c.with_label_values(&[endpoint, field]).inc();
    }
}
