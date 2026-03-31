//! Prometheus metrics for the platform key management framework.

use prometheus::{CounterVec, GaugeVec, Registry};
use std::sync::OnceLock;

static ROTATION_INITIATED: OnceLock<CounterVec> = OnceLock::new();
static ROTATION_FAILED: OnceLock<CounterVec> = OnceLock::new();
static GRACE_PERIOD_EXPIRED: OnceLock<CounterVec> = OnceLock::new();
static EMERGENCY_REVOCATIONS: OnceLock<CounterVec> = OnceLock::new();
static KEYS_BY_STATUS: OnceLock<GaugeVec> = OnceLock::new();
static DAYS_UNTIL_ROTATION: OnceLock<GaugeVec> = OnceLock::new();
static REENCRYPTION_PROGRESS: OnceLock<GaugeVec> = OnceLock::new();

pub fn register(r: &Registry) {
    ROTATION_INITIATED
        .set(
            prometheus::register_counter_vec_with_registry!(
                "aframp_key_rotations_initiated_total",
                "Total key rotations initiated by key type",
                &["key_type"],
                r
            )
            .unwrap(),
        )
        .ok();

    ROTATION_FAILED
        .set(
            prometheus::register_counter_vec_with_registry!(
                "aframp_key_rotation_failures_total",
                "Total key rotation failures by key type",
                &["key_type"],
                r
            )
            .unwrap(),
        )
        .ok();

    GRACE_PERIOD_EXPIRED
        .set(
            prometheus::register_counter_vec_with_registry!(
                "aframp_key_grace_periods_expired_total",
                "Total key grace periods expired (old key retired) by key type",
                &["key_type"],
                r
            )
            .unwrap(),
        )
        .ok();

    EMERGENCY_REVOCATIONS
        .set(
            prometheus::register_counter_vec_with_registry!(
                "aframp_key_emergency_revocations_total",
                "Total emergency key revocations by key type",
                &["key_type"],
                r
            )
            .unwrap(),
        )
        .ok();

    KEYS_BY_STATUS
        .set(
            prometheus::register_gauge_vec_with_registry!(
                "aframp_platform_keys_by_status",
                "Count of platform keys in each lifecycle state",
                &["key_type", "status"],
                r
            )
            .unwrap(),
        )
        .ok();

    DAYS_UNTIL_ROTATION
        .set(
            prometheus::register_gauge_vec_with_registry!(
                "aframp_key_days_until_rotation",
                "Days until next scheduled rotation per key (negative = overdue)",
                &["key_id", "key_type"],
                r
            )
            .unwrap(),
        )
        .ok();

    REENCRYPTION_PROGRESS
        .set(
            prometheus::register_gauge_vec_with_registry!(
                "aframp_reencryption_progress_ratio",
                "Re-encryption job progress ratio (0.0–1.0) per table",
                &["table_name"],
                r
            )
            .unwrap(),
        )
        .ok();
}

pub fn inc_rotation_initiated(key_type: &str) {
    if let Some(c) = ROTATION_INITIATED.get() {
        c.with_label_values(&[key_type]).inc();
    }
}

pub fn inc_rotation_failed(key_type: &str) {
    if let Some(c) = ROTATION_FAILED.get() {
        c.with_label_values(&[key_type]).inc();
    }
}

pub fn inc_grace_period_expired(key_type: &str) {
    if let Some(c) = GRACE_PERIOD_EXPIRED.get() {
        c.with_label_values(&[key_type]).inc();
    }
}

pub fn inc_emergency_revocation(key_type: &str) {
    if let Some(c) = EMERGENCY_REVOCATIONS.get() {
        c.with_label_values(&[key_type]).inc();
    }
}

pub fn set_keys_by_status(key_type: &str, status: &str, count: f64) {
    if let Some(g) = KEYS_BY_STATUS.get() {
        g.with_label_values(&[key_type, status]).set(count);
    }
}

pub fn set_days_until_rotation(key_id: &str, key_type: &str, days: f64) {
    if let Some(g) = DAYS_UNTIL_ROTATION.get() {
        g.with_label_values(&[key_id, key_type]).set(days);
    }
}

pub fn set_reencryption_progress(table_name: &str, processed: i64, total: i64) {
    if let Some(g) = REENCRYPTION_PROGRESS.get() {
        let ratio = if total > 0 { processed as f64 / total as f64 } else { 1.0 };
        g.with_label_values(&[table_name]).set(ratio);
    }
}
