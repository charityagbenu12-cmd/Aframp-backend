//! Prometheus counters for masking events per category and output channel.

use prometheus::{register_counter_vec_with_registry, CounterVec, Registry};
use std::sync::OnceLock;

static MASKING_EVENTS_TOTAL: OnceLock<CounterVec> = OnceLock::new();
static MASKING_ALERT_TOTAL: OnceLock<CounterVec> = OnceLock::new();

pub fn register(registry: &Registry) {
    MASKING_EVENTS_TOTAL
        .set(
            register_counter_vec_with_registry!(
                "aframp_masking_events_total",
                "Total masking events by sensitive data category and output channel",
                &["category", "channel"],
                registry
            )
            .unwrap(),
        )
        .ok();

    MASKING_ALERT_TOTAL
        .set(
            register_counter_vec_with_registry!(
                "aframp_masking_alerts_total",
                "Total security alerts fired when sensitive data detected in output channels",
                &["channel"],
                registry
            )
            .unwrap(),
        )
        .ok();
}

/// Record a masking event for a given field/category and channel.
pub fn record_masking_event(category: &str, channel: &str) {
    if let Some(counter) = MASKING_EVENTS_TOTAL.get() {
        counter.with_label_values(&[category, channel]).inc();
    }
}

/// Record a security alert (sensitive data reached an output channel unmasked).
pub fn record_masking_alert(channel: &str) {
    if let Some(counter) = MASKING_ALERT_TOTAL.get() {
        counter.with_label_values(&[channel]).inc();
    }
}
