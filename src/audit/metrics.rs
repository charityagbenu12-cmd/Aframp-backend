use prometheus::{register_counter_vec_with_registry, register_gauge_with_registry,
                  register_histogram_vec_with_registry, CounterVec, Gauge, HistogramVec, Registry};
use std::sync::OnceLock;

static AUDIT_ENTRIES_TOTAL: OnceLock<CounterVec> = OnceLock::new();
static AUDIT_WRITER_CHANNEL_UTILISATION: OnceLock<Gauge> = OnceLock::new();
static AUDIT_HASH_CHAIN_DURATION_SECONDS: OnceLock<HistogramVec> = OnceLock::new();
static AUDIT_REPLICATION_LAG_SECONDS: OnceLock<Gauge> = OnceLock::new();
static AUDIT_OVERFLOW_FALLBACKS_TOTAL: OnceLock<CounterVec> = OnceLock::new();

pub fn entries_total() -> &'static CounterVec {
    AUDIT_ENTRIES_TOTAL.get().expect("audit metrics not initialised")
}

pub fn writer_channel_utilisation() -> &'static Gauge {
    AUDIT_WRITER_CHANNEL_UTILISATION.get().expect("audit metrics not initialised")
}

pub fn hash_chain_duration_seconds() -> &'static HistogramVec {
    AUDIT_HASH_CHAIN_DURATION_SECONDS.get().expect("audit metrics not initialised")
}

pub fn replication_lag_seconds() -> &'static Gauge {
    AUDIT_REPLICATION_LAG_SECONDS.get().expect("audit metrics not initialised")
}

pub fn overflow_fallbacks_total() -> &'static CounterVec {
    AUDIT_OVERFLOW_FALLBACKS_TOTAL.get().expect("audit metrics not initialised")
}

pub fn register(r: &Registry) {
    AUDIT_ENTRIES_TOTAL
        .set(
            register_counter_vec_with_registry!(
                "aframp_audit_entries_total",
                "Total audit log entries written per event category",
                &["event_category"],
                r
            )
            .unwrap(),
        )
        .ok();

    AUDIT_WRITER_CHANNEL_UTILISATION
        .set(
            register_gauge_with_registry!(
                "aframp_audit_writer_channel_utilisation",
                "Fraction of audit writer channel buffer currently in use (0.0–1.0)",
                r
            )
            .unwrap(),
        )
        .ok();

    AUDIT_HASH_CHAIN_DURATION_SECONDS
        .set(
            register_histogram_vec_with_registry!(
                "aframp_audit_hash_chain_duration_seconds",
                "Time spent computing audit log hash chain entries",
                &["operation"],
                vec![0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05],
                r
            )
            .unwrap(),
        )
        .ok();

    AUDIT_REPLICATION_LAG_SECONDS
        .set(
            register_gauge_with_registry!(
                "aframp_audit_replication_lag_seconds",
                "Seconds since the last successful secondary replication write",
                r
            )
            .unwrap(),
        )
        .ok();

    AUDIT_OVERFLOW_FALLBACKS_TOTAL
        .set(
            register_counter_vec_with_registry!(
                "aframp_audit_overflow_fallbacks_total",
                "Times the audit writer fell back to synchronous writes due to channel overflow",
                &["reason"],
                r
            )
            .unwrap(),
        )
        .ok();
}
