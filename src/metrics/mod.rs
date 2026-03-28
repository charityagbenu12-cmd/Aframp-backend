//! Prometheus metrics registry and all metric definitions for Aframp backend.
//!
//! All metrics are registered in a single global registry exposed at GET /metrics.
//! Metric names follow Prometheus naming conventions: snake_case, unit suffix where
//! applicable, and the `aframp_` namespace prefix.

pub mod geo_restriction;
pub mod handler;
pub mod tests;

use prometheus::{
    register_counter_vec_with_registry, register_gauge_vec_with_registry,
    register_histogram_vec_with_registry, CounterVec, GaugeVec, HistogramVec, Registry,
};
use std::sync::OnceLock;

// ---------------------------------------------------------------------------
// Global registry
// ---------------------------------------------------------------------------

static REGISTRY: OnceLock<Registry> = OnceLock::new();

/// Returns the global Prometheus registry, initialising it on first call.
pub fn registry() -> &'static Registry {
    REGISTRY.get_or_init(|| {
        let r = Registry::new();
        register_all(&r);
        r
    })
}

/// Render all metrics in Prometheus text exposition format.
pub fn render() -> String {
    use prometheus::Encoder;
    let encoder = prometheus::TextEncoder::new();
    let mut buf = Vec::new();
    encoder
        .encode(&registry().gather(), &mut buf)
        .expect("encoding metrics failed");
    String::from_utf8(buf).expect("metrics output is not valid UTF-8")
}

// ---------------------------------------------------------------------------
// HTTP request metrics
// ---------------------------------------------------------------------------

pub mod http {
    use super::*;

    static HTTP_REQUESTS_TOTAL: OnceLock<CounterVec> = OnceLock::new();
    static HTTP_REQUEST_DURATION_SECONDS: OnceLock<HistogramVec> = OnceLock::new();
    static HTTP_REQUESTS_IN_FLIGHT: OnceLock<GaugeVec> = OnceLock::new();

    pub fn requests_total() -> &'static CounterVec {
        HTTP_REQUESTS_TOTAL.get().expect("metrics not initialised")
    }

    pub fn request_duration_seconds() -> &'static HistogramVec {
        HTTP_REQUEST_DURATION_SECONDS
            .get()
            .expect("metrics not initialised")
    }

    pub fn requests_in_flight() -> &'static GaugeVec {
        HTTP_REQUESTS_IN_FLIGHT
            .get()
            .expect("metrics not initialised")
    }

    pub(super) fn register(r: &Registry) {
        HTTP_REQUESTS_TOTAL
            .set(
                register_counter_vec_with_registry!(
                    "aframp_http_requests_total",
                    "Total number of HTTP requests",
                    &["method", "route", "status_code"],
                    r
                )
                .unwrap(),
            )
            .ok();

        HTTP_REQUEST_DURATION_SECONDS
            .set(
                register_histogram_vec_with_registry!(
                    "aframp_http_request_duration_seconds",
                    "HTTP request duration in seconds",
                    &["method", "route"],
                    vec![0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0],
                    r
                )
                .unwrap(),
            )
            .ok();

        HTTP_REQUESTS_IN_FLIGHT
            .set(
                register_gauge_vec_with_registry!(
                    "aframp_http_requests_in_flight",
                    "Number of HTTP requests currently being processed",
                    &["route"],
                    r
                )
                .unwrap(),
            )
            .ok();
    }
}

// ---------------------------------------------------------------------------
// cNGN transaction metrics
// ---------------------------------------------------------------------------

pub mod cngn {
    use super::*;

    static CNGN_TRANSACTIONS_TOTAL: OnceLock<CounterVec> = OnceLock::new();
    static CNGN_TRANSACTION_VOLUME: OnceLock<HistogramVec> = OnceLock::new();
    static CNGN_TRANSACTION_DURATION_SECONDS: OnceLock<HistogramVec> = OnceLock::new();

    pub fn transactions_total() -> &'static CounterVec {
        CNGN_TRANSACTIONS_TOTAL
            .get()
            .expect("metrics not initialised")
    }

    pub fn transaction_volume() -> &'static HistogramVec {
        CNGN_TRANSACTION_VOLUME
            .get()
            .expect("metrics not initialised")
    }

    pub fn transaction_duration_seconds() -> &'static HistogramVec {
        CNGN_TRANSACTION_DURATION_SECONDS
            .get()
            .expect("metrics not initialised")
    }

    pub(super) fn register(r: &Registry) {
        CNGN_TRANSACTIONS_TOTAL
            .set(
                register_counter_vec_with_registry!(
                    "aframp_cngn_transactions_total",
                    "Total cNGN transactions by type and status",
                    &["tx_type", "status"],
                    r
                )
                .unwrap(),
            )
            .ok();

        CNGN_TRANSACTION_VOLUME
            .set(
                register_histogram_vec_with_registry!(
                    "aframp_cngn_transaction_volume_ngn",
                    "cNGN transaction amounts in NGN",
                    &["tx_type"],
                    vec![
                        100.0, 500.0, 1_000.0, 5_000.0, 10_000.0, 50_000.0, 100_000.0,
                        500_000.0, 1_000_000.0,
                    ],
                    r
                )
                .unwrap(),
            )
            .ok();

        CNGN_TRANSACTION_DURATION_SECONDS
            .set(
                register_histogram_vec_with_registry!(
                    "aframp_cngn_transaction_duration_seconds",
                    "cNGN transaction processing duration from initiation to completion",
                    &["tx_type"],
                    vec![1.0, 5.0, 15.0, 30.0, 60.0, 120.0, 300.0, 600.0, 1800.0],
                    r
                )
                .unwrap(),
            )
            .ok();
    }
}

// ---------------------------------------------------------------------------
// Payment provider metrics
// ---------------------------------------------------------------------------

pub mod payment {
    use super::*;

    static PAYMENT_PROVIDER_REQUESTS_TOTAL: OnceLock<CounterVec> = OnceLock::new();
    static PAYMENT_PROVIDER_REQUEST_DURATION_SECONDS: OnceLock<HistogramVec> = OnceLock::new();
    static PAYMENT_PROVIDER_FAILURES_TOTAL: OnceLock<CounterVec> = OnceLock::new();

    pub fn provider_requests_total() -> &'static CounterVec {
        PAYMENT_PROVIDER_REQUESTS_TOTAL
            .get()
            .expect("metrics not initialised")
    }

    pub fn provider_request_duration_seconds() -> &'static HistogramVec {
        PAYMENT_PROVIDER_REQUEST_DURATION_SECONDS
            .get()
            .expect("metrics not initialised")
    }

    pub fn provider_failures_total() -> &'static CounterVec {
        PAYMENT_PROVIDER_FAILURES_TOTAL
            .get()
            .expect("metrics not initialised")
    }

    pub(super) fn register(r: &Registry) {
        PAYMENT_PROVIDER_REQUESTS_TOTAL
            .set(
                register_counter_vec_with_registry!(
                    "aframp_payment_provider_requests_total",
                    "Total payment provider requests by provider and operation",
                    &["provider", "operation"],
                    r
                )
                .unwrap(),
            )
            .ok();

        PAYMENT_PROVIDER_REQUEST_DURATION_SECONDS
            .set(
                register_histogram_vec_with_registry!(
                    "aframp_payment_provider_request_duration_seconds",
                    "Payment provider request duration in seconds",
                    &["provider", "operation"],
                    vec![0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0],
                    r
                )
                .unwrap(),
            )
            .ok();

        PAYMENT_PROVIDER_FAILURES_TOTAL
            .set(
                register_counter_vec_with_registry!(
                    "aframp_payment_provider_failures_total",
                    "Total payment provider failures by provider and failure reason",
                    &["provider", "failure_reason"],
                    r
                )
                .unwrap(),
            )
            .ok();
    }
}

// ---------------------------------------------------------------------------
// Stellar service metrics
// ---------------------------------------------------------------------------

pub mod stellar {
    use super::*;

    static STELLAR_TX_SUBMISSIONS_TOTAL: OnceLock<CounterVec> = OnceLock::new();
    static STELLAR_TX_SUBMISSION_DURATION_SECONDS: OnceLock<HistogramVec> = OnceLock::new();
    static STELLAR_TRUSTLINE_ATTEMPTS_TOTAL: OnceLock<CounterVec> = OnceLock::new();

    pub fn tx_submissions_total() -> &'static CounterVec {
        STELLAR_TX_SUBMISSIONS_TOTAL
            .get()
            .expect("metrics not initialised")
    }

    pub fn tx_submission_duration_seconds() -> &'static HistogramVec {
        STELLAR_TX_SUBMISSION_DURATION_SECONDS
            .get()
            .expect("metrics not initialised")
    }

    pub fn trustline_attempts_total() -> &'static CounterVec {
        STELLAR_TRUSTLINE_ATTEMPTS_TOTAL
            .get()
            .expect("metrics not initialised")
    }

    pub(super) fn register(r: &Registry) {
        STELLAR_TX_SUBMISSIONS_TOTAL
            .set(
                register_counter_vec_with_registry!(
                    "aframp_stellar_tx_submissions_total",
                    "Total Stellar transaction submissions by status",
                    &["status"],
                    r
                )
                .unwrap(),
            )
            .ok();

        STELLAR_TX_SUBMISSION_DURATION_SECONDS
            .set(
                register_histogram_vec_with_registry!(
                    "aframp_stellar_tx_submission_duration_seconds",
                    "Stellar transaction submission duration in seconds",
                    &[],
                    vec![0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 20.0, 30.0],
                    r
                )
                .unwrap(),
            )
            .ok();

        STELLAR_TRUSTLINE_ATTEMPTS_TOTAL
            .set(
                register_counter_vec_with_registry!(
                    "aframp_stellar_trustline_attempts_total",
                    "Total Stellar trustline creation attempts by status",
                    &["status"],
                    r
                )
                .unwrap(),
            )
            .ok();
    }
}

// ---------------------------------------------------------------------------
// Background worker metrics
// ---------------------------------------------------------------------------

pub mod worker {
    use super::*;

    static WORKER_CYCLES_TOTAL: OnceLock<CounterVec> = OnceLock::new();
    static WORKER_CYCLE_DURATION_SECONDS: OnceLock<HistogramVec> = OnceLock::new();
    static WORKER_RECORDS_PROCESSED: OnceLock<GaugeVec> = OnceLock::new();
    static WORKER_ERRORS_TOTAL: OnceLock<CounterVec> = OnceLock::new();

    pub fn cycles_total() -> &'static CounterVec {
        WORKER_CYCLES_TOTAL
            .get()
            .expect("metrics not initialised")
    }

    pub fn cycle_duration_seconds() -> &'static HistogramVec {
        WORKER_CYCLE_DURATION_SECONDS
            .get()
            .expect("metrics not initialised")
    }

    pub fn records_processed() -> &'static GaugeVec {
        WORKER_RECORDS_PROCESSED
            .get()
            .expect("metrics not initialised")
    }

    pub fn errors_total() -> &'static CounterVec {
        WORKER_ERRORS_TOTAL
            .get()
            .expect("metrics not initialised")
    }

    pub(super) fn register(r: &Registry) {
        WORKER_CYCLES_TOTAL
            .set(
                register_counter_vec_with_registry!(
                    "aframp_worker_cycles_total",
                    "Total background worker processing cycles",
                    &["worker"],
                    r
                )
                .unwrap(),
            )
            .ok();

        WORKER_CYCLE_DURATION_SECONDS
            .set(
                register_histogram_vec_with_registry!(
                    "aframp_worker_cycle_duration_seconds",
                    "Background worker cycle duration in seconds",
                    &["worker"],
                    vec![0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0, 30.0, 60.0],
                    r
                )
                .unwrap(),
            )
            .ok();

        WORKER_RECORDS_PROCESSED
            .set(
                register_gauge_vec_with_registry!(
                    "aframp_worker_records_processed",
                    "Number of records processed in the last worker cycle",
                    &["worker"],
                    r
                )
                .unwrap(),
            )
            .ok();

        WORKER_ERRORS_TOTAL
            .set(
                register_counter_vec_with_registry!(
                    "aframp_worker_errors_total",
                    "Total background worker errors by worker and error type",
                    &["worker", "error_type"],
                    r
                )
                .unwrap(),
            )
            .ok();
    }
}

// ---------------------------------------------------------------------------
// Redis cache metrics
// ---------------------------------------------------------------------------

pub mod cache {
    use super::*;

    static CACHE_HITS_TOTAL: OnceLock<CounterVec> = OnceLock::new();
    static CACHE_MISSES_TOTAL: OnceLock<CounterVec> = OnceLock::new();
    static CACHE_OPERATION_DURATION_SECONDS: OnceLock<HistogramVec> = OnceLock::new();

    pub fn hits_total() -> &'static CounterVec {
        CACHE_HITS_TOTAL.get().expect("metrics not initialised")
    }

    pub fn misses_total() -> &'static CounterVec {
        CACHE_MISSES_TOTAL.get().expect("metrics not initialised")
    }

    pub fn operation_duration_seconds() -> &'static HistogramVec {
        CACHE_OPERATION_DURATION_SECONDS
            .get()
            .expect("metrics not initialised")
    }

    pub(super) fn register(r: &Registry) {
        CACHE_HITS_TOTAL
            .set(
                register_counter_vec_with_registry!(
                    "aframp_cache_hits_total",
                    "Total Redis cache hits by key prefix",
                    &["key_prefix"],
                    r
                )
                .unwrap(),
            )
            .ok();

        CACHE_MISSES_TOTAL
            .set(
                register_counter_vec_with_registry!(
                    "aframp_cache_misses_total",
                    "Total Redis cache misses by key prefix",
                    &["key_prefix"],
                    r
                )
                .unwrap(),
            )
            .ok();

        CACHE_OPERATION_DURATION_SECONDS
            .set(
                register_histogram_vec_with_registry!(
                    "aframp_cache_operation_duration_seconds",
                    "Redis cache operation duration in seconds",
                    &["operation"],
                    vec![0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5],
                    r
                )
                .unwrap(),
            )
            .ok();
    }
}

// ---------------------------------------------------------------------------
// Database metrics
// ---------------------------------------------------------------------------

pub mod database {
    use super::*;

    static DB_QUERY_DURATION_SECONDS: OnceLock<HistogramVec> = OnceLock::new();
    static DB_CONNECTIONS_ACTIVE: OnceLock<GaugeVec> = OnceLock::new();
    static DB_ERRORS_TOTAL: OnceLock<CounterVec> = OnceLock::new();

    pub fn query_duration_seconds() -> &'static HistogramVec {
        DB_QUERY_DURATION_SECONDS
            .get()
            .expect("metrics not initialised")
    }

    pub fn connections_active() -> &'static GaugeVec {
        DB_CONNECTIONS_ACTIVE
            .get()
            .expect("metrics not initialised")
    }

    pub fn errors_total() -> &'static CounterVec {
        DB_ERRORS_TOTAL.get().expect("metrics not initialised")
    }

    pub(super) fn register(r: &Registry) {
        DB_QUERY_DURATION_SECONDS
            .set(
                register_histogram_vec_with_registry!(
                    "aframp_db_query_duration_seconds",
                    "Database query duration in seconds",
                    &["query_type", "table"],
                    vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 5.0],
                    r
                )
                .unwrap(),
            )
            .ok();

        DB_CONNECTIONS_ACTIVE
            .set(
                register_gauge_vec_with_registry!(
                    "aframp_db_connections_active",
                    "Active database connections in the pool",
                    &["pool"],
                    r
                )
                .unwrap(),
            )
            .ok();

        DB_ERRORS_TOTAL
            .set(
                register_counter_vec_with_registry!(
                    "aframp_db_errors_total",
                    "Total database errors by error type",
                    &["error_type"],
                    r
                )
                .unwrap(),
            )
            .ok();
    }
}

// ---------------------------------------------------------------------------
// Security metrics
// Security / replay-prevention metrics  (Issue #141)
// ---------------------------------------------------------------------------

pub mod security {
    use super::*;

    static REQUEST_ANOMALY_FLAGS_TOTAL: OnceLock<CounterVec> = OnceLock::new();

    pub fn request_anomaly_flags_total() -> &'static CounterVec {
        REQUEST_ANOMALY_FLAGS_TOTAL
            .get()
            .expect("metrics not initialised")
    }

    static REPLAY_ATTEMPTS_TOTAL: OnceLock<CounterVec> = OnceLock::new();
    static TIMESTAMP_REJECTIONS_TOTAL: OnceLock<CounterVec> = OnceLock::new();
    static TIMESTAMP_DELTA_SECONDS: OnceLock<HistogramVec> = OnceLock::new();

    /// Increment when a replay is detected (nonce already seen).
    pub fn replay_attempts_total() -> &'static CounterVec {
        REPLAY_ATTEMPTS_TOTAL
            .get()
            .expect("metrics not initialised")
    }

    /// Increment when a request is rejected due to clock skew.
    pub fn timestamp_rejections_total() -> &'static CounterVec {
        TIMESTAMP_REJECTIONS_TOTAL
            .get()
            .expect("metrics not initialised")
    }

    /// Histogram of |server_time − request_timestamp| for valid requests.
    pub fn timestamp_delta_seconds() -> &'static HistogramVec {
        TIMESTAMP_DELTA_SECONDS
            .get()
            .expect("metrics not initialised")
    }

    pub(super) fn register(r: &Registry) {
        REQUEST_ANOMALY_FLAGS_TOTAL
            .set(
                register_counter_vec_with_registry!(
                    "aframp_request_anomaly_flags_total",
                    "Total non-blocking request anomaly flags by consumer, endpoint, and field",
                    &["consumer_id", "endpoint", "field"],
                    r
                )
                .unwrap(),
            )
            .ok();

        REPLAY_ATTEMPTS_TOTAL
            .set(
                register_counter_vec_with_registry!(
                    "aframp_security_replay_attempts_total",
                    "Total replay attempts detected, labelled by consumer_id and endpoint",
                    &["consumer_id", "endpoint"],
                    r
                )
                .unwrap(),
            )
            .ok();

        TIMESTAMP_REJECTIONS_TOTAL
            .set(
                register_counter_vec_with_registry!(
                    "aframp_security_timestamp_rejections_total",
                    "Total requests rejected due to timestamp clock skew",
                    &["consumer_id", "reason"],
                    r
                )
                .unwrap(),
            )
            .ok();

        TIMESTAMP_DELTA_SECONDS
            .set(
                register_histogram_vec_with_registry!(
                    "aframp_security_timestamp_delta_seconds",
                    "Distribution of |server_time - request_timestamp| for accepted requests",
                    &["consumer_id"],
                    vec![0.5, 1.0, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0],
                    r
                )
                .unwrap(),
            )
            .ok();
    }
}

// ---------------------------------------------------------------------------
// IP Detection & Blocking metrics (Issue #166)
// ---------------------------------------------------------------------------

pub mod ip_detection {
    use super::*;

    static IP_FLAGGED_TOTAL: OnceLock<CounterVec> = OnceLock::new();
    static IP_BLOCKS_APPLIED_TOTAL: OnceLock<CounterVec> = OnceLock::new();
    static IP_SHADOW_BLOCKS_APPLIED_TOTAL: OnceLock<CounterVec> = OnceLock::new();
    static IP_BLOCK_ENFORCEMENT_TOTAL: OnceLock<CounterVec> = OnceLock::new();
    static IP_AUTOMATED_BLOCKING_RATE: OnceLock<GaugeVec> = OnceLock::new();

    pub fn ip_flagged_total() -> &'static CounterVec {
        IP_FLAGGED_TOTAL.get().expect("metrics not initialised")
    }

    pub fn ip_blocks_applied_total() -> &'static CounterVec {
        IP_BLOCKS_APPLIED_TOTAL.get().expect("metrics not initialised")
    }

    pub fn ip_shadow_blocks_applied_total() -> &'static CounterVec {
        IP_SHADOW_BLOCKS_APPLIED_TOTAL.get().expect("metrics not initialised")
    }

    pub fn ip_block_enforcement_total() -> &'static CounterVec {
        IP_BLOCK_ENFORCEMENT_TOTAL.get().expect("metrics not initialised")
    }

    pub fn ip_automated_blocking_rate() -> &'static GaugeVec {
        IP_AUTOMATED_BLOCKING_RATE.get().expect("metrics not initialised")
    }

    pub(super) fn register(r: &Registry) {
        IP_FLAGGED_TOTAL
            .set(
                register_counter_vec_with_registry!(
                    "aframp_ip_flagged_total",
                    "Total IPs flagged by detection source",
                    &["detection_source", "evidence_type"],
                    r
                )
                .unwrap(),
            )
            .ok();

        IP_BLOCKS_APPLIED_TOTAL
            .set(
                register_counter_vec_with_registry!(
                    "aframp_ip_blocks_applied_total",
                    "Total IP blocks applied by block type",
                    &["block_type"],
                    r
                )
                .unwrap(),
            )
            .ok();

        IP_SHADOW_BLOCKS_APPLIED_TOTAL
            .set(
                register_counter_vec_with_registry!(
                    "aframp_ip_shadow_blocks_applied_total",
                    "Total IP shadow blocks applied",
                    &[],
                    r
                )
                .unwrap(),
            )
            .ok();

        IP_BLOCK_ENFORCEMENT_TOTAL
            .set(
                register_counter_vec_with_registry!(
                    "aframp_ip_block_enforcement_total",
                    "Total IP block enforcement events by endpoint and block type",
                    &["endpoint", "block_type"],
                    r
                )
                .unwrap(),
            )
            .ok();

        IP_AUTOMATED_BLOCKING_RATE
            .set(
                register_gauge_vec_with_registry!(
                    "aframp_ip_automated_blocking_rate",
                    "Rate of automated IP blocking per minute in the last 5 minutes",
                    &[],
                    r
                )
                .unwrap(),
            )
            .ok();
    }
}

// ---------------------------------------------------------------------------
// Alerting-specific metrics (Issue #111)
//
// These metrics are consumed directly by Prometheus alert rules and are not
// derived from existing counters/histograms. They expose state that cannot
// be computed from rate() expressions alone.
// ---------------------------------------------------------------------------

pub mod alerting {
    use super::*;
    use prometheus::{register_counter_vec_with_registry, register_gauge_vec_with_registry};

    /// Gauge: Unix timestamp (seconds) of the last successful exchange rate
    /// update per currency pair. Alert rules compute staleness as
    /// `time() - aframp_exchange_rate_last_updated_timestamp_seconds`.
    static EXCHANGE_RATE_LAST_UPDATED: OnceLock<GaugeVec> = OnceLock::new();

    /// Gauge: Unix timestamp (seconds) of the last completed worker cycle.
    /// Alert rules compute missed-cycle age as
    /// `time() - aframp_worker_last_cycle_timestamp_seconds`.
    static WORKER_LAST_CYCLE_TIMESTAMP: OnceLock<GaugeVec> = OnceLock::new();

    /// Gauge: Number of transactions currently in a pending state that have
    /// exceeded the configured processing timeout.
    static PENDING_TRANSACTIONS_STALE: OnceLock<GaugeVec> = OnceLock::new();

    /// Counter: Total rate-limit breaches (HTTP 429 responses) by endpoint.
    static RATE_LIMIT_BREACHES_TOTAL: OnceLock<CounterVec> = OnceLock::new();

    pub fn exchange_rate_last_updated() -> &'static GaugeVec {
        EXCHANGE_RATE_LAST_UPDATED
            .get()
            .expect("alerting metrics not initialised")
    }

    pub fn worker_last_cycle_timestamp() -> &'static GaugeVec {
        WORKER_LAST_CYCLE_TIMESTAMP
            .get()
            .expect("alerting metrics not initialised")
    }

    pub fn pending_transactions_stale() -> &'static GaugeVec {
        PENDING_TRANSACTIONS_STALE
            .get()
            .expect("alerting metrics not initialised")
    }

    pub fn rate_limit_breaches_total() -> &'static CounterVec {
        RATE_LIMIT_BREACHES_TOTAL
            .get()
            .expect("alerting metrics not initialised")
    }

    pub(super) fn register(r: &Registry) {
        EXCHANGE_RATE_LAST_UPDATED
            .set(
                register_gauge_vec_with_registry!(
                    "aframp_exchange_rate_last_updated_timestamp_seconds",
                    "Unix timestamp of the last successful exchange rate update per currency pair",
                    &["currency_pair"],
                    r
                )
                .unwrap(),
            )
            .ok();

        WORKER_LAST_CYCLE_TIMESTAMP
            .set(
                register_gauge_vec_with_registry!(
                    "aframp_worker_last_cycle_timestamp_seconds",
                    "Unix timestamp of the last completed worker cycle",
                    &["worker"],
                    r
                )
                .unwrap(),
            )
            .ok();

        PENDING_TRANSACTIONS_STALE
            .set(
                register_gauge_vec_with_registry!(
                    "aframp_pending_transactions_stale_total",
                    "Number of pending transactions that have exceeded the processing timeout",
                    &["tx_type"],
                    r
                )
                .unwrap(),
            )
            .ok();

        RATE_LIMIT_BREACHES_TOTAL
            .set(
                register_counter_vec_with_registry!(
                    "aframp_rate_limit_breaches_total",
                    "Total rate-limit breaches (HTTP 429 responses) by endpoint",
                    &["endpoint"],
                    r
                )
                .unwrap(),
            )
            .ok();
    }
}

// ---------------------------------------------------------------------------
// Register all metrics
// ---------------------------------------------------------------------------

fn register_all(r: &Registry) {
    http::register(r);
    cngn::register(r);
    payment::register(r);
    stellar::register(r);
    worker::register(r);
    cache::register(r);
    database::register(r);
    security::register(r);
    ip_detection::register(r);
    alerting::register(r);
    crate::ddos::metrics::register(r);
    crate::crypto::metrics::register(r);
    crate::key_management::metrics::register(r);
    crate::pentest::metrics::register(r);
    crate::masking::metrics::register(r);
    crate::gateway::metrics::register(r);
    #[cfg(feature = "database")]
}

// ---------------------------------------------------------------------------
// Helper: extract key prefix from a Redis key (first colon-delimited segment)
// ---------------------------------------------------------------------------

pub fn key_prefix(key: &str) -> &str {
    key.find(':').map(|i| &key[..i]).unwrap_or(key)
}
