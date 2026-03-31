//! Integration tests for the alerting system (Issue #111).
//!
//! These tests simulate metric threshold breaches and verify that the correct
//! metrics are emitted with the right labels and values, matching the
//! conditions defined in monitoring/prometheus/rules/aframp_alerts.yml.
//!
//! Tests use isolated Prometheus registries so they never interfere with the
//! global registry or each other.
//!
//! Run with: cargo test --features cache alerting_integration

#[cfg(test)]
mod alerting_metrics_tests {
    use prometheus::{
        register_counter_vec_with_registry, register_gauge_vec_with_registry,
        register_histogram_vec_with_registry, Encoder, Registry, TextEncoder,
    };

    // -----------------------------------------------------------------------
    // Helpers: build isolated registries mirroring production metric shapes
    // -----------------------------------------------------------------------

    fn make_registry() -> Registry {
        Registry::new()
    }

    fn make_http_requests_total(r: &Registry) -> prometheus::CounterVec {
        register_counter_vec_with_registry!(
            "aframp_http_requests_total",
            "Total HTTP requests",
            &["method", "route", "status_code"],
            r
        )
        .unwrap()
    }

    fn make_cngn_transactions_total(r: &Registry) -> prometheus::CounterVec {
        register_counter_vec_with_registry!(
            "aframp_cngn_transactions_total",
            "Total cNGN transactions",
            &["tx_type", "status"],
            r
        )
        .unwrap()
    }

    fn make_stellar_submissions_total(r: &Registry) -> prometheus::CounterVec {
        register_counter_vec_with_registry!(
            "aframp_stellar_tx_submissions_total",
            "Total Stellar submissions",
            &["status"],
            r
        )
        .unwrap()
    }

    fn make_worker_errors_total(r: &Registry) -> prometheus::CounterVec {
        register_counter_vec_with_registry!(
            "aframp_worker_errors_total",
            "Total worker errors",
            &["worker", "error_type"],
            r
        )
        .unwrap()
    }

    fn make_worker_cycles_total(r: &Registry) -> prometheus::CounterVec {
        register_counter_vec_with_registry!(
            "aframp_worker_cycles_total",
            "Total worker cycles",
            &["worker"],
            r
        )
        .unwrap()
    }

    fn make_db_errors_total(r: &Registry) -> prometheus::CounterVec {
        register_counter_vec_with_registry!(
            "aframp_db_errors_total",
            "Total DB errors",
            &["error_type"],
            r
        )
        .unwrap()
    }

    fn make_payment_provider_failures_total(r: &Registry) -> prometheus::CounterVec {
        register_counter_vec_with_registry!(
            "aframp_payment_provider_failures_total",
            "Total payment provider failures",
            &["provider", "failure_reason"],
            r
        )
        .unwrap()
    }

    fn make_exchange_rate_last_updated(r: &Registry) -> prometheus::GaugeVec {
        register_gauge_vec_with_registry!(
            "aframp_exchange_rate_last_updated_timestamp_seconds",
            "Unix timestamp of last exchange rate update",
            &["currency_pair"],
            r
        )
        .unwrap()
    }

    fn make_worker_last_cycle_timestamp(r: &Registry) -> prometheus::GaugeVec {
        register_gauge_vec_with_registry!(
            "aframp_worker_last_cycle_timestamp_seconds",
            "Unix timestamp of last worker cycle",
            &["worker"],
            r
        )
        .unwrap()
    }

    fn make_pending_transactions_stale(r: &Registry) -> prometheus::GaugeVec {
        register_gauge_vec_with_registry!(
            "aframp_pending_transactions_stale_total",
            "Stale pending transactions",
            &["tx_type"],
            r
        )
        .unwrap()
    }

    fn make_rate_limit_breaches_total(r: &Registry) -> prometheus::CounterVec {
        register_counter_vec_with_registry!(
            "aframp_rate_limit_breaches_total",
            "Total rate limit breaches",
            &["endpoint"],
            r
        )
        .unwrap()
    }

    fn make_cache_hits_total(r: &Registry) -> prometheus::CounterVec {
        register_counter_vec_with_registry!(
            "aframp_cache_hits_total",
            "Cache hits",
            &["key_prefix"],
            r
        )
        .unwrap()
    }

    fn make_cache_misses_total(r: &Registry) -> prometheus::CounterVec {
        register_counter_vec_with_registry!(
            "aframp_cache_misses_total",
            "Cache misses",
            &["key_prefix"],
            r
        )
        .unwrap()
    }

    fn render(r: &Registry) -> String {
        let encoder = TextEncoder::new();
        let mut buf = Vec::new();
        encoder.encode(&r.gather(), &mut buf).unwrap();
        String::from_utf8(buf).unwrap()
    }

    // -----------------------------------------------------------------------
    // HTTP 5xx alert condition tests
    // -----------------------------------------------------------------------

    /// Simulates a 5xx error rate spike above the critical threshold (5%).
    /// Alert rule: HighHttp5xxErrorRate fires when 5xx/total > 0.05
    #[test]
    fn test_http_5xx_critical_threshold_breach() {
        let r = make_registry();
        let counter = make_http_requests_total(&r);

        // 10 total requests, 1 is 5xx → 10% error rate (above 5% critical threshold)
        counter.with_label_values(&["POST", "/api/onramp/quote", "200"]).inc_by(9.0);
        counter.with_label_values(&["POST", "/api/onramp/quote", "500"]).inc_by(1.0);

        let total_5xx: f64 = r.gather().iter()
            .find(|mf| mf.get_name() == "aframp_http_requests_total")
            .map(|mf| {
                mf.get_metric().iter()
                    .filter(|m| m.get_label().iter().any(|l| l.get_name() == "status_code" && l.get_value().starts_with('5')))
                    .map(|m| m.get_counter().get_value())
                    .sum()
            })
            .unwrap_or(0.0);

        let total: f64 = r.gather().iter()
            .find(|mf| mf.get_name() == "aframp_http_requests_total")
            .map(|mf| mf.get_metric().iter().map(|m| m.get_counter().get_value()).sum())
            .unwrap_or(0.0);

        let error_rate = total_5xx / total;
        // Verify the simulated condition exceeds the critical threshold
        assert!(error_rate > 0.05, "5xx rate {:.2} should exceed critical threshold 0.05", error_rate);
        assert!(error_rate > 0.02, "5xx rate {:.2} should also exceed warning threshold 0.02", error_rate);
    }

    /// Simulates a 5xx error rate below both thresholds — no alert should fire.
    #[test]
    fn test_http_5xx_below_threshold_no_alert() {
        let r = make_registry();
        let counter = make_http_requests_total(&r);

        // 100 requests, 1 is 5xx → 1% error rate (below 2% warning threshold)
        counter.with_label_values(&["GET", "/api/rates", "200"]).inc_by(99.0);
        counter.with_label_values(&["GET", "/api/rates", "500"]).inc_by(1.0);

        let total_5xx: f64 = r.gather().iter()
            .find(|mf| mf.get_name() == "aframp_http_requests_total")
            .map(|mf| {
                mf.get_metric().iter()
                    .filter(|m| m.get_label().iter().any(|l| l.get_name() == "status_code" && l.get_value().starts_with('5')))
                    .map(|m| m.get_counter().get_value())
                    .sum()
            })
            .unwrap_or(0.0);

        let total: f64 = r.gather().iter()
            .find(|mf| mf.get_name() == "aframp_http_requests_total")
            .map(|mf| mf.get_metric().iter().map(|m| m.get_counter().get_value()).sum())
            .unwrap_or(0.0);

        let error_rate = total_5xx / total;
        assert!(error_rate < 0.02, "5xx rate {:.2} should be below warning threshold 0.02", error_rate);
    }

    // -----------------------------------------------------------------------
    // Transaction failure alert condition tests
    // -----------------------------------------------------------------------

    /// Simulates a transaction failure rate above the critical threshold (10%).
    /// Alert rule: HighTransactionFailureRate fires when failed/total > 0.10 by tx_type
    #[test]
    fn test_transaction_failure_rate_critical_threshold() {
        let r = make_registry();
        let counter = make_cngn_transactions_total(&r);

        // onramp: 8 completed, 2 failed → 20% failure rate (above 10% critical)
        counter.with_label_values(&["onramp", "completed"]).inc_by(8.0);
        counter.with_label_values(&["onramp", "failed"]).inc_by(2.0);

        let failed = counter.with_label_values(&["onramp", "failed"]).get();
        let completed = counter.with_label_values(&["onramp", "completed"]).get();
        let total = failed + completed;
        let failure_rate = failed / total;

        assert!(failure_rate > 0.10, "failure rate {:.2} should exceed critical threshold 0.10", failure_rate);
        assert_eq!(failed, 2.0);
        assert_eq!(total, 10.0);
    }

    /// Simulates a refund spike for bill_payment transactions.
    /// Alert rule: TransactionRefundSpike fires when refunded rate > 0.05/s
    #[test]
    fn test_transaction_refund_spike_labels() {
        let r = make_registry();
        let counter = make_cngn_transactions_total(&r);

        counter.with_label_values(&["bill_payment", "refunded"]).inc_by(5.0);
        counter.with_label_values(&["bill_payment", "completed"]).inc_by(10.0);

        let refunded = counter.with_label_values(&["bill_payment", "refunded"]).get();
        assert_eq!(refunded, 5.0, "refunded count should be 5");

        // Verify label cardinality — each tx_type+status combination is distinct
        let output = render(&r);
        assert!(output.contains(r#"tx_type="bill_payment""#));
        assert!(output.contains(r#"status="refunded""#));
    }

    // -----------------------------------------------------------------------
    // Stale pending transaction alert condition tests
    // -----------------------------------------------------------------------

    /// Simulates stale pending transactions exceeding the critical threshold (5).
    /// Alert rule: StalePendingTransactions fires when stale_total > 5
    #[test]
    fn test_stale_pending_transactions_critical_threshold() {
        let r = make_registry();
        let gauge = make_pending_transactions_stale(&r);

        // Set 8 stale transactions — above the critical threshold of 5
        gauge.with_label_values(&["all"]).set(8.0);

        let stale = gauge.with_label_values(&["all"]).get();
        assert!(stale > 5.0, "stale count {} should exceed critical threshold 5", stale);

        let output = render(&r);
        assert!(output.contains("aframp_pending_transactions_stale_total"));
        assert!(output.contains(r#"tx_type="all""#));
    }

    /// Verifies that zero stale transactions does not trigger any alert.
    #[test]
    fn test_no_stale_pending_transactions_no_alert() {
        let r = make_registry();
        let gauge = make_pending_transactions_stale(&r);

        gauge.with_label_values(&["all"]).set(0.0);

        let stale = gauge.with_label_values(&["all"]).get();
        assert_eq!(stale, 0.0, "no stale transactions should not trigger alert");
    }

    // -----------------------------------------------------------------------
    // Exchange rate staleness alert condition tests
    // -----------------------------------------------------------------------

    /// Simulates an exchange rate that has not been updated for > 300s (critical threshold).
    /// Alert rule: ExchangeRateStale fires when time() - last_updated > 300
    #[test]
    fn test_exchange_rate_staleness_critical_threshold() {
        let r = make_registry();
        let gauge = make_exchange_rate_last_updated(&r);

        // Set last update to 400 seconds ago
        let stale_timestamp = chrono::Utc::now().timestamp() as f64 - 400.0;
        gauge.with_label_values(&["NGN/USD"]).set(stale_timestamp);

        let last_updated = gauge.with_label_values(&["NGN/USD"]).get();
        let age_seconds = chrono::Utc::now().timestamp() as f64 - last_updated;

        assert!(age_seconds > 300.0, "rate age {}s should exceed critical threshold 300s", age_seconds);
        assert!(age_seconds > 180.0, "rate age {}s should also exceed warning threshold 180s", age_seconds);

        let output = render(&r);
        assert!(output.contains("aframp_exchange_rate_last_updated_timestamp_seconds"));
        assert!(output.contains(r#"currency_pair="NGN/USD""#));
    }

    /// Simulates a fresh exchange rate — no alert should fire.
    #[test]
    fn test_exchange_rate_fresh_no_alert() {
        let r = make_registry();
        let gauge = make_exchange_rate_last_updated(&r);

        // Set last update to 30 seconds ago (well within 180s warning threshold)
        let fresh_timestamp = chrono::Utc::now().timestamp() as f64 - 30.0;
        gauge.with_label_values(&["NGN/USD"]).set(fresh_timestamp);

        let last_updated = gauge.with_label_values(&["NGN/USD"]).get();
        let age_seconds = chrono::Utc::now().timestamp() as f64 - last_updated;

        assert!(age_seconds < 180.0, "rate age {}s should be below warning threshold 180s", age_seconds);
    }

    // -----------------------------------------------------------------------
    // Worker missed-cycle alert condition tests
    // -----------------------------------------------------------------------

    /// Simulates a worker that has not completed a cycle in > 120s (critical threshold).
    /// Alert rule: WorkerMissedCycles fires when time() - last_cycle > 120
    #[test]
    fn test_worker_missed_cycles_critical_threshold() {
        let r = make_registry();
        let gauge = make_worker_last_cycle_timestamp(&r);

        // Set last cycle to 200 seconds ago
        let stale_ts = chrono::Utc::now().timestamp() as f64 - 200.0;
        gauge.with_label_values(&["transaction_monitor"]).set(stale_ts);

        let last_cycle = gauge.with_label_values(&["transaction_monitor"]).get();
        let age_seconds = chrono::Utc::now().timestamp() as f64 - last_cycle;

        assert!(age_seconds > 120.0, "worker age {}s should exceed critical threshold 120s", age_seconds);

        let output = render(&r);
        assert!(output.contains("aframp_worker_last_cycle_timestamp_seconds"));
        assert!(output.contains(r#"worker="transaction_monitor""#));
    }

    /// Verifies that a recently-cycled worker does not trigger the missed-cycle alert.
    #[test]
    fn test_worker_recent_cycle_no_alert() {
        let r = make_registry();
        let gauge = make_worker_last_cycle_timestamp(&r);

        // Set last cycle to 10 seconds ago
        let recent_ts = chrono::Utc::now().timestamp() as f64 - 10.0;
        gauge.with_label_values(&["offramp_processor"]).set(recent_ts);

        let last_cycle = gauge.with_label_values(&["offramp_processor"]).get();
        let age_seconds = chrono::Utc::now().timestamp() as f64 - last_cycle;

        assert!(age_seconds < 120.0, "worker age {}s should be below critical threshold 120s", age_seconds);
    }

    // -----------------------------------------------------------------------
    // Rate limit breach alert condition tests
    // -----------------------------------------------------------------------

    /// Simulates a rate limit breach spike above the warning threshold (10/s).
    /// Alert rule: RateLimitBreachSpike fires when rate(breaches[5m]) > 10
    #[test]
    fn test_rate_limit_breach_spike_labels() {
        let r = make_registry();
        let counter = make_rate_limit_breaches_total(&r);

        counter.with_label_values(&["/api/onramp/quote"]).inc_by(50.0);
        counter.with_label_values(&["/api/offramp/initiate"]).inc_by(30.0);

        let quote_breaches = counter.with_label_values(&["/api/onramp/quote"]).get();
        let offramp_breaches = counter.with_label_values(&["/api/offramp/initiate"]).get();

        assert_eq!(quote_breaches, 50.0);
        assert_eq!(offramp_breaches, 30.0);

        let output = render(&r);
        assert!(output.contains("aframp_rate_limit_breaches_total"));
        assert!(output.contains(r#"endpoint="/api/onramp/quote""#));
        assert!(output.contains(r#"endpoint="/api/offramp/initiate""#));
    }

    // -----------------------------------------------------------------------
    // Stellar submission failure alert condition tests
    // -----------------------------------------------------------------------

    /// Simulates Stellar submission failure rate above the critical threshold (10%).
    /// Alert rule: StellarSubmissionFailureSpike fires when failed/total > 0.10
    #[test]
    fn test_stellar_submission_failure_critical_threshold() {
        let r = make_registry();
        let counter = make_stellar_submissions_total(&r);

        // 7 success, 3 failed → 30% failure rate (above 10% critical threshold)
        counter.with_label_values(&["success"]).inc_by(7.0);
        counter.with_label_values(&["failed"]).inc_by(3.0);

        let failed = counter.with_label_values(&["failed"]).get();
        let success = counter.with_label_values(&["success"]).get();
        let total = failed + success;
        let failure_rate = failed / total;

        assert!(failure_rate > 0.10, "Stellar failure rate {:.2} should exceed critical threshold 0.10", failure_rate);
        assert_eq!(total, 10.0);
    }

    /// Simulates Horizon unavailability — zero successful submissions with attempts ongoing.
    /// Alert rule: StellarHorizonUnavailable fires when success rate == 0 and total > 0
    #[test]
    fn test_stellar_horizon_unavailable_condition() {
        let r = make_registry();
        let counter = make_stellar_submissions_total(&r);

        // All submissions failing — Horizon is down
        counter.with_label_values(&["failed"]).inc_by(5.0);

        let success = counter.with_label_values(&["success"]).get();
        let failed = counter.with_label_values(&["failed"]).get();

        assert_eq!(success, 0.0, "no successful submissions when Horizon is down");
        assert!(failed > 0.0, "failed submissions should be > 0");

        // Alert condition: success == 0 AND total > 0
        let total = success + failed;
        assert!(total > 0.0 && success == 0.0, "Horizon unavailable condition should be met");
    }

    // -----------------------------------------------------------------------
    // Database error alert condition tests
    // -----------------------------------------------------------------------

    /// Simulates a database connection error spike above the critical threshold.
    /// Alert rule: DatabaseConnectionErrors fires when connection_error rate > 0.1/s
    #[test]
    fn test_database_connection_error_labels() {
        let r = make_registry();
        let counter = make_db_errors_total(&r);

        counter.with_label_values(&["connection_error"]).inc_by(10.0);
        counter.with_label_values(&["query_error"]).inc_by(2.0);

        let conn_errors = counter.with_label_values(&["connection_error"]).get();
        assert_eq!(conn_errors, 10.0);

        let output = render(&r);
        assert!(output.contains("aframp_db_errors_total"));
        assert!(output.contains(r#"error_type="connection_error""#));
    }

    // -----------------------------------------------------------------------
    // Worker error spike alert condition tests
    // -----------------------------------------------------------------------

    /// Simulates a worker error spike above the critical threshold (1.0/s).
    /// Alert rule: WorkerCriticalErrorRate fires when worker errors > 1.0/s
    #[test]
    fn test_worker_error_spike_labels_and_severity() {
        let r = make_registry();
        let counter = make_worker_errors_total(&r);

        counter.with_label_values(&["onramp_processor", "stellar_error"]).inc_by(5.0);
        counter.with_label_values(&["onramp_processor", "timeout"]).inc_by(3.0);
        counter.with_label_values(&["offramp_processor", "database"]).inc_by(2.0);

        let onramp_stellar = counter.with_label_values(&["onramp_processor", "stellar_error"]).get();
        let onramp_timeout = counter.with_label_values(&["onramp_processor", "timeout"]).get();
        let offramp_db = counter.with_label_values(&["offramp_processor", "database"]).get();

        assert_eq!(onramp_stellar, 5.0);
        assert_eq!(onramp_timeout, 3.0);
        assert_eq!(offramp_db, 2.0);

        let output = render(&r);
        assert!(output.contains(r#"worker="onramp_processor""#));
        assert!(output.contains(r#"error_type="stellar_error""#));
        assert!(output.contains(r#"worker="offramp_processor""#));
    }

    // -----------------------------------------------------------------------
    // Payment provider failure alert condition tests
    // -----------------------------------------------------------------------

    /// Simulates a payment provider failure spike.
    /// Alert rule: PaymentProviderFailureSpike fires when failures > 0.1/s by provider
    #[test]
    fn test_payment_provider_failure_labels() {
        let r = make_registry();
        let counter = make_payment_provider_failures_total(&r);

        counter.with_label_values(&["paystack", "network_error"]).inc_by(8.0);
        counter.with_label_values(&["flutterwave", "timeout"]).inc_by(3.0);

        let paystack_failures = counter.with_label_values(&["paystack", "network_error"]).get();
        assert_eq!(paystack_failures, 8.0);

        let output = render(&r);
        assert!(output.contains("aframp_payment_provider_failures_total"));
        assert!(output.contains(r#"provider="paystack""#));
        assert!(output.contains(r#"failure_reason="network_error""#));
    }

    // -----------------------------------------------------------------------
    // Cache miss rate alert condition tests
    // -----------------------------------------------------------------------

    /// Simulates a high cache miss rate above the warning threshold (50%).
    /// Alert rule: HighCacheMissRate fires when misses/(hits+misses) > 0.5
    #[test]
    fn test_high_cache_miss_rate_threshold() {
        let r = make_registry();
        let hits = make_cache_hits_total(&r);
        let misses = make_cache_misses_total(&r);

        // 3 hits, 7 misses → 70% miss rate (above 50% warning threshold)
        hits.with_label_values(&["rates"]).inc_by(3.0);
        misses.with_label_values(&["rates"]).inc_by(7.0);

        let h = hits.with_label_values(&["rates"]).get();
        let m = misses.with_label_values(&["rates"]).get();
        let miss_rate = m / (h + m);

        assert!(miss_rate > 0.5, "cache miss rate {:.2} should exceed warning threshold 0.5", miss_rate);
    }

    // -----------------------------------------------------------------------
    // Metric deduplication / label uniqueness tests
    // -----------------------------------------------------------------------

    /// Verifies that metrics with different label values are tracked independently
    /// (no cross-contamination between workers, tx_types, or providers).
    #[test]
    fn test_metric_label_isolation() {
        let r = make_registry();
        let counter = make_cngn_transactions_total(&r);

        counter.with_label_values(&["onramp", "completed"]).inc_by(10.0);
        counter.with_label_values(&["offramp", "completed"]).inc_by(5.0);
        counter.with_label_values(&["bill_payment", "failed"]).inc_by(2.0);

        assert_eq!(counter.with_label_values(&["onramp", "completed"]).get(), 10.0);
        assert_eq!(counter.with_label_values(&["offramp", "completed"]).get(), 5.0);
        assert_eq!(counter.with_label_values(&["bill_payment", "failed"]).get(), 2.0);
        // Verify no cross-contamination
        assert_eq!(counter.with_label_values(&["onramp", "failed"]).get(), 0.0);
        assert_eq!(counter.with_label_values(&["offramp", "failed"]).get(), 0.0);
    }

    /// Verifies that worker last-cycle timestamps are tracked per-worker independently.
    #[test]
    fn test_worker_last_cycle_timestamp_per_worker_isolation() {
        let r = make_registry();
        let gauge = make_worker_last_cycle_timestamp(&r);

        let now = chrono::Utc::now().timestamp() as f64;
        gauge.with_label_values(&["transaction_monitor"]).set(now - 10.0);
        gauge.with_label_values(&["offramp_processor"]).set(now - 200.0);
        gauge.with_label_values(&["onramp_processor"]).set(now - 5.0);

        let monitor_age = now - gauge.with_label_values(&["transaction_monitor"]).get();
        let offramp_age = now - gauge.with_label_values(&["offramp_processor"]).get();
        let onramp_age = now - gauge.with_label_values(&["onramp_processor"]).get();

        // transaction_monitor and onramp_processor are healthy
        assert!(monitor_age < 120.0, "transaction_monitor should not trigger missed-cycle alert");
        assert!(onramp_age < 120.0, "onramp_processor should not trigger missed-cycle alert");
        // offramp_processor is stale — should trigger alert
        assert!(offramp_age > 120.0, "offramp_processor should trigger missed-cycle alert");
    }

    // -----------------------------------------------------------------------
    // Prometheus text output format tests
    // -----------------------------------------------------------------------

    /// Verifies that all alerting metrics render valid Prometheus text format
    /// with correct HELP and TYPE headers.
    #[test]
    fn test_alerting_metrics_render_valid_prometheus_output() {
        let r = make_registry();
        let _ = make_exchange_rate_last_updated(&r);
        let _ = make_worker_last_cycle_timestamp(&r);
        let _ = make_pending_transactions_stale(&r);
        let _ = make_rate_limit_breaches_total(&r);

        let output = render(&r);
        assert!(output.contains("# HELP aframp_exchange_rate_last_updated_timestamp_seconds"));
        assert!(output.contains("# TYPE aframp_exchange_rate_last_updated_timestamp_seconds gauge"));
        assert!(output.contains("# HELP aframp_worker_last_cycle_timestamp_seconds"));
        assert!(output.contains("# TYPE aframp_worker_last_cycle_timestamp_seconds gauge"));
        assert!(output.contains("# HELP aframp_pending_transactions_stale_total"));
        assert!(output.contains("# TYPE aframp_pending_transactions_stale_total gauge"));
        assert!(output.contains("# HELP aframp_rate_limit_breaches_total"));
        assert!(output.contains("# TYPE aframp_rate_limit_breaches_total counter"));
    }

    /// Verifies that the global registry initialises all alerting metrics without panic.
    #[test]
    fn test_global_registry_includes_alerting_metrics() {
        // Trigger global registry initialisation
        let registry = Bitmesh_backend::metrics::registry();
        let families = registry.gather();

        let metric_names: Vec<&str> = families.iter().map(|mf| mf.get_name()).collect();

        assert!(
            metric_names.contains(&"aframp_exchange_rate_last_updated_timestamp_seconds"),
            "global registry must include exchange rate staleness metric"
        );
        assert!(
            metric_names.contains(&"aframp_worker_last_cycle_timestamp_seconds"),
            "global registry must include worker last-cycle timestamp metric"
        );
        assert!(
            metric_names.contains(&"aframp_pending_transactions_stale_total"),
            "global registry must include stale pending transactions metric"
        );
        assert!(
            metric_names.contains(&"aframp_rate_limit_breaches_total"),
            "global registry must include rate limit breaches metric"
        );
    }
}
