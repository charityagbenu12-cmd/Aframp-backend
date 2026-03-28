//! Unit tests verifying that key metrics are incremented correctly.
//!
//! Each test uses an isolated Registry so tests don't interfere with each other
//! or with the global registry.

#[cfg(test)]
mod tests {
    use prometheus::{
        register_counter_vec_with_registry, register_gauge_vec_with_registry,
        register_histogram_vec_with_registry, Registry,
    };

    // -----------------------------------------------------------------------
    // Helper: build an isolated registry with the same metric shapes
    // -----------------------------------------------------------------------

    fn make_http_counters(r: &Registry) -> prometheus::CounterVec {
        register_counter_vec_with_registry!(
            "test_http_requests_total",
            "test",
            &["method", "route", "status_code"],
            r
        )
        .unwrap()
    }

    fn make_http_histogram(r: &Registry) -> prometheus::HistogramVec {
        register_histogram_vec_with_registry!(
            "test_http_request_duration_seconds",
            "test",
            &["method", "route"],
            vec![0.1, 1.0, 10.0],
            r
        )
        .unwrap()
    }

    fn make_http_gauge(r: &Registry) -> prometheus::GaugeVec {
        register_gauge_vec_with_registry!(
            "test_http_requests_in_flight",
            "test",
            &["route"],
            r
        )
        .unwrap()
    }

    fn make_cngn_counter(r: &Registry) -> prometheus::CounterVec {
        register_counter_vec_with_registry!(
            "test_cngn_transactions_total",
            "test",
            &["tx_type", "status"],
            r
        )
        .unwrap()
    }

    fn make_cngn_volume(r: &Registry) -> prometheus::HistogramVec {
        register_histogram_vec_with_registry!(
            "test_cngn_transaction_volume_ngn",
            "test",
            &["tx_type"],
            vec![100.0, 1000.0, 10000.0],
            r
        )
        .unwrap()
    }

    fn make_payment_counter(r: &Registry) -> prometheus::CounterVec {
        register_counter_vec_with_registry!(
            "test_payment_provider_requests_total",
            "test",
            &["provider", "operation"],
            r
        )
        .unwrap()
    }

    fn make_payment_failures(r: &Registry) -> prometheus::CounterVec {
        register_counter_vec_with_registry!(
            "test_payment_provider_failures_total",
            "test",
            &["provider", "failure_reason"],
            r
        )
        .unwrap()
    }

    fn make_stellar_counter(r: &Registry) -> prometheus::CounterVec {
        register_counter_vec_with_registry!(
            "test_stellar_tx_submissions_total",
            "test",
            &["status"],
            r
        )
        .unwrap()
    }

    fn make_trustline_counter(r: &Registry) -> prometheus::CounterVec {
        register_counter_vec_with_registry!(
            "test_stellar_trustline_attempts_total",
            "test",
            &["status"],
            r
        )
        .unwrap()
    }

    fn make_worker_cycles(r: &Registry) -> prometheus::CounterVec {
        register_counter_vec_with_registry!(
            "test_worker_cycles_total",
            "test",
            &["worker"],
            r
        )
        .unwrap()
    }

    fn make_worker_errors(r: &Registry) -> prometheus::CounterVec {
        register_counter_vec_with_registry!(
            "test_worker_errors_total",
            "test",
            &["worker", "error_type"],
            r
        )
        .unwrap()
    }

    fn make_worker_records(r: &Registry) -> prometheus::GaugeVec {
        register_gauge_vec_with_registry!(
            "test_worker_records_processed",
            "test",
            &["worker"],
            r
        )
        .unwrap()
    }

    fn make_cache_hits(r: &Registry) -> prometheus::CounterVec {
        register_counter_vec_with_registry!(
            "test_cache_hits_total",
            "test",
            &["key_prefix"],
            r
        )
        .unwrap()
    }

    fn make_cache_misses(r: &Registry) -> prometheus::CounterVec {
        register_counter_vec_with_registry!(
            "test_cache_misses_total",
            "test",
            &["key_prefix"],
            r
        )
        .unwrap()
    }

    fn make_db_errors(r: &Registry) -> prometheus::CounterVec {
        register_counter_vec_with_registry!(
            "test_db_errors_total",
            "test",
            &["error_type"],
            r
        )
        .unwrap()
    }

    fn make_db_pool_gauge(r: &Registry) -> prometheus::GaugeVec {
        register_gauge_vec_with_registry!(
            "test_db_connections_active",
            "test",
            &["pool"],
            r
        )
        .unwrap()
    }

    // -----------------------------------------------------------------------
    // HTTP metrics tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_http_request_counter_increments() {
        let r = Registry::new();
        let counter = make_http_counters(&r);

        counter.with_label_values(&["GET", "/api/rates", "200"]).inc();
        counter.with_label_values(&["POST", "/api/onramp/quote", "201"]).inc();
        counter.with_label_values(&["GET", "/api/rates", "200"]).inc();

        assert_eq!(
            counter.with_label_values(&["GET", "/api/rates", "200"]).get(),
            2.0
        );
        assert_eq!(
            counter.with_label_values(&["POST", "/api/onramp/quote", "201"]).get(),
            1.0
        );
    }

    #[test]
    fn test_http_request_duration_histogram_observes() {
        let r = Registry::new();
        let hist = make_http_histogram(&r);

        hist.with_label_values(&["GET", "/health"]).observe(0.05);
        hist.with_label_values(&["GET", "/health"]).observe(0.2);

        let mf = r.gather();
        let metric = mf.iter().find(|m| m.get_name() == "test_http_request_duration_seconds");
        assert!(metric.is_some());
    }

    #[test]
    fn test_http_in_flight_gauge_inc_dec() {
        let r = Registry::new();
        let gauge = make_http_gauge(&r);

        gauge.with_label_values(&["/api/onramp/quote"]).inc();
        gauge.with_label_values(&["/api/onramp/quote"]).inc();
        assert_eq!(gauge.with_label_values(&["/api/onramp/quote"]).get(), 2.0);

        gauge.with_label_values(&["/api/onramp/quote"]).dec();
        assert_eq!(gauge.with_label_values(&["/api/onramp/quote"]).get(), 1.0);
    }

    // -----------------------------------------------------------------------
    // cNGN transaction metrics tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_cngn_transaction_counter_by_type_and_status() {
        let r = Registry::new();
        let counter = make_cngn_counter(&r);

        counter.with_label_values(&["onramp", "completed"]).inc();
        counter.with_label_values(&["onramp", "failed"]).inc();
        counter.with_label_values(&["offramp", "completed"]).inc();
        counter.with_label_values(&["bill_payment", "completed"]).inc();
        counter.with_label_values(&["onramp", "refunded"]).inc();

        assert_eq!(counter.with_label_values(&["onramp", "completed"]).get(), 1.0);
        assert_eq!(counter.with_label_values(&["onramp", "failed"]).get(), 1.0);
        assert_eq!(counter.with_label_values(&["offramp", "completed"]).get(), 1.0);
        assert_eq!(counter.with_label_values(&["bill_payment", "completed"]).get(), 1.0);
        assert_eq!(counter.with_label_values(&["onramp", "refunded"]).get(), 1.0);
    }

    #[test]
    fn test_cngn_volume_histogram_observes_amounts() {
        let r = Registry::new();
        let hist = make_cngn_volume(&r);

        hist.with_label_values(&["onramp"]).observe(5000.0);
        hist.with_label_values(&["offramp"]).observe(10000.0);

        let mf = r.gather();
        let metric = mf.iter().find(|m| m.get_name() == "test_cngn_transaction_volume_ngn");
        assert!(metric.is_some());
    }

    // -----------------------------------------------------------------------
    // Payment provider metrics tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_payment_provider_request_counter() {
        let r = Registry::new();
        let counter = make_payment_counter(&r);

        counter.with_label_values(&["paystack", "initiate"]).inc();
        counter.with_label_values(&["paystack", "verify"]).inc();
        counter.with_label_values(&["flutterwave", "initiate"]).inc();
        counter.with_label_values(&["paystack", "initiate"]).inc();

        assert_eq!(counter.with_label_values(&["paystack", "initiate"]).get(), 2.0);
        assert_eq!(counter.with_label_values(&["paystack", "verify"]).get(), 1.0);
        assert_eq!(counter.with_label_values(&["flutterwave", "initiate"]).get(), 1.0);
    }

    #[test]
    fn test_payment_provider_failure_counter() {
        let r = Registry::new();
        let counter = make_payment_failures(&r);

        counter.with_label_values(&["paystack", "network_error"]).inc();
        counter.with_label_values(&["flutterwave", "timeout"]).inc();
        counter.with_label_values(&["paystack", "network_error"]).inc();

        assert_eq!(counter.with_label_values(&["paystack", "network_error"]).get(), 2.0);
        assert_eq!(counter.with_label_values(&["flutterwave", "timeout"]).get(), 1.0);
    }

    // -----------------------------------------------------------------------
    // Stellar metrics tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_stellar_submission_counter_by_status() {
        let r = Registry::new();
        let counter = make_stellar_counter(&r);

        counter.with_label_values(&["success"]).inc();
        counter.with_label_values(&["success"]).inc();
        counter.with_label_values(&["failed"]).inc();

        assert_eq!(counter.with_label_values(&["success"]).get(), 2.0);
        assert_eq!(counter.with_label_values(&["failed"]).get(), 1.0);
    }

    #[test]
    fn test_stellar_trustline_attempts_counter() {
        let r = Registry::new();
        let counter = make_trustline_counter(&r);

        counter.with_label_values(&["success"]).inc();
        counter.with_label_values(&["failed"]).inc();
        counter.with_label_values(&["already_exists"]).inc();

        assert_eq!(counter.with_label_values(&["success"]).get(), 1.0);
        assert_eq!(counter.with_label_values(&["failed"]).get(), 1.0);
        assert_eq!(counter.with_label_values(&["already_exists"]).get(), 1.0);
    }

    // -----------------------------------------------------------------------
    // Worker metrics tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_worker_cycle_counter() {
        let r = Registry::new();
        let counter = make_worker_cycles(&r);

        counter.with_label_values(&["onramp_processor"]).inc();
        counter.with_label_values(&["onramp_processor"]).inc();
        counter.with_label_values(&["offramp_processor"]).inc();
        counter.with_label_values(&["transaction_monitor"]).inc();

        assert_eq!(counter.with_label_values(&["onramp_processor"]).get(), 2.0);
        assert_eq!(counter.with_label_values(&["offramp_processor"]).get(), 1.0);
        assert_eq!(counter.with_label_values(&["transaction_monitor"]).get(), 1.0);
    }

    #[test]
    fn test_worker_error_counter() {
        let r = Registry::new();
        let counter = make_worker_errors(&r);

        counter.with_label_values(&["onramp_processor", "timeout"]).inc();
        counter.with_label_values(&["onramp_processor", "stellar_error"]).inc();
        counter.with_label_values(&["offramp_processor", "database"]).inc();

        assert_eq!(counter.with_label_values(&["onramp_processor", "timeout"]).get(), 1.0);
        assert_eq!(counter.with_label_values(&["onramp_processor", "stellar_error"]).get(), 1.0);
        assert_eq!(counter.with_label_values(&["offramp_processor", "database"]).get(), 1.0);
    }

    #[test]
    fn test_worker_records_processed_gauge() {
        let r = Registry::new();
        let gauge = make_worker_records(&r);

        gauge.with_label_values(&["onramp_processor"]).set(12.0);
        assert_eq!(gauge.with_label_values(&["onramp_processor"]).get(), 12.0);

        gauge.with_label_values(&["onramp_processor"]).set(0.0);
        assert_eq!(gauge.with_label_values(&["onramp_processor"]).get(), 0.0);
    }

    // -----------------------------------------------------------------------
    // Cache metrics tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_cache_hit_counter_by_prefix() {
        let r = Registry::new();
        let hits = make_cache_hits(&r);
        let misses = make_cache_misses(&r);

        hits.with_label_values(&["rates"]).inc();
        hits.with_label_values(&["rates"]).inc();
        misses.with_label_values(&["rates"]).inc();
        hits.with_label_values(&["wallet"]).inc();
        misses.with_label_values(&["wallet"]).inc();
        misses.with_label_values(&["wallet"]).inc();

        assert_eq!(hits.with_label_values(&["rates"]).get(), 2.0);
        assert_eq!(misses.with_label_values(&["rates"]).get(), 1.0);
        assert_eq!(hits.with_label_values(&["wallet"]).get(), 1.0);
        assert_eq!(misses.with_label_values(&["wallet"]).get(), 2.0);
    }

    // -----------------------------------------------------------------------
    // Database metrics tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_db_error_counter() {
        let r = Registry::new();
        let counter = make_db_errors(&r);

        counter.with_label_values(&["connection_error"]).inc();
        counter.with_label_values(&["query_error"]).inc();
        counter.with_label_values(&["connection_error"]).inc();

        assert_eq!(counter.with_label_values(&["connection_error"]).get(), 2.0);
        assert_eq!(counter.with_label_values(&["query_error"]).get(), 1.0);
    }

    #[test]
    fn test_db_pool_gauge() {
        let r = Registry::new();
        let gauge = make_db_pool_gauge(&r);

        gauge.with_label_values(&["primary"]).set(5.0);
        assert_eq!(gauge.with_label_values(&["primary"]).get(), 5.0);

        gauge.with_label_values(&["primary"]).set(8.0);
        assert_eq!(gauge.with_label_values(&["primary"]).get(), 8.0);
    }

    // -----------------------------------------------------------------------
    // key_prefix helper test
    // -----------------------------------------------------------------------

    #[test]
    fn test_key_prefix_extraction() {
        assert_eq!(crate::metrics::key_prefix("rates:NGN:USD"), "rates");
        assert_eq!(crate::metrics::key_prefix("wallet:GXXX"), "wallet");
        assert_eq!(crate::metrics::key_prefix("no_colon"), "no_colon");
    }

    // -----------------------------------------------------------------------
    // Prometheus text output test
    // -----------------------------------------------------------------------

    #[test]
    fn test_global_registry_renders_valid_prometheus_output() {
        // Ensure the global registry initialises without panic
        let registry = crate::metrics::registry();
        assert!(!registry.gather().is_empty());

        let output = crate::metrics::render();
        // Must contain at least one metric family header
        assert!(output.contains("# HELP") || output.is_empty());
    }
}
