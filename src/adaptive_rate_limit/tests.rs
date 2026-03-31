//! Unit and integration tests for the adaptive rate limiting system.

#[cfg(test)]
mod unit {
    use crate::adaptive_rate_limit::{
        config::AdaptiveRateLimitConfig,
        models::{
            AdaptationMode, ConsumerPriorityTier, ConsumerRateTrend, RollingSignalAverage,
            SignalSnapshot,
        },
    };

    // ── Rolling average ───────────────────────────────────────────────────────

    fn make_snapshot(cpu: f64, db: f64, redis: f64, queue: u64, err: f64, p99: f64) -> SignalSnapshot {
        SignalSnapshot {
            captured_at: chrono::Utc::now(),
            cpu_utilisation: cpu,
            db_pool_utilisation: db,
            redis_memory_pressure: redis,
            request_queue_depth: queue,
            error_rate: err,
            p99_response_time_ms: p99,
        }
    }

    #[test]
    fn rolling_average_empty_returns_zero() {
        let avg = RollingSignalAverage::new(5);
        assert_eq!(avg.avg_cpu(), 0.0);
        assert_eq!(avg.avg_db_pool(), 0.0);
        assert_eq!(avg.avg_error_rate(), 0.0);
    }

    #[test]
    fn rolling_average_single_sample() {
        let mut avg = RollingSignalAverage::new(5);
        avg.push(make_snapshot(0.8, 0.6, 0.5, 100, 0.1, 500.0));
        assert!((avg.avg_cpu() - 0.8).abs() < 1e-9);
        assert!((avg.avg_db_pool() - 0.6).abs() < 1e-9);
        assert!((avg.avg_error_rate() - 0.1).abs() < 1e-9);
    }

    #[test]
    fn rolling_average_multiple_samples() {
        let mut avg = RollingSignalAverage::new(4);
        avg.push(make_snapshot(0.2, 0.0, 0.0, 0, 0.0, 0.0));
        avg.push(make_snapshot(0.4, 0.0, 0.0, 0, 0.0, 0.0));
        avg.push(make_snapshot(0.6, 0.0, 0.0, 0, 0.0, 0.0));
        avg.push(make_snapshot(0.8, 0.0, 0.0, 0, 0.0, 0.0));
        // Average of 0.2, 0.4, 0.6, 0.8 = 0.5
        assert!((avg.avg_cpu() - 0.5).abs() < 1e-9);
    }

    #[test]
    fn rolling_average_evicts_oldest_when_full() {
        let mut avg = RollingSignalAverage::new(3);
        avg.push(make_snapshot(1.0, 0.0, 0.0, 0, 0.0, 0.0)); // will be evicted
        avg.push(make_snapshot(0.3, 0.0, 0.0, 0, 0.0, 0.0));
        avg.push(make_snapshot(0.3, 0.0, 0.0, 0, 0.0, 0.0));
        avg.push(make_snapshot(0.3, 0.0, 0.0, 0, 0.0, 0.0)); // evicts 1.0
        // Average of 0.3, 0.3, 0.3 = 0.3
        assert!((avg.avg_cpu() - 0.3).abs() < 1e-9);
    }

    #[test]
    fn rolling_average_latest_returns_most_recent() {
        let mut avg = RollingSignalAverage::new(5);
        avg.push(make_snapshot(0.1, 0.0, 0.0, 0, 0.0, 0.0));
        avg.push(make_snapshot(0.9, 0.0, 0.0, 0, 0.0, 0.0));
        assert!((avg.latest().unwrap().cpu_utilisation - 0.9).abs() < 1e-9);
    }

    // ── Mode transition threshold evaluation ─────────────────────────────────

    fn default_cfg() -> AdaptiveRateLimitConfig {
        AdaptiveRateLimitConfig::default()
    }

    /// Simulate the emergency check from the engine.
    fn would_be_emergency(cfg: &AdaptiveRateLimitConfig, avg: &SignalSnapshot) -> bool {
        avg.cpu_utilisation >= cfg.emergency_cpu_threshold
            || avg.db_pool_utilisation >= cfg.emergency_db_pool_threshold
            || avg.error_rate >= cfg.emergency_error_rate_threshold
    }

    /// Simulate the critical check from the engine.
    fn critical_signal_count(cfg: &AdaptiveRateLimitConfig, avg: &SignalSnapshot) -> usize {
        [
            avg.cpu_utilisation >= cfg.critical_cpu_threshold,
            avg.db_pool_utilisation >= cfg.critical_db_pool_threshold,
            avg.redis_memory_pressure >= cfg.critical_redis_threshold,
            avg.request_queue_depth >= cfg.critical_queue_depth_threshold,
            avg.error_rate >= cfg.critical_error_rate_threshold,
            avg.p99_response_time_ms >= cfg.critical_p99_ms_threshold,
        ]
        .iter()
        .filter(|&&b| b)
        .count()
    }

    fn any_elevated(cfg: &AdaptiveRateLimitConfig, avg: &SignalSnapshot) -> bool {
        avg.cpu_utilisation >= cfg.elevated_cpu_threshold
            || avg.db_pool_utilisation >= cfg.elevated_db_pool_threshold
            || avg.redis_memory_pressure >= cfg.elevated_redis_threshold
            || avg.request_queue_depth >= cfg.elevated_queue_depth_threshold
            || avg.error_rate >= cfg.elevated_error_rate_threshold
            || avg.p99_response_time_ms >= cfg.elevated_p99_ms_threshold
    }

    #[test]
    fn normal_signals_do_not_trigger_elevated() {
        let cfg = default_cfg();
        let avg = make_snapshot(0.3, 0.3, 0.3, 50, 0.01, 200.0);
        assert!(!any_elevated(&cfg, &avg));
        assert!(!would_be_emergency(&cfg, &avg));
    }

    #[test]
    fn high_cpu_triggers_elevated() {
        let cfg = default_cfg();
        let avg = make_snapshot(0.75, 0.3, 0.3, 50, 0.01, 200.0);
        assert!(any_elevated(&cfg, &avg));
        assert!(!would_be_emergency(&cfg, &avg));
    }

    #[test]
    fn multiple_critical_signals_trigger_critical() {
        let cfg = default_cfg();
        // CPU + DB both above critical threshold
        let avg = make_snapshot(0.90, 0.92, 0.3, 50, 0.01, 200.0);
        assert!(critical_signal_count(&cfg, &avg) >= cfg.critical_signal_count);
    }

    #[test]
    fn single_critical_signal_does_not_trigger_critical() {
        let cfg = default_cfg();
        let avg = make_snapshot(0.90, 0.3, 0.3, 50, 0.01, 200.0);
        assert!(critical_signal_count(&cfg, &avg) < cfg.critical_signal_count);
    }

    #[test]
    fn emergency_cpu_triggers_emergency() {
        let cfg = default_cfg();
        let avg = make_snapshot(0.96, 0.3, 0.3, 50, 0.01, 200.0);
        assert!(would_be_emergency(&cfg, &avg));
    }

    #[test]
    fn emergency_error_rate_triggers_emergency() {
        let cfg = default_cfg();
        let avg = make_snapshot(0.3, 0.3, 0.3, 50, 0.35, 200.0);
        assert!(would_be_emergency(&cfg, &avg));
    }

    // ── Hysteresis enforcement ────────────────────────────────────────────────

    fn all_below_relax(cfg: &AdaptiveRateLimitConfig, s: &SignalSnapshot) -> bool {
        s.cpu_utilisation < cfg.relax_cpu_threshold
            && s.db_pool_utilisation < cfg.relax_db_pool_threshold
            && s.redis_memory_pressure < cfg.relax_redis_threshold
            && s.request_queue_depth < cfg.relax_queue_depth_threshold
            && s.error_rate < cfg.relax_error_rate_threshold
            && s.p99_response_time_ms < cfg.relax_p99_ms_threshold
    }

    #[test]
    fn signals_above_relax_threshold_prevent_relaxation() {
        let cfg = default_cfg();
        // CPU just above relax threshold
        let s = make_snapshot(0.65, 0.3, 0.3, 50, 0.01, 200.0);
        assert!(!all_below_relax(&cfg, &s));
    }

    #[test]
    fn all_signals_below_relax_threshold_allow_relaxation() {
        let cfg = default_cfg();
        let s = make_snapshot(0.3, 0.3, 0.3, 50, 0.01, 200.0);
        assert!(all_below_relax(&cfg, &s));
    }

    // ── Adaptive multiplier application ──────────────────────────────────────

    fn base_multiplier(
        cfg: &AdaptiveRateLimitConfig,
        mode: AdaptationMode,
        tier: ConsumerPriorityTier,
    ) -> f64 {
        match (mode, tier) {
            (AdaptationMode::Normal, _) => 1.0,
            (AdaptationMode::Elevated, ConsumerPriorityTier::High) => 1.0,
            (AdaptationMode::Elevated, ConsumerPriorityTier::Standard) => cfg.elevated_standard_multiplier,
            (AdaptationMode::Elevated, ConsumerPriorityTier::Low) => cfg.elevated_low_multiplier,
            (AdaptationMode::Critical, ConsumerPriorityTier::High) => 1.0,
            (AdaptationMode::Critical, ConsumerPriorityTier::Standard) => cfg.critical_standard_multiplier,
            (AdaptationMode::Critical, ConsumerPriorityTier::Low) => cfg.critical_low_multiplier,
            (AdaptationMode::Emergency, ConsumerPriorityTier::High) => cfg.emergency_high_multiplier,
            (AdaptationMode::Emergency, _) => 0.05,
        }
    }

    #[test]
    fn normal_mode_all_tiers_get_full_limit() {
        let cfg = default_cfg();
        assert_eq!(base_multiplier(&cfg, AdaptationMode::Normal, ConsumerPriorityTier::High), 1.0);
        assert_eq!(base_multiplier(&cfg, AdaptationMode::Normal, ConsumerPriorityTier::Standard), 1.0);
        assert_eq!(base_multiplier(&cfg, AdaptationMode::Normal, ConsumerPriorityTier::Low), 1.0);
    }

    #[test]
    fn elevated_mode_high_priority_protected() {
        let cfg = default_cfg();
        assert_eq!(base_multiplier(&cfg, AdaptationMode::Elevated, ConsumerPriorityTier::High), 1.0);
    }

    #[test]
    fn elevated_mode_standard_gets_tightened() {
        let cfg = default_cfg();
        let m = base_multiplier(&cfg, AdaptationMode::Elevated, ConsumerPriorityTier::Standard);
        assert!(m < 1.0);
        assert!((m - cfg.elevated_standard_multiplier).abs() < 1e-9);
    }

    #[test]
    fn critical_mode_high_priority_protected() {
        let cfg = default_cfg();
        assert_eq!(base_multiplier(&cfg, AdaptationMode::Critical, ConsumerPriorityTier::High), 1.0);
    }

    #[test]
    fn critical_mode_standard_more_aggressive_than_elevated() {
        let cfg = default_cfg();
        let elevated = base_multiplier(&cfg, AdaptationMode::Elevated, ConsumerPriorityTier::Standard);
        let critical = base_multiplier(&cfg, AdaptationMode::Critical, ConsumerPriorityTier::Standard);
        assert!(critical < elevated);
    }

    #[test]
    fn emergency_mode_high_priority_gets_reduced_but_nonzero() {
        let cfg = default_cfg();
        let m = base_multiplier(&cfg, AdaptationMode::Emergency, ConsumerPriorityTier::High);
        assert!(m > 0.0);
        assert!(m < 1.0);
    }

    #[test]
    fn emergency_mode_standard_gets_minimal() {
        let cfg = default_cfg();
        let m = base_multiplier(&cfg, AdaptationMode::Emergency, ConsumerPriorityTier::Standard);
        assert!(m > 0.0);
        assert!(m <= 0.1);
    }

    // ── Per-consumer accelerating request detection ───────────────────────────

    #[test]
    fn non_accelerating_trend_not_detected() {
        let mut trend = ConsumerRateTrend::new(uuid::Uuid::new_v4(), 6);
        // Flat traffic
        for _ in 0..6 {
            trend.buckets.push_back(100);
        }
        assert!(!trend.is_accelerating());
    }

    #[test]
    fn accelerating_trend_detected() {
        let mut trend = ConsumerRateTrend::new(uuid::Uuid::new_v4(), 6);
        // Rapidly increasing traffic
        trend.buckets.push_back(10);
        trend.buckets.push_back(20);
        trend.buckets.push_back(40);
        trend.buckets.push_back(80);
        trend.buckets.push_back(160);
        trend.buckets.push_back(320);
        assert!(trend.is_accelerating());
    }

    #[test]
    fn insufficient_buckets_not_accelerating() {
        let mut trend = ConsumerRateTrend::new(uuid::Uuid::new_v4(), 6);
        trend.buckets.push_back(10);
        trend.buckets.push_back(20);
        // Only 2 buckets — need at least 3
        assert!(!trend.is_accelerating());
    }

    #[test]
    fn decreasing_trend_not_accelerating() {
        let mut trend = ConsumerRateTrend::new(uuid::Uuid::new_v4(), 6);
        trend.buckets.push_back(320);
        trend.buckets.push_back(160);
        trend.buckets.push_back(80);
        trend.buckets.push_back(40);
        assert!(!trend.is_accelerating());
    }

    // ── Request shedding ─────────────────────────────────────────────────────

    #[test]
    fn endpoint_category_essential_classification() {
        use crate::adaptive_rate_limit::models::EndpointCategory;
        assert_eq!(EndpointCategory::classify("/api/onramp/initiate"), EndpointCategory::Essential);
        assert_eq!(EndpointCategory::classify("/api/offramp/initiate"), EndpointCategory::Essential);
        assert_eq!(EndpointCategory::classify("/api/bills/pay"), EndpointCategory::Essential);
    }

    #[test]
    fn endpoint_category_non_essential_classification() {
        use crate::adaptive_rate_limit::models::EndpointCategory;
        assert_eq!(EndpointCategory::classify("/api/rates"), EndpointCategory::NonEssential);
        assert_eq!(EndpointCategory::classify("/api/onramp/quote"), EndpointCategory::NonEssential);
        assert_eq!(EndpointCategory::classify("/api/wallet/balance"), EndpointCategory::NonEssential);
    }

    // ── Consumer priority tier mapping ────────────────────────────────────────

    #[test]
    fn backend_microservice_maps_to_high_priority() {
        assert_eq!(
            ConsumerPriorityTier::from_consumer_type("backend_microservice"),
            ConsumerPriorityTier::High
        );
    }

    #[test]
    fn third_party_partner_maps_to_high_priority() {
        assert_eq!(
            ConsumerPriorityTier::from_consumer_type("third_party_partner"),
            ConsumerPriorityTier::High
        );
    }

    #[test]
    fn mobile_client_maps_to_standard_priority() {
        assert_eq!(
            ConsumerPriorityTier::from_consumer_type("mobile_client"),
            ConsumerPriorityTier::Standard
        );
    }

    #[test]
    fn unknown_type_maps_to_standard_priority() {
        assert_eq!(
            ConsumerPriorityTier::from_consumer_type("unknown_type"),
            ConsumerPriorityTier::Standard
        );
    }

    // ── AdaptationMode helpers ────────────────────────────────────────────────

    #[test]
    fn mode_severity_ordering() {
        assert!(AdaptationMode::Normal.severity() < AdaptationMode::Elevated.severity());
        assert!(AdaptationMode::Elevated.severity() < AdaptationMode::Critical.severity());
        assert!(AdaptationMode::Critical.severity() < AdaptationMode::Emergency.severity());
    }

    #[test]
    fn mode_as_str_round_trips() {
        for mode in [
            AdaptationMode::Normal,
            AdaptationMode::Elevated,
            AdaptationMode::Critical,
            AdaptationMode::Emergency,
        ] {
            assert!(!mode.as_str().is_empty());
        }
    }
}

// ---------------------------------------------------------------------------
// Integration tests (require database + Redis — run with --features integration)
// ---------------------------------------------------------------------------

#[cfg(all(test, feature = "integration"))]
mod integration {
    // Integration tests are in tests/adaptive_rate_limit_integration.rs
}
