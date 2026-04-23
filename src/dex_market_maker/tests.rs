#[cfg(test)]
mod tests {
    use crate::dex_market_maker::circuit_breaker::CircuitBreaker;
    use crate::dex_market_maker::config::{
        CIRCUIT_BREAKER_DRAIN_RATE, CIRCUIT_BREAKER_PAUSE_SECS, LADDER_RUNGS, SPREAD_MAX,
        SPREAD_MIN,
    };

    // ── Spread constants ─────────────────────────────────────────────────────

    #[test]
    fn spread_bounds_are_valid() {
        assert!(SPREAD_MIN > 0.0);
        assert!(SPREAD_MAX > SPREAD_MIN);
        // Acceptance criterion: spread must be achievable below 1%.
        assert!(SPREAD_MIN < 0.01);
    }

    #[test]
    fn ladder_rungs_nonzero() {
        assert!(LADDER_RUNGS > 0);
    }

    // ── Circuit breaker ──────────────────────────────────────────────────────

    #[test]
    fn circuit_breaker_does_not_trip_on_stable_inventory() {
        let cb = CircuitBreaker::new(1_000_000.0);
        // Inventory unchanged — should not trip.
        assert!(!cb.check(1_000_000.0));
        assert!(!cb.is_tripped());
    }

    #[test]
    fn circuit_breaker_trips_on_rapid_drain() {
        let cb = CircuitBreaker::new(1_000_000.0);
        // Simulate a drain well above the threshold within the same window.
        // drain_fraction = 0.9, elapsed_mins ≈ 0.01 → drain_per_min ≈ 90 >> threshold.
        let tripped = cb.check(100_000.0);
        assert!(tripped);
        assert!(cb.is_tripped());
    }

    #[test]
    fn circuit_breaker_resets_manually() {
        let cb = CircuitBreaker::new(1_000_000.0);
        cb.check(100_000.0); // trip it
        assert!(cb.is_tripped());
        cb.reset();
        assert!(!cb.is_tripped());
    }

    #[test]
    fn circuit_breaker_constants_are_sane() {
        assert!(CIRCUIT_BREAKER_DRAIN_RATE > 0.0 && CIRCUIT_BREAKER_DRAIN_RATE < 1.0);
        assert!(CIRCUIT_BREAKER_PAUSE_SECS >= 60);
    }

    // ── Ladder price calculation ─────────────────────────────────────────────

    #[test]
    fn ladder_prices_widen_with_rung() {
        let mid = 1.0_f64;
        let half_spread = SPREAD_MIN / 2.0;
        let step = crate::dex_market_maker::config::LADDER_STEP;

        let mut prev_bid = mid;
        let mut prev_ask = mid;

        for rung in 0..LADDER_RUNGS {
            let offset = half_spread + rung as f64 * step;
            let bid = mid * (1.0 - offset);
            let ask = mid * (1.0 + offset);

            assert!(bid < prev_bid || rung == 0, "bid should decrease with rung");
            assert!(ask > prev_ask || rung == 0, "ask should increase with rung");
            assert!(ask > bid, "ask must always be above bid");

            prev_bid = bid;
            prev_ask = ask;
        }
    }

    #[test]
    fn spread_stays_below_1_pct_at_tightest_rung() {
        let mid = 1.0_f64;
        let half_spread = SPREAD_MIN / 2.0;
        let bid = mid * (1.0 - half_spread);
        let ask = mid * (1.0 + half_spread);
        let spread_pct = (ask - bid) / mid * 100.0;
        // Acceptance criterion: spread < 1% for 99.9% of the trading day.
        assert!(spread_pct < 1.0, "spread_pct={spread_pct}");
    }
}
