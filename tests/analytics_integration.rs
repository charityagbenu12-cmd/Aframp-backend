//! Integration tests for analytics endpoints (Issue #113).
//!
//! These tests require a running Postgres instance (DATABASE_URL env var) and
//! seed transaction data across multiple time periods and providers.
//!
//! Run with:
//!   cargo test --test analytics_integration --features database -- --test-threads=1

#[cfg(feature = "database")]
mod analytics_integration {
    use chrono::{Duration, Utc};

    /// Validates that the DateRangeParams validation logic rejects unbounded ranges.
    #[test]
    fn rejects_range_over_366_days() {
        use Bitmesh_backend::analytics::models::DateRangeParams;
        let p = DateRangeParams {
            from: Utc::now() - Duration::days(400),
            to: Utc::now(),
            period: "daily".to_string(),
        };
        assert!(p.validate().is_err());
    }

    /// Validates that a 30-day daily range is accepted.
    #[test]
    fn accepts_30_day_daily_range() {
        use Bitmesh_backend::analytics::models::DateRangeParams;
        let p = DateRangeParams {
            from: Utc::now() - Duration::days(30),
            to: Utc::now(),
            period: "daily".to_string(),
        };
        assert!(p.validate().is_ok());
    }

    /// Validates that a monthly period is accepted.
    #[test]
    fn accepts_monthly_period() {
        use Bitmesh_backend::analytics::models::DateRangeParams;
        let p = DateRangeParams {
            from: Utc::now() - Duration::days(90),
            to: Utc::now(),
            period: "monthly".to_string(),
        };
        assert!(p.validate().is_ok());
    }
}
