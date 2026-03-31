
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

#![cfg(feature = "database")]

use chrono::{Duration, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use Bitmesh_backend::analytics::{
    health::HealthScoreCalculator,
    models::*,
    repository::AnalyticsRepository,
    snapshot::SnapshotGenerator,
    anomaly::{AnomalyDetector, AnomalyDetectionConfig},
};
use Bitmesh_backend::audit::models::{AuditActorType, AuditEventCategory, AuditOutcome, AuditLogEntry};
use Bitmesh_backend::audit::repository::AuditLogRepository;
use std::sync::Arc;

async fn setup_test_db() -> PgPool {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@localhost/aframp_test".to_string());
    
    PgPool::connect(&database_url)
        .await
        .expect("Failed to connect to test database")
}

async fn seed_audit_logs(pool: &PgPool, consumer_id: &str, count: i32, success_rate: f64) {
    let audit_repo = AuditLogRepository::new(pool.clone());
    
    for i in 0..count {
        let outcome = if (i as f64 / count as f64) < success_rate {
            AuditOutcome::Success
        } else {
            AuditOutcome::Failure
        };

        let entry = AuditLogEntry {
            id: Uuid::new_v4(),
            event_type: "api_request".to_string(),
            event_category: AuditEventCategory::DataAccess,
            actor_type: AuditActorType::Consumer,
            actor_id: Some(consumer_id.to_string()),
            actor_ip: Some("192.168.1.1".to_string()),
            actor_consumer_type: Some("partner".to_string()),
            session_id: Some(Uuid::new_v4().to_string()),
            target_resource_type: Some("transaction".to_string()),
            target_resource_id: Some(Uuid::new_v4().to_string()),
            request_method: "POST".to_string(),
            request_path: "/api/onramp/quote".to_string(),
            request_body_hash: None,
            response_status: if outcome == AuditOutcome::Success { 200 } else { 500 },
            response_latency_ms: 150,
            outcome,
            failure_reason: if outcome == AuditOutcome::Failure {
                Some("Internal error".to_string())
            } else {
                None
            },
            environment: "test".to_string(),
            previous_entry_hash: None,
            current_entry_hash: format!("hash_{}", i),
            created_at: Utc::now() - Duration::hours(i as i64),
        };

        audit_repo.insert(&entry).await.expect("Failed to insert audit log");
    }
}

#[tokio::test]
async fn test_snapshot_generation() {
    let pool = setup_test_db().await;
    let consumer_id = "test_consumer_1";
    
    // Seed audit logs
    seed_audit_logs(&pool, consumer_id, 100, 0.95).await;
    
    let repo = Arc::new(AnalyticsRepository::new(pool.clone()));
    let generator = SnapshotGenerator::new(Arc::new(pool.clone()), repo.clone());
    
    let period_end = Utc::now();
    let period_start = period_end - Duration::days(1);
    
    let result = generator
        .generate_snapshots(SnapshotPeriod::Daily, period_start, period_end)
        .await
        .expect("Snapshot generation failed");
    
    assert!(result.snapshots_created > 0);
    assert_eq!(result.status, "success");
    
    // Verify snapshot was persisted
    let snapshots = repo
        .get_consumer_snapshots(consumer_id, SnapshotPeriod::Daily, 1)
        .await
        .expect("Failed to fetch snapshots");
    
    assert_eq!(snapshots.len(), 1);
    assert_eq!(snapshots[0].consumer_id, consumer_id);
    assert!(snapshots[0].total_requests > 0);
}

#[tokio::test]
async fn test_health_score_calculation() {
    let pool = setup_test_db().await;
    let consumer_id = "test_consumer_2";
    
    // Seed audit logs with high error rate
    seed_audit_logs(&pool, consumer_id, 100, 0.70).await;
    
    let repo = Arc::new(AnalyticsRepository::new(pool.clone()));
    let calculator = HealthScoreCalculator::new(Arc::new(pool.clone()), repo.clone());
    
    let score = calculator
        .calculate_health_score(consumer_id)
        .await
        .expect("Health score calculation failed");
    
    assert!(score.health_score < 100);
    assert!(score.error_rate_score < 100);
    assert_eq!(score.consumer_id, consumer_id);
}

#[tokio::test]
async fn test_anomaly_detection_volume_drop() {
    let pool = setup_test_db().await;
    let consumer_id = "test_consumer_3";
    
    // Seed historical high volume
    for i in 0..7 {
        seed_audit_logs(&pool, consumer_id, 100, 0.95).await;
    }
    
    // Current period: very low volume (simulated by not seeding recent data)
    
    let repo = Arc::new(AnalyticsRepository::new(pool.clone()));
    let detector = AnomalyDetector::new(
        Arc::new(pool.clone()),
        repo.clone(),
        AnomalyDetectionConfig::default(),
    );
    
    let anomalies = detector
        .detect_anomalies()
        .await
        .expect("Anomaly detection failed");
    
    // Should detect volume drop
    let volume_drops: Vec<_> = anomalies
        .iter()
        .filter(|a| a.anomaly_type == "volume_drop")
        .collect();
    
    assert!(!volume_drops.is_empty());
}

#[tokio::test]
async fn test_incremental_snapshot_computation() {
    let pool = setup_test_db().await;
    let consumer_id = "test_consumer_4";
    
    seed_audit_logs(&pool, consumer_id, 50, 0.95).await;
    
    let repo = Arc::new(AnalyticsRepository::new(pool.clone()));
    let generator = SnapshotGenerator::new(Arc::new(pool.clone()), repo.clone());
    
    let period_end = Utc::now();
    let period_start = period_end - Duration::hours(1);
    
    // First generation
    let result1 = generator
        .generate_snapshots(SnapshotPeriod::Hourly, period_start, period_end)
        .await
        .expect("First snapshot generation failed");
    
    // Add more audit logs
    seed_audit_logs(&pool, consumer_id, 25, 0.90).await;
    
    // Second generation (should update existing snapshot)
    let result2 = generator
        .generate_snapshots(SnapshotPeriod::Hourly, period_start, period_end)
        .await
        .expect("Second snapshot generation failed");
    
    assert_eq!(result1.status, "success");
    assert_eq!(result2.status, "success");
    
    // Verify snapshot was updated (not duplicated)
    let snapshots = repo
        .get_consumer_snapshots(consumer_id, SnapshotPeriod::Hourly, 10)
        .await
        .expect("Failed to fetch snapshots");
    
    // Should have only one snapshot for this period due to UPSERT
    let matching_snapshots: Vec<_> = snapshots
        .iter()
        .filter(|s| s.period_start == period_start)
        .collect();
    
    assert_eq!(matching_snapshots.len(), 1);
}

#[tokio::test]
async fn test_health_score_trend_detection() {
    let pool = setup_test_db().await;
    let consumer_id = "test_consumer_5";
    
    let repo = Arc::new(AnalyticsRepository::new(pool.clone()));
    let calculator = HealthScoreCalculator::new(Arc::new(pool.clone()), repo.clone());
    
    // Generate multiple health scores over time
    for day in (0..7).rev() {
        seed_audit_logs(&pool, consumer_id, 50, 0.95 - (day as f64 * 0.02)).await;
        
        let _score = calculator
            .calculate_health_score(consumer_id)
            .await
            .expect("Health score calculation failed");
    }
    
    // Latest score should show declining trend
    let latest_score = repo
        .get_latest_health_score(consumer_id)
        .await
        .expect("Failed to fetch health score")
        .expect("No health score found");
    
    assert_eq!(latest_score.health_trend, HealthTrend::Declining);

}
