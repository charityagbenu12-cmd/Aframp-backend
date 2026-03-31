//! Consumer Usage Analytics System Demo
//!
//! Demonstrates:
//! - Snapshot generation for different periods
//! - Health score calculation
//! - Anomaly detection
//! - Report generation
//! - Consumer and admin analytics endpoints

use Bitmesh_backend::analytics::{
    anomaly::{AnomalyDetector, AnomalyDetectionConfig},
    health::HealthScoreCalculator,
    models::SnapshotPeriod,
    repository::AnalyticsRepository,
    reports::ReportGenerator,
    snapshot::SnapshotGenerator,
    worker::{AnalyticsWorker, AnalyticsWorkerConfig},
};
use chrono::{Duration, Utc};
use sqlx::PgPool;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@localhost/aframp".to_string());

    let pool = PgPool::connect(&database_url).await?;
    let pool = Arc::new(pool);

    println!("🔍 Consumer Usage Analytics System Demo\n");

    // Initialize components
    let repo = Arc::new(AnalyticsRepository::new(pool.as_ref().clone()));
    let snapshot_generator = Arc::new(SnapshotGenerator::new(pool.clone(), repo.clone()));
    let health_calculator = Arc::new(HealthScoreCalculator::new(pool.clone(), repo.clone()));
    let anomaly_detector = Arc::new(AnomalyDetector::new(
        pool.clone(),
        repo.clone(),
        AnomalyDetectionConfig::default(),
    ));
    let report_generator = Arc::new(ReportGenerator::new(pool.clone(), repo.clone()));

    // ── 1. Generate usage snapshots ──────────────────────────────────────────
    println!("📊 Generating usage snapshots...");
    
    let period_end = Utc::now();
    let period_start = period_end - Duration::days(1);
    
    let result = snapshot_generator
        .generate_snapshots(SnapshotPeriod::Daily, period_start, period_end)
        .await?;
    
    println!("   ✓ Processed {} consumers", result.consumers_processed);
    println!("   ✓ Created {} snapshots", result.snapshots_created);
    println!("   ✓ Duration: {}ms", result.duration_ms);
    println!("   ✓ Status: {}\n", result.status);

    // ── 2. Calculate health scores ───────────────────────────────────────────
    println!("💚 Calculating consumer health scores...");
    
    // Get a sample consumer
    let sample_consumer = sqlx::query_scalar!(
        r#"
        SELECT DISTINCT actor_id
        FROM api_audit_logs
        WHERE actor_type = 'consumer' AND actor_id IS NOT NULL
        LIMIT 1
        "#
    )
    .fetch_optional(&*pool)
    .await?
    .flatten();

    if let Some(consumer_id) = sample_consumer {
        let health_score = health_calculator
            .calculate_health_score(&consumer_id)
            .await?;
        
        println!("   Consumer: {}", consumer_id);
        println!("   ✓ Health Score: {}/100", health_score.health_score);
        println!("   ✓ Error Rate Score: {}", health_score.error_rate_score);
        println!("   ✓ Activity Score: {}", health_score.activity_recency_score);
        println!("   ✓ Trend: {:?}", health_score.health_trend);
        println!("   ✓ At Risk: {}\n", health_score.is_at_risk);
    }

    // ── 3. Detect usage anomalies ────────────────────────────────────────────
    println!("🚨 Detecting usage anomalies...");
    
    let anomalies = anomaly_detector.detect_anomalies().await?;
    
    println!("   ✓ Detected {} anomalies", anomalies.len());
    for anomaly in anomalies.iter().take(3) {
        println!("   - Type: {}, Severity: {}, Consumer: {}", 
            anomaly.anomaly_type, anomaly.severity, anomaly.consumer_id);
    }
    println!();

    // ── 4. Generate platform report ──────────────────────────────────────────
    println!("📈 Generating weekly platform report...");
    
    let report = report_generator
        .generate_weekly_platform_report()
        .await?;
    
    println!("   ✓ Total API Requests: {}", report.total_api_requests);
    println!("   ✓ Platform Error Rate: {:.2}%", report.platform_error_rate * 100.0);
    println!("   ✓ Total Consumers: {}", report.total_consumers);
    println!("   ✓ Active Consumers: {}", report.active_consumers);
    println!("   ✓ New Consumers: {}", report.new_consumers);
    println!("   ✓ At-Risk Consumers: {}\n", report.at_risk_consumers);

    // ── 5. Query at-risk consumers ───────────────────────────────────────────
    println!("⚠️  At-risk consumers...");
    
    let at_risk = repo.get_at_risk_consumers(10).await?;
    
    println!("   ✓ Found {} at-risk consumers", at_risk.len());
    for consumer in at_risk.iter().take(5) {
        println!("   - {}: Score {}/100", consumer.consumer_id, consumer.health_score);
    }
    println!();

    // ── 6. Start analytics worker (demo mode) ────────────────────────────────
    println!("🔄 Analytics worker configuration:");
    let worker_config = AnalyticsWorkerConfig::default();
    println!("   ✓ Hourly snapshots: {}", worker_config.hourly_snapshot_enabled);
    println!("   ✓ Daily snapshots: {}", worker_config.daily_snapshot_enabled);
    println!("   ✓ Health scoring: {}", worker_config.health_score_enabled);
    println!("   ✓ Anomaly detection: {}", worker_config.anomaly_detection_enabled);
    println!("   ✓ Check interval: {}s\n", worker_config.check_interval_secs);

    println!("✅ Analytics system demo completed successfully!");

    Ok(())
}
