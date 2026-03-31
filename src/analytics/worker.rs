use super::anomaly::{AnomalyDetector, AnomalyDetectionConfig};
use super::health::HealthScoreCalculator;
use super::models::SnapshotPeriod;
use super::repository::AnalyticsRepository;
use super::reports::ReportGenerator;
use super::snapshot::SnapshotGenerator;
use chrono::{DateTime, Datelike, Duration, Timelike, Utc};
use sqlx::PgPool;
use std::sync::Arc;
use tokio::sync::watch;
use tokio::time::interval;
use tracing::{error, info};

pub struct AnalyticsWorker {
    snapshot_generator: Arc<SnapshotGenerator>,
    health_calculator: Arc<HealthScoreCalculator>,
    anomaly_detector: Arc<AnomalyDetector>,
    report_generator: Arc<ReportGenerator>,
    pool: Arc<PgPool>,
    repo: Arc<AnalyticsRepository>,
    config: AnalyticsWorkerConfig,
}

#[derive(Debug, Clone)]
pub struct AnalyticsWorkerConfig {
    pub hourly_snapshot_enabled: bool,
    pub daily_snapshot_enabled: bool,
    pub weekly_snapshot_enabled: bool,
    pub monthly_snapshot_enabled: bool,
    pub health_score_enabled: bool,
    pub anomaly_detection_enabled: bool,
    pub weekly_report_enabled: bool,
    pub monthly_report_enabled: bool,
    pub check_interval_secs: u64,
}

impl Default for AnalyticsWorkerConfig {
    fn default() -> Self {
        Self {
            hourly_snapshot_enabled: true,
            daily_snapshot_enabled: true,
            weekly_snapshot_enabled: true,
            monthly_snapshot_enabled: true,
            health_score_enabled: true,
            anomaly_detection_enabled: true,
            weekly_report_enabled: true,
            monthly_report_enabled: true,
            check_interval_secs: 300, // 5 minutes
        }
    }
}

impl AnalyticsWorker {
    pub fn new(
        pool: Arc<PgPool>,
        config: AnalyticsWorkerConfig,
    ) -> Self {
        let repo = Arc::new(AnalyticsRepository::new(pool.as_ref().clone()));
        let snapshot_generator = Arc::new(SnapshotGenerator::new(pool.clone(), repo.clone()));
        let health_calculator = Arc::new(HealthScoreCalculator::new(pool.clone(), repo.clone()));
        let anomaly_detector = Arc::new(AnomalyDetector::new(
            pool.clone(),
            repo.clone(),
            AnomalyDetectionConfig::default(),
        ));
        let report_generator = Arc::new(ReportGenerator::new(pool.clone(), repo.clone()));

        Self {
            snapshot_generator,
            health_calculator,
            anomaly_detector,
            report_generator,
            pool,
            repo,
            config,
        }
    }

    pub async fn run(&self, mut shutdown: watch::Receiver<bool>) {
        info!("Analytics worker started");
        let mut ticker = interval(std::time::Duration::from_secs(self.config.check_interval_secs));

        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    if let Err(e) = self.process_cycle().await {
                        error!(error = %e, "Analytics worker cycle failed");
                    }
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        info!("Analytics worker shutting down");
                        break;
                    }
                }
            }
        }
    }

    async fn process_cycle(&self) -> Result<(), anyhow::Error> {
        let now = Utc::now();

        // Hourly snapshots (at minute 0)
        if self.config.hourly_snapshot_enabled && now.minute() == 0 {
            self.generate_hourly_snapshot(now).await?;
        }

        // Daily snapshots (at midnight)
        if self.config.daily_snapshot_enabled && now.hour() == 0 && now.minute() == 0 {
            self.generate_daily_snapshot(now).await?;
            
            // Calculate health scores after daily snapshot
            if self.config.health_score_enabled {
                self.calculate_all_health_scores().await?;
            }
        }

        // Weekly snapshots (Monday at midnight)
        if self.config.weekly_snapshot_enabled 
            && now.weekday() == chrono::Weekday::Mon 
            && now.hour() == 0 
            && now.minute() == 0 {
            self.generate_weekly_snapshot(now).await?;
            
            // Generate weekly report
            if self.config.weekly_report_enabled {
                self.report_generator.generate_weekly_platform_report().await?;
            }
        }

        // Monthly snapshots (1st of month at midnight)
        if self.config.monthly_snapshot_enabled 
            && now.day() == 1 
            && now.hour() == 0 
            && now.minute() == 0 {
            self.generate_monthly_snapshot(now).await?;
        }

        // Anomaly detection (every cycle)
        if self.config.anomaly_detection_enabled {
            let anomalies = self.anomaly_detector.detect_anomalies().await?;
            if !anomalies.is_empty() {
                info!(anomaly_count = anomalies.len(), "Usage anomalies detected");
            }
        }

        Ok(())
    }

    async fn generate_hourly_snapshot(&self, now: DateTime<Utc>) -> Result<(), anyhow::Error> {
        let period_end = now;
        let period_start = now - Duration::hours(1);
        
        self.snapshot_generator
            .generate_snapshots(SnapshotPeriod::Hourly, period_start, period_end)
            .await?;
        
        Ok(())
    }

    async fn generate_daily_snapshot(&self, now: DateTime<Utc>) -> Result<(), anyhow::Error> {
        let period_end = now;
        let period_start = now - Duration::days(1);
        
        self.snapshot_generator
            .generate_snapshots(SnapshotPeriod::Daily, period_start, period_end)
            .await?;
        
        Ok(())
    }

    async fn generate_weekly_snapshot(&self, now: DateTime<Utc>) -> Result<(), anyhow::Error> {
        let period_end = now;
        let period_start = now - Duration::days(7);
        
        self.snapshot_generator
            .generate_snapshots(SnapshotPeriod::Weekly, period_start, period_end)
            .await?;
        
        Ok(())
    }

    async fn generate_monthly_snapshot(&self, now: DateTime<Utc>) -> Result<(), anyhow::Error> {
        let period_end = now;
        let period_start = now - Duration::days(30);
        
        self.snapshot_generator
            .generate_snapshots(SnapshotPeriod::Monthly, period_start, period_end)
            .await?;
        
        Ok(())
    }

    async fn calculate_all_health_scores(&self) -> Result<(), anyhow::Error> {
        let consumers = sqlx::query_scalar!(
            r#"
            SELECT DISTINCT actor_id
            FROM api_audit_logs
            WHERE actor_type = 'consumer' 
              AND actor_id IS NOT NULL
              AND created_at >= NOW() - INTERVAL '30 days'
            "#
        )
        .fetch_all(&*self.pool)
        .await?;

        let mut calculated = 0;
        for consumer_id in consumers.into_iter().flatten() {
            if let Err(e) = self.health_calculator.calculate_health_score(&consumer_id).await {
                error!(consumer_id = %consumer_id, error = %e, "Failed to calculate health score");
            } else {
                calculated += 1;
            }
        }

        info!(calculated, "Health scores calculated");
        Ok(())
    }
}
