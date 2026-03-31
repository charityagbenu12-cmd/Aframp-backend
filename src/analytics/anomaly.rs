use super::models::*;
use super::repository::AnalyticsRepository;
use chrono::{DateTime, Duration, Utc};
use serde_json::json;
use sqlx::PgPool;
use std::sync::Arc;
use tracing::{info, warn};
use uuid::Uuid;

pub struct AnomalyDetector {
    pool: Arc<PgPool>,
    repo: Arc<AnalyticsRepository>,
    config: AnomalyDetectionConfig,
}

#[derive(Debug, Clone)]
pub struct AnomalyDetectionConfig {
    pub volume_drop_threshold_percent: f64,
    pub error_spike_threshold_percent: f64,
    pub inactivity_window_hours: i64,
    pub rolling_average_window_days: i64,
}

impl Default for AnomalyDetectionConfig {
    fn default() -> Self {
        Self {
            volume_drop_threshold_percent: 50.0,
            error_spike_threshold_percent: 200.0,
            inactivity_window_hours: 72,
            rolling_average_window_days: 7,
        }
    }
}

impl AnomalyDetector {
    pub fn new(pool: Arc<PgPool>, repo: Arc<AnalyticsRepository>, config: AnomalyDetectionConfig) -> Self {
        Self { pool, repo, config }
    }

    /// Detect anomalies for all active consumers
    pub async fn detect_anomalies(&self) -> Result<Vec<ConsumerUsageAnomaly>, anyhow::Error> {
        let mut anomalies = Vec::new();

        // Get all consumers with recent activity
        let consumers = self.get_recent_consumers().await?;

        for consumer_id in consumers {
            // Check for volume drops
            if let Some(anomaly) = self.detect_volume_drop(&consumer_id).await? {
                anomalies.push(anomaly);
            }

            // Check for error spikes
            if let Some(anomaly) = self.detect_error_spike(&consumer_id).await? {
                anomalies.push(anomaly);
            }

            // Check for inactivity
            if let Some(anomaly) = self.detect_inactivity(&consumer_id).await? {
                anomalies.push(anomaly);
            }
        }

        // Persist anomalies
        for anomaly in &anomalies {
            self.repo.insert_anomaly(anomaly).await?;
            
            // Update metrics
            crate::analytics::metrics::anomalies_detected_total()
                .with_label_values(&[&anomaly.anomaly_type, &anomaly.severity])
                .inc();

            info!(
                consumer_id = %anomaly.consumer_id,
                anomaly_type = %anomaly.anomaly_type,
                severity = %anomaly.severity,
                "Usage anomaly detected"
            );
        }

        Ok(anomalies)
    }

    async fn get_recent_consumers(&self) -> Result<Vec<String>, anyhow::Error> {
        let lookback = Utc::now() - Duration::days(self.config.rolling_average_window_days);
        
        let consumers = sqlx::query_scalar!(
            r#"
            SELECT DISTINCT actor_id
            FROM api_audit_logs
            WHERE created_at >= $1 AND actor_id IS NOT NULL AND actor_type = 'consumer'
            "#,
            lookback
        )
        .fetch_all(&*self.pool)
        .await?;

        Ok(consumers.into_iter().flatten().collect())
    }

    async fn detect_volume_drop(&self, consumer_id: &str) -> Result<Option<ConsumerUsageAnomaly>, anyhow::Error> {
        let now = Utc::now();
        let last_24h_start = now - Duration::hours(24);
        let rolling_window_start = now - Duration::days(self.config.rolling_average_window_days);

        // Get current 24h volume
        let current_volume = sqlx::query_scalar!(
            r#"
            SELECT COUNT(*) as "count!"
            FROM api_audit_logs
            WHERE actor_id = $1 AND created_at >= $2
            "#,
            consumer_id,
            last_24h_start
        )
        .fetch_one(&*self.pool)
        .await? as f64;

        // Get rolling average (excluding last 24h)
        let rolling_avg = sqlx::query_scalar!(
            r#"
            SELECT AVG(daily_count) as "avg"
            FROM (
                SELECT DATE_TRUNC('day', created_at) as day, COUNT(*) as daily_count
                FROM api_audit_logs
                WHERE actor_id = $1 
                  AND created_at >= $2 
                  AND created_at < $3
                GROUP BY day
            ) daily_counts
            "#,
            consumer_id,
            rolling_window_start,
            last_24h_start
        )
        .fetch_one(&*self.pool)
        .await?
        .unwrap_or(0.0);

        if rolling_avg == 0.0 {
            return Ok(None);
        }

        let drop_percent = ((rolling_avg - current_volume) / rolling_avg) * 100.0;

        if drop_percent >= self.config.volume_drop_threshold_percent {
            let severity = if drop_percent >= 80.0 {
                "critical"
            } else if drop_percent >= 60.0 {
                "high"
            } else {
                "medium"
            };

            Ok(Some(ConsumerUsageAnomaly {
                id: Uuid::new_v4(),
                consumer_id: consumer_id.to_string(),
                anomaly_type: "volume_drop".to_string(),
                severity: severity.to_string(),
                detected_value: Some(current_volume),
                expected_value: Some(rolling_avg),
                threshold_value: Some(self.config.volume_drop_threshold_percent),
                deviation_percent: Some(drop_percent),
                detection_window: "last_24h".to_string(),
                anomaly_context: Some(json!({
                    "rolling_window_days": self.config.rolling_average_window_days,
                    "current_24h_volume": current_volume,
                    "rolling_avg_volume": rolling_avg
                })),
                is_resolved: false,
                resolved_at: None,
                resolution_notes: None,
                detected_at: now,
                notified_at: None,
                created_at: now,
            }))
        } else {
            Ok(None)
        }
    }

    async fn detect_error_spike(&self, consumer_id: &str) -> Result<Option<ConsumerUsageAnomaly>, anyhow::Error> {
        let now = Utc::now();
        let last_24h_start = now - Duration::hours(24);
        let rolling_window_start = now - Duration::days(self.config.rolling_average_window_days);

        // Get current 24h error rate
        let current_stats = sqlx::query!(
            r#"
            SELECT 
                COUNT(*) as "total!",
                COUNT(*) FILTER (WHERE outcome = 'failure') as "failures!"
            FROM api_audit_logs
            WHERE actor_id = $1 AND created_at >= $2
            "#,
            consumer_id,
            last_24h_start
        )
        .fetch_one(&*self.pool)
        .await?;

        if current_stats.total == 0 {
            return Ok(None);
        }

        let current_error_rate = (current_stats.failures as f64 / current_stats.total as f64) * 100.0;

        // Get rolling average error rate
        let rolling_avg_error_rate = sqlx::query_scalar!(
            r#"
            SELECT 
                (COUNT(*) FILTER (WHERE outcome = 'failure')::float / COUNT(*)::float * 100.0) as "error_rate"
            FROM api_audit_logs
            WHERE actor_id = $1 
              AND created_at >= $2 
              AND created_at < $3
            "#,
            consumer_id,
            rolling_window_start,
            last_24h_start
        )
        .fetch_one(&*self.pool)
        .await?
        .unwrap_or(0.0);

        if rolling_avg_error_rate == 0.0 {
            return Ok(None);
        }

        let spike_percent = ((current_error_rate - rolling_avg_error_rate) / rolling_avg_error_rate) * 100.0;

        if spike_percent >= self.config.error_spike_threshold_percent {
            let severity = if current_error_rate >= 20.0 {
                "critical"
            } else if current_error_rate >= 10.0 {
                "high"
            } else {
                "medium"
            };

            Ok(Some(ConsumerUsageAnomaly {
                id: Uuid::new_v4(),
                consumer_id: consumer_id.to_string(),
                anomaly_type: "error_spike".to_string(),
                severity: severity.to_string(),
                detected_value: Some(current_error_rate),
                expected_value: Some(rolling_avg_error_rate),
                threshold_value: Some(self.config.error_spike_threshold_percent),
                deviation_percent: Some(spike_percent),
                detection_window: "last_24h".to_string(),
                anomaly_context: Some(json!({
                    "current_error_rate": current_error_rate,
                    "rolling_avg_error_rate": rolling_avg_error_rate,
                    "total_requests_24h": current_stats.total,
                    "failed_requests_24h": current_stats.failures
                })),
                is_resolved: false,
                resolved_at: None,
                resolution_notes: None,
                detected_at: now,
                notified_at: None,
                created_at: now,
            }))
        } else {
            Ok(None)
        }
    }

    async fn detect_inactivity(&self, consumer_id: &str) -> Result<Option<ConsumerUsageAnomaly>, anyhow::Error> {
        let now = Utc::now();
        let inactivity_threshold = now - Duration::hours(self.config.inactivity_window_hours);

        let last_activity = sqlx::query_scalar!(
            r#"
            SELECT MAX(created_at)
            FROM api_audit_logs
            WHERE actor_id = $1
            "#,
            consumer_id
        )
        .fetch_one(&*self.pool)
        .await?;

        if let Some(last_activity) = last_activity {
            if last_activity < inactivity_threshold {
                let hours_inactive = (now - last_activity).num_hours();
                
                let severity = if hours_inactive >= 168 {
                    "high"
                } else {
                    "medium"
                };

                Ok(Some(ConsumerUsageAnomaly {
                    id: Uuid::new_v4(),
                    consumer_id: consumer_id.to_string(),
                    anomaly_type: "inactivity".to_string(),
                    severity: severity.to_string(),
                    detected_value: Some(hours_inactive as f64),
                    expected_value: None,
                    threshold_value: Some(self.config.inactivity_window_hours as f64),
                    deviation_percent: None,
                    detection_window: format!("last_{}h", self.config.inactivity_window_hours),
                    anomaly_context: Some(json!({
                        "last_activity": last_activity,
                        "hours_inactive": hours_inactive
                    })),
                    is_resolved: false,
                    resolved_at: None,
                    resolution_notes: None,
                    detected_at: now,
                    notified_at: None,
                    created_at: now,
                }))
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }
}
