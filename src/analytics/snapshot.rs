use super::models::*;
use super::repository::AnalyticsRepository;
use chrono::{DateTime, Duration, Utc};
use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{error, info, warn};
use uuid::Uuid;

pub struct SnapshotGenerator {
    pool: Arc<PgPool>,
    repo: Arc<AnalyticsRepository>,
}

impl SnapshotGenerator {
    pub fn new(pool: Arc<PgPool>, repo: Arc<AnalyticsRepository>) -> Self {
        Self { pool, repo }
    }

    /// Generate usage snapshots for all consumers for a given period
    pub async fn generate_snapshots(
        &self,
        period: SnapshotPeriod,
        period_start: DateTime<Utc>,
        period_end: DateTime<Utc>,
    ) -> Result<SnapshotGenerationResult, anyhow::Error> {
        let start_time = Utc::now();
        info!(
            period = period.as_str(),
            ?period_start,
            ?period_end,
            "Starting snapshot generation"
        );

        // Get all unique consumers from audit logs in this period
        let consumers = self.get_active_consumers(period_start, period_end).await?;
        let consumer_count = consumers.len();

        let mut snapshots_created = 0;
        let mut errors = Vec::new();

        for consumer_id in consumers {
            match self
                .generate_consumer_snapshot(&consumer_id, period, period_start, period_end)
                .await
            {
                Ok(_) => {
                    snapshots_created += 1;
                }
                Err(e) => {
                    error!(consumer_id = %consumer_id, error = %e, "Failed to generate snapshot");
                    errors.push(format!("{}: {}", consumer_id, e));
                }
            }
        }

        let duration_ms = (Utc::now() - start_time).num_milliseconds();

        // Log generation result
        let status = if errors.is_empty() {
            "success"
        } else if snapshots_created > 0 {
            "partial"
        } else {
            "failed"
        };

        let error_message = if !errors.is_empty() {
            Some(errors.join("; "))
        } else {
            None
        };

        self.repo
            .log_snapshot_generation(
                period,
                period_start,
                period_end,
                consumer_count as i32,
                snapshots_created,
                duration_ms,
                status,
                error_message.as_deref(),
                start_time,
            )
            .await?;

        // Update metrics
        crate::analytics::metrics::snapshot_generation_duration_seconds()
            .with_label_values(&[period.as_str()])
            .observe(duration_ms as f64 / 1000.0);

        crate::analytics::metrics::snapshots_generated_total()
            .with_label_values(&[period.as_str(), status])
            .inc_by(snapshots_created as u64);

        info!(
            period = period.as_str(),
            consumers_processed = consumer_count,
            snapshots_created,
            duration_ms,
            status,
            "Snapshot generation completed"
        );

        Ok(SnapshotGenerationResult {
            consumers_processed: consumer_count as i32,
            snapshots_created,
            duration_ms,
            status: status.to_string(),
            errors,
        })
    }

    /// Get all consumers who made requests in the given period
    async fn get_active_consumers(
        &self,
        period_start: DateTime<Utc>,
        period_end: DateTime<Utc>,
    ) -> Result<Vec<String>, anyhow::Error> {
        let rows = sqlx::query_scalar!(
            r#"
            SELECT DISTINCT actor_id
            FROM api_audit_logs
            WHERE created_at >= $1 
              AND created_at < $2
              AND actor_id IS NOT NULL
              AND actor_type = 'consumer'
            "#,
            period_start,
            period_end
        )
        .fetch_all(&*self.pool)
        .await?;

        Ok(rows.into_iter().flatten().collect())
    }

    /// Generate a single consumer's usage snapshot
    async fn generate_consumer_snapshot(
        &self,
        consumer_id: &str,
        period: SnapshotPeriod,
        period_start: DateTime<Utc>,
        period_end: DateTime<Utc>,
    ) -> Result<(), anyhow::Error> {
        // Query audit logs for this consumer in this period
        let stats = sqlx::query!(
            r#"
            SELECT 
                COUNT(*) as "total_requests!",
                COUNT(*) FILTER (WHERE outcome = 'success') as "successful_requests!",
                COUNT(*) FILTER (WHERE outcome = 'failure') as "failed_requests!",
                PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY response_latency_ms) as "p50_latency",
                PERCENTILE_CONT(0.99) WITHIN GROUP (ORDER BY response_latency_ms) as "p99_latency",
                AVG(response_latency_ms) as "avg_latency",
                COUNT(DISTINCT request_path) as "unique_endpoints!"
            FROM api_audit_logs
            WHERE actor_id = $1
              AND created_at >= $2
              AND created_at < $3
            "#,
            consumer_id,
            period_start,
            period_end
        )
        .fetch_one(&*self.pool)
        .await?;

        let total_requests = stats.total_requests;
        let successful_requests = stats.successful_requests;
        let failed_requests = stats.failed_requests;

        let error_rate = if total_requests > 0 {
            failed_requests as f64 / total_requests as f64
        } else {
            0.0
        };

        // Get rate limit breaches (from a hypothetical rate_limit_events table or metric)
        // For now, we'll use a placeholder
        let rate_limit_breaches = 0;

        // Determine consumer tier (placeholder - should come from oauth_clients or similar)
        let consumer_tier = ConsumerTier::Free;

        let snapshot = ConsumerUsageSnapshot {
            id: Uuid::new_v4(),
            consumer_id: consumer_id.to_string(),
            consumer_tier,
            snapshot_period: period,
            period_start,
            period_end,
            total_requests,
            successful_requests,
            failed_requests,
            error_rate,
            p50_response_time_ms: stats.p50_latency.unwrap_or(0.0) as i32,
            p99_response_time_ms: stats.p99_latency.unwrap_or(0.0) as i32,
            avg_response_time_ms: stats.avg_latency.unwrap_or(0.0) as i32,
            rate_limit_breaches,
            unique_endpoints: stats.unique_endpoints as i32,
            snapshot_timestamp: Utc::now(),
            created_at: Utc::now(),
        };

        self.repo.insert_usage_snapshot(&snapshot).await?;

        // Generate endpoint-level breakdown
        self.generate_endpoint_usage(consumer_id, period, period_start, period_end)
            .await?;

        // Update feature adoption
        self.update_feature_adoption(consumer_id, period_start, period_end)
            .await?;

        // Generate revenue attribution
        self.generate_revenue_attribution(consumer_id, period, period_start, period_end)
            .await?;

        Ok(())
    }

    /// Generate per-endpoint usage breakdown
    async fn generate_endpoint_usage(
        &self,
        consumer_id: &str,
        period: SnapshotPeriod,
        period_start: DateTime<Utc>,
        period_end: DateTime<Utc>,
    ) -> Result<(), anyhow::Error> {
        let endpoint_stats = sqlx::query!(
            r#"
            SELECT 
                request_path,
                request_method,
                COUNT(*) as "request_count!",
                COUNT(*) FILTER (WHERE outcome = 'success') as "success_count!",
                COUNT(*) FILTER (WHERE outcome = 'failure') as "error_count!",
                AVG(response_latency_ms) as "avg_latency"
            FROM api_audit_logs
            WHERE actor_id = $1
              AND created_at >= $2
              AND created_at < $3
            GROUP BY request_path, request_method
            "#,
            consumer_id,
            period_start,
            period_end
        )
        .fetch_all(&*self.pool)
        .await?;

        for stat in endpoint_stats {
            let usage = ConsumerEndpointUsage {
                id: Uuid::new_v4(),
                consumer_id: consumer_id.to_string(),
                endpoint_path: stat.request_path,
                http_method: stat.request_method,
                snapshot_period: period,
                period_start,
                period_end,
                request_count: stat.request_count,
                success_count: stat.success_count,
                error_count: stat.error_count,
                avg_latency_ms: stat.avg_latency.unwrap_or(0.0) as i32,
                created_at: Utc::now(),
            };

            self.repo.insert_endpoint_usage(&usage).await?;
        }

        Ok(())
    }

    /// Update feature adoption based on endpoint usage
    async fn update_feature_adoption(
        &self,
        consumer_id: &str,
        period_start: DateTime<Utc>,
        period_end: DateTime<Utc>,
    ) -> Result<(), anyhow::Error> {
        // Map endpoints to features
        let feature_map = Self::get_feature_map();

        let endpoints = sqlx::query_scalar!(
            r#"
            SELECT DISTINCT request_path
            FROM api_audit_logs
            WHERE actor_id = $1
              AND created_at >= $2
              AND created_at < $3
            "#,
            consumer_id,
            period_start,
            period_end
        )
        .fetch_all(&*self.pool)
        .await?;

        for endpoint in endpoints {
            if let Some(feature) = Self::map_endpoint_to_feature(&endpoint, &feature_map) {
                self.repo
                    .upsert_feature_adoption(consumer_id, &feature)
                    .await?;
            }
        }

        Ok(())
    }

    /// Generate revenue attribution from transactions
    async fn generate_revenue_attribution(
        &self,
        consumer_id: &str,
        period: SnapshotPeriod,
        period_start: DateTime<Utc>,
        period_end: DateTime<Utc>,
    ) -> Result<(), anyhow::Error> {
        // Query transactions table for revenue data
        // This is a placeholder - actual implementation depends on transaction schema
        let revenue = ConsumerRevenueAttribution {
            id: Uuid::new_v4(),
            consumer_id: consumer_id.to_string(),
            snapshot_period: period,
            period_start,
            period_end,
            total_transaction_count: 0,
            total_transaction_volume: 0.0,
            total_fees_generated: 0.0,
            cngn_volume_transferred: 0.0,
            created_at: Utc::now(),
        };

        self.repo.insert_revenue_attribution(&revenue).await?;
        Ok(())
    }

    /// Map endpoints to feature names
    fn get_feature_map() -> HashMap<String, String> {
        let mut map = HashMap::new();
        map.insert("/api/onramp".to_string(), "onramp".to_string());
        map.insert("/api/offramp".to_string(), "offramp".to_string());
        map.insert("/api/bills".to_string(), "bills".to_string());
        map.insert("/api/batch".to_string(), "batch".to_string());
        map.insert("/api/recurring".to_string(), "recurring".to_string());
        map
    }

    fn map_endpoint_to_feature(
        endpoint: &str,
        feature_map: &HashMap<String, String>,
    ) -> Option<String> {
        for (prefix, feature) in feature_map {
            if endpoint.starts_with(prefix) {
                return Some(feature.clone());
            }
        }
        None
    }
}

#[derive(Debug)]
pub struct SnapshotGenerationResult {
    pub consumers_processed: i32,
    pub snapshots_created: i32,
    pub duration_ms: i64,
    pub status: String,
    pub errors: Vec<String>,
}
