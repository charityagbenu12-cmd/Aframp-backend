use super::models::*;
use super::repository::AnalyticsRepository;
use chrono::{DateTime, Duration, Utc};
use serde_json::json;
use sqlx::PgPool;
use std::sync::Arc;
use tracing::{info, warn};
use uuid::Uuid;

pub struct HealthScoreCalculator {
    pool: Arc<PgPool>,
    repo: Arc<AnalyticsRepository>,
}

impl HealthScoreCalculator {
    pub fn new(pool: Arc<PgPool>, repo: Arc<AnalyticsRepository>) -> Self {
        Self { pool, repo }
    }

    /// Calculate health score for a consumer
    pub async fn calculate_health_score(
        &self,
        consumer_id: &str,
    ) -> Result<ConsumerHealthScore, anyhow::Error> {
        let config = self.repo.get_active_health_config().await?;
        let lookback = Duration::days(config.trend_lookback_days as i64);
        let period_start = Utc::now() - lookback;

        // Calculate individual factor scores
        let error_rate_score = self.calculate_error_rate_score(consumer_id, period_start).await?;
        let rate_limit_score = self.calculate_rate_limit_score(consumer_id, period_start).await?;
        let auth_failure_score = self.calculate_auth_failure_score(consumer_id, period_start).await?;
        let webhook_delivery_score = self.calculate_webhook_delivery_score(consumer_id, period_start).await?;
        let activity_recency_score = self.calculate_activity_recency_score(consumer_id).await?;

        // Calculate weighted health score
        let health_score = (
            error_rate_score as f64 * config.error_rate_weight +
            rate_limit_score as f64 * config.rate_limit_weight +
            auth_failure_score as f64 * config.auth_failure_weight +
            webhook_delivery_score as f64 * config.webhook_delivery_weight +
            activity_recency_score as f64 * config.activity_recency_weight
        ).round() as i32;

        // Get previous score for trend analysis
        let previous_score_record = self.repo.get_latest_health_score(consumer_id).await?;
        let previous_score = previous_score_record.as_ref().map(|s| s.health_score);
        let score_change = previous_score.map(|prev| health_score - prev).unwrap_or(0);

        // Determine trend
        let health_trend = self.determine_trend(consumer_id, health_score, &config).await?;

        // Identify risk factors
        let mut risk_factors = Vec::new();
        if error_rate_score < 70 {
            risk_factors.push("high_error_rate");
        }
        if rate_limit_score < 70 {
            risk_factors.push("frequent_rate_limit_breaches");
        }
        if auth_failure_score < 70 {
            risk_factors.push("authentication_failures");
        }
        if webhook_delivery_score < 70 {
            risk_factors.push("webhook_delivery_issues");
        }
        if activity_recency_score < 70 {
            risk_factors.push("low_activity");
        }

        let is_at_risk = health_score < config.at_risk_threshold;

        let score = ConsumerHealthScore {
            id: Uuid::new_v4(),
            consumer_id: consumer_id.to_string(),
            health_score,
            error_rate_score,
            rate_limit_score,
            auth_failure_score,
            webhook_delivery_score,
            activity_recency_score,
            health_trend,
            previous_score,
            score_change,
            is_at_risk,
            risk_factors: if risk_factors.is_empty() {
                None
            } else {
                Some(json!(risk_factors))
            },
            score_timestamp: Utc::now(),
            created_at: Utc::now(),
        };

        self.repo.insert_health_score(&score).await?;

        // Update metrics
        crate::analytics::metrics::consumer_health_score()
            .with_label_values(&[consumer_id])
            .set(health_score as f64);

        if is_at_risk {
            crate::analytics::metrics::at_risk_consumers_total().inc();
            info!(
                consumer_id = %consumer_id,
                health_score,
                ?risk_factors,
                "Consumer flagged as at-risk"
            );
        }

        Ok(score)
    }

    async fn calculate_error_rate_score(
        &self,
        consumer_id: &str,
        period_start: DateTime<Utc>,
    ) -> Result<i32, anyhow::Error> {
        let stats = sqlx::query!(
            r#"
            SELECT 
                COUNT(*) as "total!",
                COUNT(*) FILTER (WHERE outcome = 'failure') as "failures!"
            FROM api_audit_logs
            WHERE actor_id = $1 AND created_at >= $2
            "#,
            consumer_id,
            period_start
        )
        .fetch_one(&*self.pool)
        .await?;

        if stats.total == 0 {
            return Ok(100);
        }

        let error_rate = stats.failures as f64 / stats.total as f64;
        // Score: 100 at 0% errors, 0 at 10%+ errors
        let score = ((1.0 - (error_rate * 10.0).min(1.0)) * 100.0).round() as i32;
        Ok(score.clamp(0, 100))
    }

    async fn calculate_rate_limit_score(
        &self,
        consumer_id: &str,
        period_start: DateTime<Utc>,
    ) -> Result<i32, anyhow::Error> {
        // Placeholder - would query rate limit breach events
        Ok(100)
    }

    async fn calculate_auth_failure_score(
        &self,
        consumer_id: &str,
        period_start: DateTime<Utc>,
    ) -> Result<i32, anyhow::Error> {
        let failures = sqlx::query_scalar!(
            r#"
            SELECT COUNT(*)
            FROM api_audit_logs
            WHERE actor_id = $1 
              AND created_at >= $2
              AND event_category = 'authentication'
              AND outcome = 'failure'
            "#,
            consumer_id,
            period_start
        )
        .fetch_one(&*self.pool)
        .await?
        .unwrap_or(0);

        // Score: 100 at 0 failures, decreases with more failures
        let score = (100.0 - (failures as f64 * 5.0).min(100.0)).round() as i32;
        Ok(score.clamp(0, 100))
    }

    async fn calculate_webhook_delivery_score(
        &self,
        _consumer_id: &str,
        _period_start: DateTime<Utc>,
    ) -> Result<i32, anyhow::Error> {
        // Placeholder - would query webhook_events table
        Ok(100)
    }

    async fn calculate_activity_recency_score(
        &self,
        consumer_id: &str,
    ) -> Result<i32, anyhow::Error> {
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
            let hours_since = (Utc::now() - last_activity).num_hours();
            // Score: 100 if active in last 24h, decreases over 7 days
            let score = if hours_since <= 24 {
                100
            } else if hours_since >= 168 {
                0
            } else {
                (100.0 - ((hours_since - 24) as f64 / 144.0 * 100.0)).round() as i32
            };
            Ok(score.clamp(0, 100))
        } else {
            Ok(0)
        }
    }

    async fn determine_trend(
        &self,
        consumer_id: &str,
        current_score: i32,
        config: &HealthScoreConfig,
    ) -> Result<HealthTrend, anyhow::Error> {
        let lookback = Duration::days(config.trend_lookback_days as i64);
        let period_start = Utc::now() - lookback;

        let historical_scores = sqlx::query_scalar!(
            r#"
            SELECT health_score
            FROM consumer_health_scores
            WHERE consumer_id = $1 AND score_timestamp >= $2
            ORDER BY score_timestamp ASC
            "#,
            consumer_id,
            period_start
        )
        .fetch_all(&*self.pool)
        .await?;

        if historical_scores.len() < 2 {
            return Ok(HealthTrend::Stable);
        }

        let avg_historical = historical_scores.iter().sum::<i32>() as f64 / historical_scores.len() as f64;
        let diff = current_score as f64 - avg_historical;

        if diff > 5.0 {
            Ok(HealthTrend::Improving)
        } else if diff < -5.0 {
            Ok(HealthTrend::Declining)
        } else {
            Ok(HealthTrend::Stable)
        }
    }
}
