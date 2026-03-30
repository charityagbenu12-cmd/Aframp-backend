//! Database repository for abuse detection records

use super::case_management::{AbuseCase, AbuseCaseStatus};
use super::response::{ResponseAction, ResponseTier};
use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use sqlx::{PgPool, Row};
use uuid::Uuid;

pub struct AbuseDetectionRepository {
    pool: PgPool,
}

impl AbuseDetectionRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Create a new abuse case
    pub async fn create_case(&self, case: &AbuseCase) -> Result<(), sqlx::Error> {
        sqlx::query!(
            r#"
            INSERT INTO abuse_cases (
                id, consumer_ids, detection_signals, composite_confidence,
                response_tier, status, created_at, updated_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            "#,
            case.id,
            &case.consumer_ids,
            serde_json::to_value(&case.detection_signals).unwrap(),
            case.composite_confidence,
            case.response_tier.as_str(),
            case.status as AbuseCaseStatus,
            case.created_at,
            case.updated_at,
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Get abuse case by ID
    pub async fn get_case(&self, case_id: Uuid) -> Result<Option<AbuseCase>, sqlx::Error> {
        let row = sqlx::query!(
            r#"
            SELECT id, consumer_ids, detection_signals, composite_confidence,
                   response_tier, status as "status: AbuseCaseStatus",
                   created_at, updated_at, resolved_at, resolution_notes,
                   escalated_by, resolved_by, false_positive, whitelisted_signals
            FROM abuse_cases
            WHERE id = $1
            "#,
            case_id
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| AbuseCase {
            id: r.id,
            consumer_ids: r.consumer_ids,
            detection_signals: serde_json::from_value(r.detection_signals).unwrap_or_default(),
            composite_confidence: r.composite_confidence,
            response_tier: match r.response_tier.as_str() {
                "monitor" => ResponseTier::Monitor,
                "soft" => ResponseTier::Soft,
                "hard" => ResponseTier::Hard,
                "critical" => ResponseTier::Critical,
                _ => ResponseTier::Monitor,
            },
            status: r.status,
            created_at: r.created_at,
            updated_at: r.updated_at,
            resolved_at: r.resolved_at,
            resolution_notes: r.resolution_notes,
            escalated_by: r.escalated_by,
            resolved_by: r.resolved_by,
            false_positive: r.false_positive,
            whitelisted_signals: r.whitelisted_signals,
        }))
    }

    /// List abuse cases with pagination
    pub async fn list_cases(
        &self,
        status_filter: Option<AbuseCaseStatus>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<AbuseCase>, sqlx::Error> {
        let rows = if let Some(status) = status_filter {
            sqlx::query!(
                r#"
                SELECT id, consumer_ids, detection_signals, composite_confidence,
                       response_tier, status as "status: AbuseCaseStatus",
                       created_at, updated_at, resolved_at, resolution_notes,
                       escalated_by, resolved_by, false_positive, whitelisted_signals
                FROM abuse_cases
                WHERE status = $1
                ORDER BY created_at DESC
                LIMIT $2 OFFSET $3
                "#,
                status as AbuseCaseStatus,
                limit,
                offset
            )
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query!(
                r#"
                SELECT id, consumer_ids, detection_signals, composite_confidence,
                       response_tier, status as "status: AbuseCaseStatus",
                       created_at, updated_at, resolved_at, resolution_notes,
                       escalated_by, resolved_by, false_positive, whitelisted_signals
                FROM abuse_cases
                ORDER BY created_at DESC
                LIMIT $1 OFFSET $2
                "#,
                limit,
                offset
            )
            .fetch_all(&self.pool)
            .await?
        };

        Ok(rows
            .into_iter()
            .map(|r| AbuseCase {
                id: r.id,
                consumer_ids: r.consumer_ids,
                detection_signals: serde_json::from_value(r.detection_signals).unwrap_or_default(),
                composite_confidence: r.composite_confidence,
                response_tier: match r.response_tier.as_str() {
                    "monitor" => ResponseTier::Monitor,
                    "soft" => ResponseTier::Soft,
                    "hard" => ResponseTier::Hard,
                    "critical" => ResponseTier::Critical,
                    _ => ResponseTier::Monitor,
                },
                status: r.status,
                created_at: r.created_at,
                updated_at: r.updated_at,
                resolved_at: r.resolved_at,
                resolution_notes: r.resolution_notes,
                escalated_by: r.escalated_by,
                resolved_by: r.resolved_by,
                false_positive: r.false_positive,
                whitelisted_signals: r.whitelisted_signals,
            })
            .collect())
    }

    /// Update abuse case
    pub async fn update_case(&self, case: &AbuseCase) -> Result<(), sqlx::Error> {
        sqlx::query!(
            r#"
            UPDATE abuse_cases
            SET status = $2, updated_at = $3, resolved_at = $4,
                resolution_notes = $5, escalated_by = $6, resolved_by = $7,
                false_positive = $8, whitelisted_signals = $9, response_tier = $10
            WHERE id = $1
            "#,
            case.id,
            case.status as AbuseCaseStatus,
            case.updated_at,
            case.resolved_at,
            case.resolution_notes,
            case.escalated_by,
            case.resolved_by,
            case.false_positive,
            &case.whitelisted_signals,
            case.response_tier.as_str(),
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Record response action
    pub async fn record_response_action(&self, action: &ResponseAction) -> Result<(), sqlx::Error> {
        sqlx::query!(
            r#"
            INSERT INTO abuse_response_actions (
                id, tier, consumer_ids, applied_at, expires_at,
                reason, evidence_case_id, actions_taken, notification_sent
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            "#,
            action.id,
            action.tier.as_str(),
            &action.consumer_ids,
            action.applied_at,
            action.expires_at,
            action.reason,
            action.evidence_case_id,
            &action.actions_taken,
            action.notification_sent,
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Get active response actions for consumer
    pub async fn get_active_responses(
        &self,
        consumer_id: Uuid,
    ) -> Result<Vec<ResponseAction>, sqlx::Error> {
        let rows = sqlx::query!(
            r#"
            SELECT id, tier, consumer_ids, applied_at, expires_at,
                   reason, evidence_case_id, actions_taken, notification_sent
            FROM abuse_response_actions
            WHERE $1 = ANY(consumer_ids)
              AND (expires_at IS NULL OR expires_at > NOW())
            ORDER BY applied_at DESC
            "#,
            consumer_id
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| ResponseAction {
                id: r.id,
                tier: match r.tier.as_str() {
                    "monitor" => ResponseTier::Monitor,
                    "soft" => ResponseTier::Soft,
                    "hard" => ResponseTier::Hard,
                    "critical" => ResponseTier::Critical,
                    _ => ResponseTier::Monitor,
                },
                consumer_ids: r.consumer_ids,
                applied_at: r.applied_at,
                expires_at: r.expires_at,
                reason: r.reason,
                evidence_case_id: r.evidence_case_id,
                actions_taken: r.actions_taken,
                notification_sent: r.notification_sent,
            })
            .collect())
    }

    /// Get case statistics
    pub async fn get_statistics(
        &self,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> Result<CaseStatistics, sqlx::Error> {
        let row = sqlx::query!(
            r#"
            SELECT
                COUNT(*) FILTER (WHERE status = 'open') as "open_count!",
                COUNT(*) FILTER (WHERE status = 'resolved') as "resolved_count!",
                COUNT(*) FILTER (WHERE status = 'dismissed') as "dismissed_count!",
                COUNT(*) FILTER (WHERE false_positive = true) as "false_positive_count!",
                COUNT(*) FILTER (WHERE response_tier = 'monitor') as "monitor_count!",
                COUNT(*) FILTER (WHERE response_tier = 'soft') as "soft_count!",
                COUNT(*) FILTER (WHERE response_tier = 'hard') as "hard_count!",
                COUNT(*) FILTER (WHERE response_tier = 'critical') as "critical_count!"
            FROM abuse_cases
            WHERE created_at BETWEEN $1 AND $2
            "#,
            from,
            to
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(CaseStatistics {
            open_count: row.open_count,
            resolved_count: row.resolved_count,
            dismissed_count: row.dismissed_count,
            false_positive_count: row.false_positive_count,
            monitor_count: row.monitor_count,
            soft_count: row.soft_count,
            hard_count: row.hard_count,
            critical_count: row.critical_count,
        })
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct CaseStatistics {
    pub open_count: i64,
    pub resolved_count: i64,
    pub dismissed_count: i64,
    pub false_positive_count: i64,
    pub monitor_count: i64,
    pub soft_count: i64,
    pub hard_count: i64,
    pub critical_count: i64,
}
