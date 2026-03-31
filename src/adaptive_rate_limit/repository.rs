//! Database repository for adaptive rate limiting persistence.
//!
//! Persists:
//!   - Signal snapshots (for historical analysis)
//!   - Mode transition records (immutable audit trail)

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::adaptive_rate_limit::models::{ModeTransitionRecord, SignalSnapshot};

#[derive(Clone)]
pub struct AdaptiveRateLimitRepository {
    pool: PgPool,
}

impl AdaptiveRateLimitRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Persist a signal snapshot for historical analysis.
    pub async fn persist_signal_snapshot(
        &self,
        snapshot: &SignalSnapshot,
    ) -> Result<(), sqlx::Error> {
        sqlx::query!(
            r#"
            INSERT INTO adaptive_rl_signal_snapshots
                (captured_at, cpu_utilisation, db_pool_utilisation,
                 redis_memory_pressure, request_queue_depth,
                 error_rate, p99_response_time_ms)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            "#,
            snapshot.captured_at,
            snapshot.cpu_utilisation,
            snapshot.db_pool_utilisation,
            snapshot.redis_memory_pressure,
            snapshot.request_queue_depth as i64,
            snapshot.error_rate,
            snapshot.p99_response_time_ms,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Persist a mode transition record.
    pub async fn persist_transition(
        &self,
        record: &ModeTransitionRecord,
    ) -> Result<(), sqlx::Error> {
        let signal_values = serde_json::to_value(&record.signal_values)
            .unwrap_or(serde_json::Value::Null);

        sqlx::query!(
            r#"
            INSERT INTO adaptive_rl_mode_transitions
                (id, from_mode, to_mode, trigger_signal, signal_values,
                 reason, is_manual_override, transitioned_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            "#,
            record.id,
            record.from_mode.as_str(),
            record.to_mode.as_str(),
            record.trigger_signal,
            signal_values,
            record.reason,
            record.is_manual_override,
            record.transitioned_at,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Fetch the most recent N mode transitions.
    pub async fn recent_transitions(
        &self,
        limit: i64,
    ) -> Result<Vec<ModeTransitionRow>, sqlx::Error> {
        let rows = sqlx::query_as!(
            ModeTransitionRow,
            r#"
            SELECT id, from_mode, to_mode, trigger_signal, reason,
                   is_manual_override, transitioned_at
            FROM adaptive_rl_mode_transitions
            ORDER BY transitioned_at DESC
            LIMIT $1
            "#,
            limit,
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }
}

#[derive(Debug, sqlx::FromRow, serde::Serialize)]
pub struct ModeTransitionRow {
    pub id: Uuid,
    pub from_mode: String,
    pub to_mode: String,
    pub trigger_signal: String,
    pub reason: String,
    pub is_manual_override: bool,
    pub transitioned_at: DateTime<Utc>,
}
