use crate::database::error::{DatabaseError, DatabaseErrorKind};
use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Entities
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, FromRow)]
pub struct RecurringSchedule {
    pub id: Uuid,
    pub wallet_address: String,
    pub transaction_type: String,
    pub provider: Option<String>,
    pub amount: sqlx::types::BigDecimal,
    pub currency: String,
    pub frequency: String,
    pub custom_interval_days: Option<i32>,
    pub payment_metadata: serde_json::Value,
    pub status: String,
    pub failure_count: i32,
    pub failure_threshold: i32,
    pub next_execution_at: DateTime<Utc>,
    pub last_executed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow)]
pub struct RecurringExecution {
    pub id: Uuid,
    pub schedule_id: Uuid,
    pub scheduled_at: DateTime<Utc>,
    pub executed_at: DateTime<Utc>,
    pub outcome: String,
    pub transaction_id: Option<Uuid>,
    pub error_message: Option<String>,
    pub created_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Repository
// ---------------------------------------------------------------------------

pub struct RecurringPaymentRepository {
    pool: PgPool,
}

impl RecurringPaymentRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    // -----------------------------------------------------------------------
    // Schedule CRUD
    // -----------------------------------------------------------------------

    pub async fn create_schedule(
        &self,
        wallet_address: &str,
        transaction_type: &str,
        provider: Option<&str>,
        amount: sqlx::types::BigDecimal,
        currency: &str,
        frequency: &str,
        custom_interval_days: Option<i32>,
        payment_metadata: serde_json::Value,
        failure_threshold: i32,
        next_execution_at: DateTime<Utc>,
    ) -> Result<RecurringSchedule, DatabaseError> {
        sqlx::query_as::<_, RecurringSchedule>(
            r#"
            INSERT INTO recurring_payment_schedules
                (wallet_address, transaction_type, provider, amount, currency,
                 frequency, custom_interval_days, payment_metadata,
                 failure_threshold, next_execution_at)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
            RETURNING *
            "#,
        )
        .bind(wallet_address)
        .bind(transaction_type)
        .bind(provider)
        .bind(amount)
        .bind(currency)
        .bind(frequency)
        .bind(custom_interval_days)
        .bind(payment_metadata)
        .bind(failure_threshold)
        .bind(next_execution_at)
        .fetch_one(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)
    }

    pub async fn find_by_id(&self, id: Uuid) -> Result<Option<RecurringSchedule>, DatabaseError> {
        sqlx::query_as::<_, RecurringSchedule>(
            "SELECT * FROM recurring_payment_schedules WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)
    }

    /// Find schedule by id, enforcing wallet ownership.
    pub async fn find_by_id_and_wallet(
        &self,
        id: Uuid,
        wallet_address: &str,
    ) -> Result<Option<RecurringSchedule>, DatabaseError> {
        sqlx::query_as::<_, RecurringSchedule>(
            "SELECT * FROM recurring_payment_schedules WHERE id = $1 AND wallet_address = $2",
        )
        .bind(id)
        .bind(wallet_address)
        .fetch_optional(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)
    }

    pub async fn list_for_wallet(
        &self,
        wallet_address: &str,
        status_filter: Option<&str>,
        type_filter: Option<&str>,
    ) -> Result<Vec<RecurringSchedule>, DatabaseError> {
        sqlx::query_as::<_, RecurringSchedule>(
            r#"
            SELECT * FROM recurring_payment_schedules
            WHERE wallet_address = $1
              AND ($2::text IS NULL OR status = $2::recurring_status)
              AND ($3::text IS NULL OR transaction_type = $3)
            ORDER BY created_at DESC
            "#,
        )
        .bind(wallet_address)
        .bind(status_filter)
        .bind(type_filter)
        .fetch_all(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)
    }

    /// Fetch all active schedules whose next_execution_at <= now (for the worker).
    pub async fn fetch_due_schedules(
        &self,
        now: DateTime<Utc>,
        limit: i64,
    ) -> Result<Vec<RecurringSchedule>, DatabaseError> {
        sqlx::query_as::<_, RecurringSchedule>(
            r#"
            SELECT * FROM recurring_payment_schedules
            WHERE status = 'active'
              AND next_execution_at <= $1
            ORDER BY next_execution_at ASC
            LIMIT $2
            "#,
        )
        .bind(now)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)
    }

    pub async fn update_schedule(
        &self,
        id: Uuid,
        amount: Option<sqlx::types::BigDecimal>,
        frequency: Option<&str>,
        custom_interval_days: Option<i32>,
        next_execution_at: Option<DateTime<Utc>>,
        status: Option<&str>,
    ) -> Result<RecurringSchedule, DatabaseError> {
        sqlx::query_as::<_, RecurringSchedule>(
            r#"
            UPDATE recurring_payment_schedules SET
                amount              = COALESCE($2, amount),
                frequency           = COALESCE($3::recurring_frequency, frequency),
                custom_interval_days = CASE WHEN $3 IS NOT NULL THEN $4 ELSE custom_interval_days END,
                next_execution_at   = COALESCE($5, next_execution_at),
                status              = COALESCE($6::recurring_status, status)
            WHERE id = $1
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(amount)
        .bind(frequency)
        .bind(custom_interval_days)
        .bind(next_execution_at)
        .bind(status)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            if matches!(e, sqlx::Error::RowNotFound) {
                DatabaseError::new(DatabaseErrorKind::NotFound {
                    entity: "RecurringSchedule".to_string(),
                    id: id.to_string(),
                })
            } else {
                DatabaseError::from_sqlx(e)
            }
        })
    }

    /// Soft-cancel: set status = 'cancelled'.
    pub async fn cancel_schedule(&self, id: Uuid) -> Result<RecurringSchedule, DatabaseError> {
        sqlx::query_as::<_, RecurringSchedule>(
            "UPDATE recurring_payment_schedules SET status = 'cancelled' WHERE id = $1 RETURNING *",
        )
        .bind(id)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            if matches!(e, sqlx::Error::RowNotFound) {
                DatabaseError::new(DatabaseErrorKind::NotFound {
                    entity: "RecurringSchedule".to_string(),
                    id: id.to_string(),
                })
            } else {
                DatabaseError::from_sqlx(e)
            }
        })
    }

    /// After successful execution: reset failure_count, advance next_execution_at.
    pub async fn record_success(
        &self,
        id: Uuid,
        next_execution_at: DateTime<Utc>,
    ) -> Result<(), DatabaseError> {
        sqlx::query(
            r#"
            UPDATE recurring_payment_schedules
            SET failure_count = 0,
                last_executed_at = now(),
                next_execution_at = $2
            WHERE id = $1
            "#,
        )
        .bind(id)
        .bind(next_execution_at)
        .execute(&self.pool)
        .await
        .map(|_| ())
        .map_err(DatabaseError::from_sqlx)
    }

    /// After failed execution: increment failure_count, advance next_execution_at.
    /// If failure_count reaches threshold, suspend the schedule.
    pub async fn record_failure(
        &self,
        id: Uuid,
        next_execution_at: DateTime<Utc>,
    ) -> Result<RecurringSchedule, DatabaseError> {
        sqlx::query_as::<_, RecurringSchedule>(
            r#"
            UPDATE recurring_payment_schedules
            SET failure_count     = failure_count + 1,
                last_executed_at  = now(),
                next_execution_at = $2,
                status = CASE
                    WHEN failure_count + 1 >= failure_threshold THEN 'suspended'::recurring_status
                    ELSE status
                END
            WHERE id = $1
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(next_execution_at)
        .fetch_one(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)
    }

    // -----------------------------------------------------------------------
    // Execution history
    // -----------------------------------------------------------------------

    /// Insert an execution record. Returns None if the idempotency key already exists.
    pub async fn insert_execution(
        &self,
        schedule_id: Uuid,
        scheduled_at: DateTime<Utc>,
        outcome: &str,
        transaction_id: Option<Uuid>,
        error_message: Option<&str>,
    ) -> Result<Option<RecurringExecution>, DatabaseError> {
        sqlx::query_as::<_, RecurringExecution>(
            r#"
            INSERT INTO recurring_payment_executions
                (schedule_id, scheduled_at, outcome, transaction_id, error_message)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (schedule_id, scheduled_at) DO NOTHING
            RETURNING *
            "#,
        )
        .bind(schedule_id)
        .bind(scheduled_at)
        .bind(outcome)
        .bind(transaction_id)
        .bind(error_message)
        .fetch_optional(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)
    }

    pub async fn list_executions_for_schedule(
        &self,
        schedule_id: Uuid,
    ) -> Result<Vec<RecurringExecution>, DatabaseError> {
        sqlx::query_as::<_, RecurringExecution>(
            "SELECT * FROM recurring_payment_executions WHERE schedule_id = $1 ORDER BY scheduled_at DESC",
        )
        .bind(schedule_id)
        .fetch_all(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)
    }
}
