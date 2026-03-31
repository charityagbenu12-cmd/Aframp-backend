use crate::database::error::{DatabaseError, DatabaseErrorKind};
use crate::database::repository::{Repository, TransactionalRepository};
use crate::database::transaction_repository::TransactionId; // Assume transaction_id type alias Uuid
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::{FromRow, PgPool};
use std::str::FromStr;
use uuid::Uuid;

/// NotificationHistory entity matching DB table
#[derive(Debug, Clone, FromRow, serde::Serialize)]
pub struct NotificationHistory {
    pub id: Uuid,
    pub transaction_id: Uuid,
    pub event_type: String,
    pub channel: String,
    pub recipient: Option<String>,
    pub payload: Value,
    pub status: String,
    pub retry_count: i32,
    pub error_message: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// NotificationRepository for notification_history ops
pub struct NotificationRepository {
    pool: PgPool,
}

impl NotificationRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Log new notification attempt
    pub async fn log_notification(
        &self,
        transaction_id: Uuid,
        event_type: &str,
        channel: &str,
        recipient: Option<&str>,
        payload: Value,
    ) -> Result<NotificationHistory, DatabaseError> {
        sqlx::query_as(
            "INSERT INTO notification_history (transaction_id, event_type, channel, recipient, payload, status) 
             VALUES ($1, $2, $3, $4, $5, 'pending')
             RETURNING *",
        )
        .bind(transaction_id)
        .bind(event_type)
        .bind(channel)
        .bind(recipient)
        .bind(payload)
        .fetch_one(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)
    }

    /// Get notifications for specific transaction
    pub async fn get_by_transaction_id(
        &self,
        transaction_id: Uuid,
        limit: i64,
    ) -> Result<Vec<NotificationHistory>, DatabaseError> {
        sqlx::query_as(
            "SELECT * FROM notification_history 
             WHERE transaction_id = $1 
             ORDER BY created_at DESC 
             LIMIT $2",
        )
        .bind(transaction_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)
    }

    /// Get pending notifications for retry
    pub async fn get_pending(&self, limit: i64) -> Result<Vec<NotificationHistory>, DatabaseError> {
        sqlx::query_as(
            "SELECT * FROM notification_history 
             WHERE status = 'pending' OR (status = 'failed' AND retry_count < 3)
             ORDER BY created_at ASC 
             LIMIT $1",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)
    }

    /// Mark as delivered
    pub async fn mark_delivered(&self, id: Uuid) -> Result<NotificationHistory, DatabaseError> {
        sqlx::query_as(
            "UPDATE notification_history 
             SET status = 'delivered', updated_at = NOW() 
             WHERE id = $1 AND (status = 'pending' OR status = 'failed')
             RETURNING *",
        )
        .bind(id)
        .fetch_one(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)
    }

    /// Mark as failed + increment retry
    pub async fn mark_failed(&self, id: Uuid, error: &str) -> Result<NotificationHistory, DatabaseError> {
        sqlx::query_as(
            "UPDATE notification_history 
             SET status = CASE WHEN retry_count + 1 >= 3 THEN 'failed' ELSE 'pending' END,
                 retry_count = retry_count + 1,
                 error_message = $2,
                 updated_at = NOW()
             WHERE id = $1
             RETURNING *",
        )
        .bind(id)
        .bind(error)
        .fetch_one(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)
    }
}

#[async_trait]
impl Repository for NotificationRepository {
    type Entity = NotificationHistory;

    async fn find_by_id(&self, id: &str) -> Result<Option<Self::Entity>, DatabaseError> {
        let uuid = Uuid::parse_str(id).map_err(|e| DatabaseError::new(DatabaseErrorKind::Unknown {
            message: format!("Invalid UUID: {}", e),
        }))?;
        sqlx::query_as("SELECT * FROM notification_history WHERE id = $1")
            .bind(uuid)
            .fetch_optional(&self.pool)
            .await
            .map_err(DatabaseError::from_sqlx)
    }

    async fn find_all(&self) -> Result<Vec<Self::Entity>, DatabaseError> {
        sqlx::query_as("SELECT * FROM notification_history ORDER BY created_at DESC")
            .fetch_all(&self.pool)
            .await
            .map_err(DatabaseError::from_sqlx)
    }

    async fn insert(&self, entity: &Self::Entity) -> Result<Self::Entity, DatabaseError> {
        // Impl similar to log_notification, omitted for brevity
        self.log_notification(entity.transaction_id, &entity.event_type, &entity.channel, None, entity.payload.clone()).await
    }

    async fn update(&self, _id: &str, _entity: &Self::Entity) -> Result<Self::Entity, DatabaseError> {
        // Generic update via direct query
        todo!("Implement generic update")
    }

    async fn delete(&self, id: &str) -> Result<bool, DatabaseError> {
        let uuid = Uuid::parse_str(id).map_err(|_| DatabaseError::new(DatabaseErrorKind::Unknown { message: "Invalid ID".to_string() }))?;
        let result = sqlx::query("DELETE FROM notification_history WHERE id = $1")
            .bind(uuid)
            .execute(&self.pool)
            .await
            .map_err(DatabaseError::from_sqlx)?;
        Ok(result.rows_affected() > 0)
    }
}

impl TransactionalRepository for NotificationRepository {
    fn pool(&self) -> &PgPool {
        &self.pool
    }
}

