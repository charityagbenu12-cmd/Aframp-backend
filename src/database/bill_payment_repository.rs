use crate::database::error::{DatabaseError, DatabaseErrorKind};
use crate::database::repository::{Repository, TransactionalRepository};
use async_trait::async_trait;
use sqlx::{FromRow, PgPool};
use uuid::Uuid;
use serde_json::Value;
use chrono::{DateTime, Utc};

/// Bill Payment entity extending a core transaction
#[derive(Debug, Clone, FromRow)]
pub struct BillPayment {
    pub id: Uuid,
    pub transaction_id: Uuid,
    pub provider_name: String,
    pub account_number: String,
    pub bill_type: String,
    pub due_date: Option<DateTime<Utc>>,
    pub paid_with_afri: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    // Bill Processor State
    pub status: String,
    pub provider_reference: Option<String>,
    pub token: Option<String>,
    pub provider_response: Option<Value>,
    pub retry_count: i32,
    pub last_retry_at: Option<DateTime<Utc>>,
    pub error_message: Option<String>,
    pub refund_tx_hash: Option<String>,
    pub account_verified: bool,
    pub verification_data: Option<Value>,
}

/// Repository for specifically managing bill payment details
pub struct BillPaymentRepository {
    pool: PgPool,
}

impl BillPaymentRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Find bill details by the core transaction ID
    pub async fn find_by_transaction_id(
        &self,
        transaction_id: Uuid,
    ) -> Result<Option<BillPayment>, DatabaseError> {
        sqlx::query_as::<_, BillPayment>(
            "SELECT * FROM bill_payments WHERE transaction_id = $1"
        )
        .bind(transaction_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)
    }

    /// Create new bill payment details for a transaction
    pub async fn create_bill_payment(
        &self,
        transaction_id: Uuid,
        provider_name: &str,
        account_number: &str,
        bill_type: &str,
        due_date: Option<DateTime<Utc>>,
        paid_with_afri: bool,
    ) -> Result<BillPayment, DatabaseError> {
        sqlx::query_as::<_, BillPayment>(
            "INSERT INTO bill_payments (transaction_id, provider_name, account_number, bill_type, due_date, paid_with_afri, status) 
             VALUES ($1, $2, $3, $4, $5, $6, 'pending_payment') 
             RETURNING *"
        )
        .bind(transaction_id)
        .bind(provider_name)
        .bind(account_number)
        .bind(bill_type)
        .bind(due_date)
        .bind(paid_with_afri)
        .fetch_one(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)
    }

    /// Update bill processing status and provider details
    pub async fn update_processing_status(
        &self,
        id: Uuid,
        status: &str,
        provider_reference: Option<&str>,
        token: Option<&str>,
        error_message: Option<&str>,
    ) -> Result<BillPayment, DatabaseError> {
        sqlx::query_as::<_, BillPayment>(
            "UPDATE bill_payments 
             SET status = $1, provider_reference = $2, token = $3, error_message = $4, updated_at = now() 
             WHERE id = $5 
             RETURNING *"
        )
        .bind(status)
        .bind(provider_reference)
        .bind(token)
        .bind(error_message)
        .bind(id)
        .fetch_one(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)
    }

    /// Find bill payments that need processing
    pub async fn find_pending_processing(&self, limit: i64) -> Result<Vec<BillPayment>, DatabaseError> {
        sqlx::query_as::<_, BillPayment>(
            "SELECT * FROM bill_payments 
             WHERE status IN ('cngn_received', 'verifying_account', 'processing_bill', 'provider_processing', 'retry_scheduled')
             ORDER BY created_at ASC 
             LIMIT $1"
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)
    }
}

#[async_trait]
impl Repository for BillPaymentRepository {
    type Entity = BillPayment;

    async fn find_by_id(&self, id: &str) -> Result<Option<Self::Entity>, DatabaseError> {
        let uuid = Uuid::parse_str(id).map_err(|e| {
            DatabaseError::new(DatabaseErrorKind::Unknown {
                message: format!("Invalid UUID: {}", e),
            })
        })?;
        sqlx::query_as::<_, BillPayment>(
            "SELECT * FROM bill_payments WHERE id = $1"
        )
        .bind(uuid)
        .fetch_optional(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)
    }

    async fn find_all(&self) -> Result<Vec<Self::Entity>, DatabaseError> {
        sqlx::query_as::<_, BillPayment>(
            "SELECT * FROM bill_payments ORDER BY created_at DESC"
        )
        .fetch_all(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)
    }

    async fn insert(&self, entity: &Self::Entity) -> Result<Self::Entity, DatabaseError> {
        sqlx::query_as::<_, BillPayment>(
            "INSERT INTO bill_payments (transaction_id, provider_name, account_number, bill_type, due_date, paid_with_afri, status) 
             VALUES ($1, $2, $3, $4, $5, $6, $7) 
             RETURNING *"
        )
        .bind(entity.transaction_id)
        .bind(&entity.provider_name)
        .bind(&entity.account_number)
        .bind(&entity.bill_type)
        .bind(entity.due_date)
        .bind(entity.paid_with_afri)
        .bind(&entity.status)
        .fetch_one(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)
    }

    async fn update(&self, id: &str, entity: &Self::Entity) -> Result<Self::Entity, DatabaseError> {
        let uuid = Uuid::parse_str(id).map_err(|e| {
            DatabaseError::new(DatabaseErrorKind::Unknown {
                message: format!("Invalid UUID: {}", e),
            })
        })?;
        sqlx::query_as::<_, BillPayment>(
            "UPDATE bill_payments 
             SET transaction_id = $1, provider_name = $2, account_number = $3, bill_type = $4, 
                 due_date = $5, paid_with_afri = $6, status = $7, provider_reference = $8, 
                 token = $9, provider_response = $10, retry_count = $11, last_retry_at = $12, 
                 error_message = $13, refund_tx_hash = $14, account_verified = $15, 
                 verification_data = $16, updated_at = now() 
             WHERE id = $17 
             RETURNING *"
        )
        .bind(entity.transaction_id)
        .bind(&entity.provider_name)
        .bind(&entity.account_number)
        .bind(&entity.bill_type)
        .bind(entity.due_date)
        .bind(entity.paid_with_afri)
        .bind(&entity.status)
        .bind(&entity.provider_reference)
        .bind(&entity.token)
        .bind(&entity.provider_response)
        .bind(entity.retry_count)
        .bind(entity.last_retry_at)
        .bind(&entity.error_message)
        .bind(&entity.refund_tx_hash)
        .bind(entity.account_verified)
        .bind(&entity.verification_data)
        .bind(uuid)
        .fetch_one(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)
    }

    async fn delete(&self, id: &str) -> Result<bool, DatabaseError> {
        let uuid = Uuid::parse_str(id).map_err(|e| {
            DatabaseError::new(DatabaseErrorKind::Unknown {
                message: format!("Invalid UUID: {}", e),
            })
        })?;
        let result = sqlx::query("DELETE FROM bill_payments WHERE id = $1")
            .bind(uuid)
            .execute(&self.pool)
            .await
            .map_err(DatabaseError::from_sqlx)?;
        Ok(result.rows_affected() > 0)
    }
}

impl TransactionalRepository for BillPaymentRepository {
    fn pool(&self) -> &PgPool {
        &self.pool
    }
}

