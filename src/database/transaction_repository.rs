use crate::database::error::{DatabaseError, DatabaseErrorKind};
use crate::database::repository::{Repository, TransactionalRepository};
use async_trait::async_trait;
use sqlx::{types::BigDecimal, FromRow, PgPool};
use uuid::Uuid;

/// Transaction entity
#[derive(Debug, Clone, FromRow)]
pub struct Transaction {
    pub transaction_id: Uuid,
    pub wallet_address: String,
    pub r#type: String,
    pub from_currency: String,
    pub to_currency: String,
    pub from_amount: BigDecimal,
    pub to_amount: BigDecimal,
    pub cngn_amount: BigDecimal,
    pub status: String,
    pub payment_provider: Option<String>,
    pub payment_reference: Option<String>,
    pub blockchain_tx_hash: Option<String>,
    pub error_message: Option<String>,
    pub metadata: serde_json::Value,
    pub priority_level: i32,
    pub partner_tier: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// Repository for managing transactions
pub struct TransactionRepository {
    pool: PgPool,
}

impl TransactionRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Create a new transaction
    pub async fn create_transaction(
        &self,
        wallet_address: &str,
        transaction_type: &str,
        from_currency: &str,
        to_currency: &str,
        from_amount: BigDecimal,
        to_amount: BigDecimal,
        cngn_amount: BigDecimal,
        status: &str,
        payment_provider: Option<&str>,
        payment_reference: Option<&str>,
        metadata: serde_json::Value,
    ) -> Result<Transaction, DatabaseError> {
        sqlx::query_as::<_, Transaction>(
            "INSERT INTO transactions 
             (wallet_address, type, from_currency, to_currency, from_amount, to_amount, 
              cngn_amount, status, payment_provider, payment_reference, metadata, priority_level, partner_tier) 
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) 
             RETURNING transaction_id, wallet_address, type, from_currency, to_currency, 
                       from_amount, to_amount, cngn_amount, status, payment_provider, 
                       payment_reference, blockchain_tx_hash, error_message, metadata, 
                       priority_level, partner_tier,
                       created_at, updated_at",
        )
        .bind(wallet_address)
        .bind(transaction_type)
        .bind(from_currency)
        .bind(to_currency)
        .bind(from_amount)
        .bind(to_amount)
        .bind(cngn_amount)
        .bind(status)
        .bind(payment_provider)
        .bind(payment_reference)
        .bind(metadata)
        .bind(0) // Default priority_level for new transactions
        .bind("standard") // Default partner_tier
        .fetch_one(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)
    }

    /// Update transaction status
    pub async fn update_status(
        &self,
        transaction_id: &str,
        status: &str,
    ) -> Result<Transaction, DatabaseError> {
        let uuid = Uuid::parse_str(transaction_id).map_err(|e| {
            DatabaseError::new(DatabaseErrorKind::Unknown {
                message: format!("Invalid UUID: {}", e),
            })
        })?;

        sqlx::query_as::<_, Transaction>(
            "UPDATE transactions 
             SET status = $2 
             WHERE transaction_id = $1 
             RETURNING transaction_id, wallet_address, type, from_currency, to_currency, 
                       from_amount, to_amount, cngn_amount, status, payment_provider, 
                       payment_reference, blockchain_tx_hash, error_message, metadata, 
                       created_at, updated_at",
        )
        .bind(uuid)
        .bind(status)
        .fetch_one(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)
    }

    /// Update transaction status with metadata
    ///
    /// This method updates both the status and merges new metadata with existing metadata.
    /// Useful for tracking payment provider responses, blockchain confirmations, etc.
    pub async fn update_status_with_metadata(
        &self,
        transaction_id: &str,
        status: &str,
        additional_metadata: serde_json::Value,
    ) -> Result<Transaction, DatabaseError> {
        let uuid = Uuid::parse_str(transaction_id).map_err(|e| {
            DatabaseError::new(DatabaseErrorKind::Unknown {
                message: format!("Invalid UUID: {}", e),
            })
        })?;

        sqlx::query_as::<_, Transaction>(
            "UPDATE transactions 
             SET status = $2, 
                 metadata = metadata || $3 
             WHERE transaction_id = $1 
             RETURNING transaction_id, wallet_address, type, from_currency, to_currency, 
                       from_amount, to_amount, cngn_amount, status, payment_provider, 
                       payment_reference, blockchain_tx_hash, error_message, metadata, 
                       created_at, updated_at",
        )
        .bind(uuid)
        .bind(status)
        .bind(additional_metadata)
        .fetch_one(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)
    }

    /// Update blockchain transaction hash
    pub async fn update_blockchain_hash(
        &self,
        transaction_id: &str,
        blockchain_tx_hash: &str,
    ) -> Result<Transaction, DatabaseError> {
        let uuid = Uuid::parse_str(transaction_id).map_err(|e| {
            DatabaseError::new(DatabaseErrorKind::Unknown {
                message: format!("Invalid UUID: {}", e),
            })
        })?;

        sqlx::query_as::<_, Transaction>(
            "UPDATE transactions 
             SET blockchain_tx_hash = $2 
             WHERE transaction_id = $1 
             RETURNING transaction_id, wallet_address, type, from_currency, to_currency, 
                       from_amount, to_amount, cngn_amount, status, payment_provider, 
                       payment_reference, blockchain_tx_hash, error_message, metadata, 
                       created_at, updated_at",
        )
        .bind(uuid)
        .bind(blockchain_tx_hash)
        .fetch_one(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)
    }

    /// Update error message
    pub async fn update_error(
        &self,
        transaction_id: &str,
        error_message: &str,
    ) -> Result<Transaction, DatabaseError> {
        let uuid = Uuid::parse_str(transaction_id).map_err(|e| {
            DatabaseError::new(DatabaseErrorKind::Unknown {
                message: format!("Invalid UUID: {}", e),
            })
        })?;

        sqlx::query_as::<_, Transaction>(
            "UPDATE transactions 
             SET error_message = $2, status = 'failed' 
             WHERE transaction_id = $1 
             RETURNING transaction_id, wallet_address, type, from_currency, to_currency, 
                       from_amount, to_amount, cngn_amount, status, payment_provider, 
                       payment_reference, blockchain_tx_hash, error_message, metadata, 
                       created_at, updated_at",
        )
        .bind(uuid)
        .bind(error_message)
        .fetch_one(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)
    }

    /// Find transactions by wallet address
    pub async fn find_by_wallet(
        &self,
        wallet_address: &str,
    ) -> Result<Vec<Transaction>, DatabaseError> {
        sqlx::query_as::<_, Transaction>(
            "SELECT transaction_id, wallet_address, type, from_currency, to_currency, 
                    from_amount, to_amount, cngn_amount, status, payment_provider, 
                    payment_reference, blockchain_tx_hash, error_message, metadata, 
                    created_at, updated_at 
             FROM transactions 
             WHERE wallet_address = $1 
             ORDER BY created_at DESC",
        )
        .bind(wallet_address)
        .fetch_all(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)
    }

    /// Find transaction by payment reference
    pub async fn find_by_payment_reference(
        &self,
        payment_reference: &str,
    ) -> Result<Option<Transaction>, DatabaseError> {
        sqlx::query_as::<_, Transaction>(
            "SELECT transaction_id, wallet_address, type, from_currency, to_currency, 
                    from_amount, to_amount, cngn_amount, status, payment_provider, 
                    payment_reference, blockchain_tx_hash, error_message, metadata, 
                    created_at, updated_at 
             FROM transactions 
             WHERE payment_reference = $1",
        )
        .bind(payment_reference)
        .fetch_optional(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)
    }

    /// Find status by transaction_id
    pub async fn find_status_by_id(&self, transaction_id: &str) -> Result<String, DatabaseError> {
        let uuid = Uuid::parse_str(transaction_id).map_err(|e| {
            DatabaseError::new(DatabaseErrorKind::Unknown {
                message: format!("Invalid UUID: {}", e),
            })
        })?;

        sqlx::query_scalar::<_, String>(
            "SELECT status FROM transactions WHERE transaction_id = $1"
        )
        .bind(uuid)
        .fetch_one(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)
    }

    /// Find pending payments for monitoring
    ///
    /// Returns up to `limit` transactions that are in 'pending' or 'processing' status
    /// and were created within `window_hours` hours. Ordered oldest-first so stale
    /// transactions are resolved before newer ones.
    pub async fn find_pending_payments_for_monitoring(
        &self,
        window_hours: i32,
        limit: i64,
    ) -> Result<Vec<Transaction>, DatabaseError> {
        sqlx::query_as::<_, Transaction>(
            "SELECT transaction_id, wallet_address, type, from_currency, to_currency,
                    from_amount, to_amount, cngn_amount, status, payment_provider,
                    payment_reference, blockchain_tx_hash, error_message, metadata,
                    priority_level, partner_tier,
                    created_at, updated_at
             FROM transactions
             WHERE status IN ('pending', 'processing', 'pending_payment', 'burning', 'refunding')
               AND created_at > NOW() - INTERVAL '1 hour' * $1
             ORDER BY created_at ASC
             LIMIT $2",
        )
        .bind(window_hours)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)
    }

    /// Find transactions by status
    pub async fn find_by_status(
        &self,
        status: &str,
        limit: i64,
    ) -> Result<Vec<Transaction>, DatabaseError> {
        sqlx::query_as::<_, Transaction>(
            "SELECT transaction_id, wallet_address, type, from_currency, to_currency, 
                    from_amount, to_amount, cngn_amount, status, payment_provider, 
                    payment_reference, blockchain_tx_hash, error_message, metadata, 
                    created_at, updated_at 
             FROM transactions 
             WHERE status = $1 
             ORDER BY created_at ASC 
             LIMIT $2",
        )
        .bind(status)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)
    }

    /// Find offramp transactions by status
    pub async fn find_offramps_by_status(
        &self,
        status: &str,
        limit: i64,
    ) -> Result<Vec<Transaction>, DatabaseError> {
        sqlx::query_as::<_, Transaction>(
            "SELECT transaction_id, wallet_address, type, from_currency, to_currency, 
                    from_amount, to_amount, cngn_amount, status, payment_provider, 
                    payment_reference, blockchain_tx_hash, error_message, metadata, 
                    created_at, updated_at 
             FROM transactions 
             WHERE status = $1 AND type = 'offramp' 
             ORDER BY created_at ASC 
             LIMIT $2",
        )
        .bind(status)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)
    }
}

#[async_trait]
impl Repository for TransactionRepository {
    type Entity = Transaction;

    async fn find_by_id(&self, id: &str) -> Result<Option<Self::Entity>, DatabaseError> {
        let uuid = Uuid::parse_str(id).map_err(|e| {
            DatabaseError::new(DatabaseErrorKind::Unknown {
                message: format!("Invalid UUID: {}", e),
            })
        })?;

        sqlx::query_as::<_, Transaction>(
            "SELECT transaction_id, wallet_address, type, from_currency, to_currency, 
                    from_amount, to_amount, cngn_amount, status, payment_provider, 
                    payment_reference, blockchain_tx_hash, error_message, metadata, 
                    created_at, updated_at 
             FROM transactions 
             WHERE transaction_id = $1",
        )
        .bind(uuid)
        .fetch_optional(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)
    }

    async fn find_all(&self) -> Result<Vec<Self::Entity>, DatabaseError> {
        sqlx::query_as::<_, Transaction>(
            "SELECT transaction_id, wallet_address, type, from_currency, to_currency, 
                    from_amount, to_amount, cngn_amount, status, payment_provider, 
                    payment_reference, blockchain_tx_hash, error_message, metadata, 
                    priority_level, partner_tier,
                    created_at, updated_at 
             FROM transactions 
             ORDER BY created_at DESC",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)
    }

    async fn insert(&self, entity: &Self::Entity) -> Result<Self::Entity, DatabaseError> {
        sqlx::query_as::<_, Transaction>(
            "INSERT INTO transactions 
             (wallet_address, type, from_currency, to_currency, from_amount, to_amount, 
              cngn_amount, status, payment_provider, payment_reference, blockchain_tx_hash, 
              error_message, metadata) 
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) 
             RETURNING transaction_id, wallet_address, type, from_currency, to_currency, 
                       from_amount, to_amount, cngn_amount, status, payment_provider, 
                       payment_reference, blockchain_tx_hash, error_message, metadata, 
                       created_at, updated_at",
        )
        .bind(&entity.wallet_address)
        .bind(&entity.r#type)
        .bind(&entity.from_currency)
        .bind(&entity.to_currency)
        .bind(&entity.from_amount)
        .bind(&entity.to_amount)
        .bind(&entity.cngn_amount)
        .bind(&entity.status)
        .bind(&entity.payment_provider)
        .bind(&entity.payment_reference)
        .bind(&entity.blockchain_tx_hash)
        .bind(&entity.error_message)
        .bind(&entity.metadata)
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

        sqlx::query_as::<_, Transaction>(
            "UPDATE transactions 
             SET wallet_address = $2, type = $3, from_currency = $4, to_currency = $5, 
                 from_amount = $6, to_amount = $7, cngn_amount = $8, status = $9, 
                 payment_provider = $10, payment_reference = $11, blockchain_tx_hash = $12, 
                 error_message = $13, metadata = $14 
             WHERE transaction_id = $1 
             RETURNING transaction_id, wallet_address, type, from_currency, to_currency, 
                       from_amount, to_amount, cngn_amount, status, payment_provider, 
                       payment_reference, blockchain_tx_hash, error_message, metadata, 
                       created_at, updated_at",
        )
        .bind(uuid)
        .bind(&entity.wallet_address)
        .bind(&entity.r#type)
        .bind(&entity.from_currency)
        .bind(&entity.to_currency)
        .bind(&entity.from_amount)
        .bind(&entity.to_amount)
        .bind(&entity.cngn_amount)
        .bind(&entity.status)
        .bind(&entity.payment_provider)
        .bind(&entity.payment_reference)
        .bind(&entity.blockchain_tx_hash)
        .bind(&entity.error_message)
        .bind(&entity.metadata)
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

        let result = sqlx::query("DELETE FROM transactions WHERE transaction_id = $1")
            .bind(uuid)
            .execute(&self.pool)
            .await
            .map_err(DatabaseError::from_sqlx)?;

        Ok(result.rows_affected() > 0)
    }
}

impl TransactionalRepository for TransactionRepository {
    fn pool(&self) -> &PgPool {
        &self.pool
    }
}
