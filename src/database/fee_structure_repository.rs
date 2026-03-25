use crate::database::error::{DatabaseError, DatabaseErrorKind};
use crate::database::repository::{Repository, TransactionalRepository};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

/// Fee structure entity
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct FeeStructure {
    pub id: Uuid,
    pub fee_type: String,
    pub fee_rate_bps: i32,
    pub fee_flat: sqlx::types::BigDecimal,
    pub min_fee: Option<sqlx::types::BigDecimal>,
    pub max_fee: Option<sqlx::types::BigDecimal>,
    pub currency: Option<String>,
    pub is_active: bool,
    pub effective_from: chrono::DateTime<chrono::Utc>,
    pub effective_until: Option<chrono::DateTime<chrono::Utc>>,
    pub metadata: serde_json::Value,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// Repository for fee structure configuration
pub struct FeeStructureRepository {
    pool: PgPool,
}

impl FeeStructureRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Create a fee structure
    pub async fn create_fee_structure(
        &self,
        fee_type: &str,
        fee_rate_bps: i32,
        fee_flat: sqlx::types::BigDecimal,
        min_fee: Option<sqlx::types::BigDecimal>,
        max_fee: Option<sqlx::types::BigDecimal>,
        currency: Option<&str>,
        is_active: bool,
        effective_from: chrono::DateTime<chrono::Utc>,
        effective_until: Option<chrono::DateTime<chrono::Utc>>,
        metadata: serde_json::Value,
    ) -> Result<FeeStructure, DatabaseError> {
        sqlx::query_as::<_, FeeStructure>(
            "INSERT INTO fee_structures 
             (fee_type, fee_rate_bps, fee_flat, min_fee, max_fee, currency, is_active, effective_from, effective_until, metadata) 
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) 
             RETURNING id, fee_type, fee_rate_bps, fee_flat, min_fee, max_fee, currency, is_active, effective_from, effective_until, metadata, created_at, updated_at",
        )
        .bind(fee_type)
        .bind(fee_rate_bps)
        .bind(fee_flat)
        .bind(min_fee)
        .bind(max_fee)
        .bind(currency)
        .bind(is_active)
        .bind(effective_from)
        .bind(effective_until)
        .bind(metadata)
        .fetch_one(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)
    }

    /// Get active fee structures for a fee type at a specific time (default now)
    pub async fn get_active_by_type(
        &self,
        fee_type: &str,
        at_time: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<Vec<FeeStructure>, DatabaseError> {
        let at_time = at_time.unwrap_or_else(chrono::Utc::now);
        sqlx::query_as::<_, FeeStructure>(
            "SELECT id, fee_type, fee_rate_bps, fee_flat, min_fee, max_fee, currency, is_active, effective_from, effective_until, metadata, created_at, updated_at 
             FROM fee_structures 
             WHERE fee_type = $1 AND is_active = TRUE 
               AND effective_from <= $2 
               AND (effective_until IS NULL OR effective_until >= $2)
             ORDER BY effective_from DESC",
        )
        .bind(fee_type)
        .bind(at_time)
        .fetch_all(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)
    }

    /// Deactivate a fee structure
    pub async fn deactivate(&self, id: Uuid) -> Result<FeeStructure, DatabaseError> {
        sqlx::query_as::<_, FeeStructure>(
            "UPDATE fee_structures 
             SET is_active = FALSE, updated_at = NOW() 
             WHERE id = $1 
             RETURNING id, fee_type, fee_rate_bps, fee_flat, min_fee, max_fee, currency, is_active, effective_from, effective_until, metadata, created_at, updated_at",
        )
        .bind(id)
        .fetch_one(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)
    }
}

#[async_trait]
impl Repository for FeeStructureRepository {
    type Entity = FeeStructure;

    async fn find_by_id(&self, id: &str) -> Result<Option<Self::Entity>, DatabaseError> {
        let uuid = Uuid::parse_str(id).map_err(|e| {
            DatabaseError::new(DatabaseErrorKind::Unknown {
                message: format!("Invalid UUID: {}", e),
            })
        })?;
        sqlx::query_as::<_, FeeStructure>(
            "SELECT id, fee_type, fee_rate_bps, fee_flat, min_fee, max_fee, currency, is_active, effective_from, effective_until, metadata, created_at, updated_at 
             FROM fee_structures WHERE id = $1",
        )
        .bind(uuid)
        .fetch_optional(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)
    }

    async fn find_all(&self) -> Result<Vec<Self::Entity>, DatabaseError> {
        sqlx::query_as::<_, FeeStructure>(
            "SELECT id, fee_type, fee_rate_bps, fee_flat, min_fee, max_fee, currency, is_active, effective_from, effective_until, metadata, created_at, updated_at 
             FROM fee_structures ORDER BY created_at DESC",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)
    }

    async fn insert(&self, entity: &Self::Entity) -> Result<Self::Entity, DatabaseError> {
        sqlx::query_as::<_, FeeStructure>(
            "INSERT INTO fee_structures 
             (id, fee_type, fee_rate_bps, fee_flat, min_fee, max_fee, currency, is_active, effective_from, effective_until, metadata, created_at, updated_at) 
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) 
             RETURNING id, fee_type, fee_rate_bps, fee_flat, min_fee, max_fee, currency, is_active, effective_from, effective_until, metadata, created_at, updated_at",
        )
        .bind(entity.id)
        .bind(&entity.fee_type)
        .bind(entity.fee_rate_bps)
        .bind(entity.fee_flat.clone())
        .bind(entity.min_fee.clone())
        .bind(entity.max_fee.clone())
        .bind(&entity.currency)
        .bind(entity.is_active)
        .bind(entity.effective_from)
        .bind(entity.effective_until)
        .bind(&entity.metadata)
        .bind(entity.created_at)
        .bind(entity.updated_at)
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
        sqlx::query_as::<_, FeeStructure>(
            "UPDATE fee_structures 
             SET fee_type = $1, fee_rate_bps = $2, fee_flat = $3, min_fee = $4, max_fee = $5, currency = $6, is_active = $7, effective_from = $8, effective_until = $9, metadata = $10, updated_at = NOW()
             WHERE id = $11 
             RETURNING id, fee_type, fee_rate_bps, fee_flat, min_fee, max_fee, currency, is_active, effective_from, effective_until, metadata, created_at, updated_at",
        )
        .bind(&entity.fee_type)
        .bind(entity.fee_rate_bps)
        .bind(entity.fee_flat.clone())
        .bind(entity.min_fee.clone())
        .bind(entity.max_fee.clone())
        .bind(&entity.currency)
        .bind(entity.is_active)
        .bind(entity.effective_from)
        .bind(entity.effective_until)
        .bind(&entity.metadata)
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
        let result = sqlx::query("DELETE FROM fee_structures WHERE id = $1")
            .bind(uuid)
            .execute(&self.pool)
            .await
            .map_err(DatabaseError::from_sqlx)?;
        Ok(result.rows_affected() > 0)
    }
}

impl TransactionalRepository for FeeStructureRepository {
    fn pool(&self) -> &PgPool {
        &self.pool
    }
}
