use crate::database::error::DatabaseError;
use sqlx::{types::BigDecimal, FromRow, PgPool};
use uuid::Uuid;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct ReconciliationReport {
    pub id: Uuid,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub internal_total: BigDecimal,
    pub on_chain_total: BigDecimal,
    pub bank_total: BigDecimal,
    pub mints_in_progress: BigDecimal,
    pub redemptions_in_progress: BigDecimal,
    pub delta_value: BigDecimal,
    pub status: String,
    pub metadata: serde_json::Value,
}

pub struct ReconciliationRepository {
    pool: PgPool,
}

impl ReconciliationRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn create_report(
        &self,
        internal: BigDecimal,
        stellar: BigDecimal,
        bank: BigDecimal,
        mints_pending: BigDecimal,
        redemptions_pending: BigDecimal,
        delta: BigDecimal,
        status: &str,
        metadata: serde_json::Value,
    ) -> Result<ReconciliationReport, DatabaseError> {
        sqlx::query_as::<_, ReconciliationReport>(
            "INSERT INTO reconciliation_reports 
             (internal_total, on_chain_total, bank_total, mints_in_progress, redemptions_in_progress, delta_value, status, metadata) 
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) 
             RETURNING id, timestamp, internal_total, on_chain_total, bank_total, mints_in_progress, redemptions_in_progress, delta_value, status, metadata"
        )
        .bind(internal)
        .bind(stellar)
        .bind(bank)
        .bind(mints_pending)
        .bind(redemptions_pending)
        .bind(delta)
        .bind(status)
        .bind(metadata)
        .fetch_one(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)
    }

    pub async fn get_internal_ledger_total(&self) -> Result<BigDecimal, DatabaseError> {
        // Internal ledger is the sum of all wallet balances
        let row = sqlx::query_scalar::<_, Option<BigDecimal>>(
            "SELECT SUM(balance::numeric) FROM wallets"
        )
        .fetch_one(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?;
        
        Ok(row.unwrap_or_else(|| BigDecimal::from(0)))
    }

    pub async fn get_mints_in_progress_total(&self) -> Result<BigDecimal, DatabaseError> {
        // Onramps that are paid but not yet completed on blockchain
        let row = sqlx::query_scalar::<_, Option<BigDecimal>>(
            "SELECT SUM(cngn_amount) FROM transactions 
             WHERE type = 'onramp' AND status IN ('payment_received', 'processing')"
        )
        .fetch_one(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(row.unwrap_or_else(|| BigDecimal::from(0)))
    }

    pub async fn get_redemptions_in_progress_total(&self) -> Result<BigDecimal, DatabaseError> {
        // Offramps that are burned on-chain but fiat not yet sent or confirmed
        let row = sqlx::query_scalar::<_, Option<BigDecimal>>(
            "SELECT SUM(cngn_amount) FROM transactions 
             WHERE type = 'offramp' AND status IN ('burning', 'burned', 'processing_withdrawal', 'transfer_pending')"
        )
        .fetch_one(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(row.unwrap_or_else(|| BigDecimal::from(0)))
    }
}
