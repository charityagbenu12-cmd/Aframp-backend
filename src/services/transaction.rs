use tracing::{info_span, instrument, Instrument};
use uuid::Uuid;

/// Minimal stand-in for a database pool (in production this would be `sqlx::PgPool`).
#[derive(Clone)]
pub struct DbPool;

/// Minimal stand-in for a Redis connection (in production this would be `redis::Client`).
#[derive(Clone)]
pub struct RedisPool;

/// Represents a payment transaction record.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Transaction {
    pub id: Uuid,
    pub wallet_address: String,
    pub amount: String,
    pub currency: String,
    pub status: String,
}

pub struct TransactionService {
    pub db: DbPool,
    pub redis: RedisPool,
}

impl TransactionService {
    pub fn new(db: DbPool, redis: RedisPool) -> Self {
        Self { db, redis }
    }

    /// Fetch a transaction by ID.
    ///
    /// Emits:
    /// * A child span labelled `db.query` with `db.operation=SELECT` and
    ///   `db.sql.table=transactions` for the database lookup.
    /// * A child span labelled `cache.get` for the Redis cache check.
    #[instrument(skip(self), fields(tx_id = %tx_id))]
    pub async fn get_transaction(&self, tx_id: Uuid) -> Option<Transaction> {
        // 1. Check Redis cache first.
        let cache_key = format!("tx:{}", tx_id);
        let _cache_span = info_span!(
            "cache.get",
            otel.kind = "client",
            db.system = "redis",
            db.operation = "GET",
            cache.key_prefix = "tx:",
        )
        .entered();
        tracing::debug!(cache_key = %cache_key, "Checking Redis cache for transaction");
        drop(_cache_span);

        // 2. Fall back to the database.
        let _db_span = info_span!(
            "db.query",
            otel.kind = "client",
            db.system = "postgresql",
            db.operation = "SELECT",
            db.sql.table = "transactions",
        )
        .entered();
        tracing::debug!(%tx_id, "Querying transactions table");
        drop(_db_span);

        // Simulated result for compilation purposes.
        Some(Transaction {
            id: tx_id,
            wallet_address: "GXXXEXAMPLE".into(),
            amount: "100".into(),
            currency: "CNGN".into(),
            status: "pending".into(),
        })
    }

    /// Persist a new transaction record.
    ///
    /// Emits a child span for the INSERT and a child span for the cache write.
    #[instrument(skip(self, tx), fields(tx_id = %tx.id))]
    pub async fn create_transaction(&self, tx: Transaction) -> anyhow::Result<Transaction> {
        // Database INSERT span.
        let db_span = info_span!(
            "db.query",
            otel.kind = "client",
            db.system = "postgresql",
            db.operation = "INSERT",
            db.sql.table = "transactions",
        );
        async {
            tracing::info!(tx_id = %tx.id, "Inserting transaction into database");
        }
        .instrument(db_span)
        .await;

        // Cache WRITE span.
        let cache_span = info_span!(
            "cache.set",
            otel.kind = "client",
            db.system = "redis",
            db.operation = "SET",
            cache.key_prefix = "tx:",
            cache.ttl_seconds = 300,
        );
        async {
            tracing::debug!(tx_id = %tx.id, "Writing transaction to Redis cache");
        }
        .instrument(cache_span)
        .await;

        Ok(tx)
    }

    /// Update transaction status.
    ///
    /// Emits a child span for the UPDATE query and cache invalidation.
    #[instrument(skip(self), fields(tx_id = %tx_id, new_status = %status))]
    pub async fn update_status(&self, tx_id: Uuid, status: &str) -> anyhow::Result<()> {
        let db_span = info_span!(
            "db.query",
            otel.kind = "client",
            db.system = "postgresql",
            db.operation = "UPDATE",
            db.sql.table = "transactions",
        );
        async {
            tracing::info!(%tx_id, %status, "Updating transaction status");
        }
        .instrument(db_span)
        .await;

        // Invalidate the cached entry.
        let cache_span = info_span!(
            "cache.del",
            otel.kind = "client",
            db.system = "redis",
            db.operation = "DEL",
            cache.key_prefix = "tx:",
        );
        async {
            tracing::debug!(%tx_id, "Invalidating cached transaction");
        }
        .instrument(cache_span)
        .await;

        Ok(())
    }
}