use chrono::{DateTime, Utc};
use sqlx::PgPool;

use crate::mint_burn::models::{MintBurnError, ProcessedEvent, UnmatchedEvent};

// ---------------------------------------------------------------------------
// Repository
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct MintBurnRepository {
    pub pool: PgPool,
}

impl MintBurnRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    // -----------------------------------------------------------------------
    // load_cursor
    // -----------------------------------------------------------------------

    /// Load the most recently persisted ledger cursor, or `None` if the table
    /// is empty (should not happen after migration seeds the row, but handled
    /// defensively).
    pub async fn load_cursor(&self) -> Result<Option<String>, MintBurnError> {
        let row: Option<(String,)> = sqlx::query_as(
            "SELECT cursor FROM ledger_cursor ORDER BY id DESC LIMIT 1",
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|(cursor,)| cursor))
    }

    // -----------------------------------------------------------------------
    // is_duplicate
    // -----------------------------------------------------------------------

    /// Return `true` if the given transaction hash already exists in
    /// `processed_events`. Used as a fast pre-check; the definitive
    /// duplicate guard is the ON CONFLICT inside `commit_event`.
    pub async fn is_duplicate(&self, tx_hash: &str) -> Result<bool, MintBurnError> {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM processed_events WHERE transaction_hash = $1",
        )
        .bind(tx_hash)
        .fetch_one(&self.pool)
        .await?;

        Ok(count > 0)
    }

    // -----------------------------------------------------------------------
    // commit_event
    // -----------------------------------------------------------------------

    /// Atomically:
    /// 1. Insert a row into `processed_events` (ON CONFLICT DO NOTHING for
    ///    idempotency — returns Ok(()) if already present).
    /// 2. Upsert the `ledger_cursor` singleton row.
    /// 3. Call `confirm_mint` or `confirm_redemption` based on
    ///    `event.operation_type` and `event.parsed_id`.
    pub async fn commit_event(
        &self,
        event: &ProcessedEvent,
        cursor: &str,
    ) -> Result<(), MintBurnError> {
        let mut tx = self.pool.begin().await?;

        // 1. Insert into processed_events — ON CONFLICT is the definitive
        //    idempotency guard, eliminating the TOCTOU race between
        //    is_duplicate() and the insert.
        let inserted = sqlx::query(
            r#"
            INSERT INTO processed_events (
                id, transaction_hash, operation_type, ledger_id,
                created_at_chain, processed_at,
                asset_code, asset_issuer, amount,
                source_account, destination_account,
                raw_memo, parsed_id
            ) VALUES (
                $1, $2, $3, $4,
                $5, $6,
                $7, $8, $9,
                $10, $11,
                $12, $13
            )
            ON CONFLICT (transaction_hash) DO NOTHING
            "#,
        )
        .bind(event.id)
        .bind(&event.transaction_hash)
        .bind(&event.operation_type)
        .bind(event.ledger_id)
        .bind(event.created_at_chain)
        .bind(event.processed_at)
        .bind(&event.asset_code)
        .bind(&event.asset_issuer)
        .bind(&event.amount)
        .bind(&event.source_account)
        .bind(&event.destination_account)
        .bind(&event.raw_memo)
        .bind(&event.parsed_id)
        .execute(&mut *tx)
        .await?;

        // Already committed by a concurrent worker — skip cursor + confirmation.
        if inserted.rows_affected() == 0 {
            tx.rollback().await?;
            return Ok(());
        }

        // 2. Upsert ledger_cursor — INSERT on first run, UPDATE thereafter.
        sqlx::query(
            r#"
            INSERT INTO ledger_cursor (cursor, updated_at)
            VALUES ($1, NOW())
            ON CONFLICT (id) DO UPDATE SET cursor = EXCLUDED.cursor, updated_at = NOW()
            "#,
        )
        .bind(cursor)
        .execute(&mut *tx)
        .await?;

        // 3. Confirm the corresponding Mint or Redemption record (best-effort
        //    within the same transaction — returns false if not found, which
        //    is acceptable here since unmatched events are handled separately).
        if let Some(ref parsed_id) = event.parsed_id {
            match event.operation_type.as_str() {
                "mint" => {
                    Self::confirm_mint_in_tx(
                        &mut tx,
                        parsed_id,
                        event.ledger_id,
                        event.created_at_chain,
                    )
                    .await?;
                }
                "burn" | "clawback" => {
                    Self::confirm_redemption_in_tx(
                        &mut tx,
                        parsed_id,
                        event.ledger_id,
                        event.created_at_chain,
                    )
                    .await?;
                }
                _ => {}
            }
        }

        tx.commit().await?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // insert_unmatched
    // -----------------------------------------------------------------------

    /// Insert a raw operation into `unmatched_events`.
    pub async fn insert_unmatched(&self, event: &UnmatchedEvent) -> Result<(), MintBurnError> {
        sqlx::query(
            r#"
            INSERT INTO unmatched_events (id, transaction_hash, raw_memo, raw_operation, recorded_at)
            VALUES ($1, $2, $3, $4, $5)
            "#,
        )
        .bind(event.id)
        .bind(&event.transaction_hash)
        .bind(&event.raw_memo)
        .bind(&event.raw_operation)
        .bind(event.recorded_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    // -----------------------------------------------------------------------
    // confirm_mint (public, standalone — uses its own connection)
    // -----------------------------------------------------------------------

    /// Update the `mints` table: set `status = 'ON_CHAIN_CONFIRMED'`,
    /// `ledger_id`, and `confirmed_at` where `id = mint_id`.
    ///
    /// Returns `true` if a row was updated, `false` if no matching record was
    /// found.
    pub async fn confirm_mint(
        &self,
        mint_id: &str,
        ledger_id: i64,
        created_at_chain: DateTime<Utc>,
    ) -> Result<bool, MintBurnError> {
        let result = sqlx::query(
            r#"
            UPDATE mints
            SET status = 'ON_CHAIN_CONFIRMED',
                ledger_id = $2,
                confirmed_at = $3
            WHERE id = $1
            "#,
        )
        .bind(mint_id)
        .bind(ledger_id)
        .bind(created_at_chain)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    // -----------------------------------------------------------------------
    // confirm_redemption (public, standalone — uses its own connection)
    // -----------------------------------------------------------------------

    /// Update the `redemptions` table: set `status = 'ON_CHAIN_CONFIRMED'`,
    /// `ledger_id`, and `confirmed_at` where `id = redemption_id`.
    ///
    /// Returns `true` if a row was updated, `false` if no matching record was
    /// found.
    pub async fn confirm_redemption(
        &self,
        redemption_id: &str,
        ledger_id: i64,
        created_at_chain: DateTime<Utc>,
    ) -> Result<bool, MintBurnError> {
        let result = sqlx::query(
            r#"
            UPDATE redemptions
            SET status = 'ON_CHAIN_CONFIRMED',
                ledger_id = $2,
                confirmed_at = $3
            WHERE id = $1
            "#,
        )
        .bind(redemption_id)
        .bind(ledger_id)
        .bind(created_at_chain)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    // -----------------------------------------------------------------------
    // Private transaction-scoped helpers
    // -----------------------------------------------------------------------

    async fn confirm_mint_in_tx(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        mint_id: &str,
        ledger_id: i64,
        created_at_chain: DateTime<Utc>,
    ) -> Result<bool, MintBurnError> {
        let result = sqlx::query(
            r#"
            UPDATE mints
            SET status = 'ON_CHAIN_CONFIRMED',
                ledger_id = $2,
                confirmed_at = $3
            WHERE id = $1
            "#,
        )
        .bind(mint_id)
        .bind(ledger_id)
        .bind(created_at_chain)
        .execute(&mut **tx)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    async fn confirm_redemption_in_tx(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        redemption_id: &str,
        ledger_id: i64,
        created_at_chain: DateTime<Utc>,
    ) -> Result<bool, MintBurnError> {
        let result = sqlx::query(
            r#"
            UPDATE redemptions
            SET status = 'ON_CHAIN_CONFIRMED',
                ledger_id = $2,
                confirmed_at = $3
            WHERE id = $1
            "#,
        )
        .bind(redemption_id)
        .bind(ledger_id)
        .bind(created_at_chain)
        .execute(&mut **tx)
        .await?;

        Ok(result.rows_affected() > 0)
    }
}
