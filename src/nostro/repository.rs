//! Nostro database repository

use super::models::{
    CorridorStatus, EodReconciliationResult, LiquidityAlert, NostroAccount, NostroBalance,
};
use chrono::NaiveDate;
use sqlx::types::BigDecimal;
use sqlx::PgPool;
use uuid::Uuid;

pub struct NostroRepository {
    pool: PgPool,
}

impl NostroRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn get_account(&self, id: Uuid) -> Result<NostroAccount, anyhow::Error> {
        Ok(sqlx::query_as::<_, NostroAccount>(
            "SELECT * FROM nostro_accounts WHERE id = $1",
        )
        .bind(id)
        .fetch_one(&self.pool)
        .await?)
    }

    pub async fn get_all_active_accounts(&self) -> Result<Vec<NostroAccount>, anyhow::Error> {
        Ok(sqlx::query_as::<_, NostroAccount>(
            "SELECT * FROM nostro_accounts WHERE is_active = true",
        )
        .fetch_all(&self.pool)
        .await?)
    }

    pub async fn upsert_balance(
        &self,
        account_id: Uuid,
        cleared: BigDecimal,
        pending: BigDecimal,
        source: &str,
    ) -> Result<(), anyhow::Error> {
        sqlx::query(
            r#"
            INSERT INTO nostro_balances (account_id, cleared_balance, pending_balance, source, polled_at)
            VALUES ($1, $2, $3, $4, NOW())
            "#,
        )
        .bind(account_id)
        .bind(cleared)
        .bind(pending)
        .bind(source)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_average_daily_volume(&self, account_id: Uuid) -> Result<BigDecimal, anyhow::Error> {
        let row: Option<(BigDecimal,)> = sqlx::query_as(
            r#"
            SELECT COALESCE(AVG(daily_total), 0)
            FROM (
                SELECT DATE(created_at) as day, SUM(to_amount) as daily_total
                FROM transactions
                WHERE metadata->>'nostro_account_id' = $1::text
                  AND created_at >= NOW() - INTERVAL '30 days'
                GROUP BY day
            ) sub
            "#,
        )
        .bind(account_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|(v,)| v).unwrap_or_else(|| BigDecimal::from(0)))
    }

    pub async fn set_corridor_status(
        &self,
        corridor_id: &str,
        status: CorridorStatus,
    ) -> Result<(), anyhow::Error> {
        let status_str = match status {
            CorridorStatus::Active => "active",
            CorridorStatus::DisabledInsufficientFunds => "disabled_insufficient_funds",
            CorridorStatus::DisabledManual => "disabled_manual",
        };
        sqlx::query(
            "UPDATE nostro_accounts SET corridor_status = $2, updated_at = NOW() WHERE corridor_id = $1",
        )
        .bind(corridor_id)
        .bind(status_str)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn restore_corridor_if_disabled(&self, corridor_id: &str) -> Result<(), anyhow::Error> {
        sqlx::query(
            r#"
            UPDATE nostro_accounts
            SET corridor_status = 'active', updated_at = NOW()
            WHERE corridor_id = $1 AND corridor_status = 'disabled_insufficient_funds'
            "#,
        )
        .bind(corridor_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_corridor_status(&self, corridor_id: &str) -> Result<CorridorStatus, anyhow::Error> {
        let row: (String,) = sqlx::query_as(
            "SELECT corridor_status FROM nostro_accounts WHERE corridor_id = $1 LIMIT 1",
        )
        .bind(corridor_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(match row.0.as_str() {
            "active" => CorridorStatus::Active,
            "disabled_manual" => CorridorStatus::DisabledManual,
            _ => CorridorStatus::DisabledInsufficientFunds,
        })
    }

    pub async fn get_corridor_cleared_balance(&self, corridor_id: &str) -> Result<BigDecimal, anyhow::Error> {
        let row: Option<(BigDecimal,)> = sqlx::query_as(
            r#"
            SELECT nb.cleared_balance
            FROM nostro_balances nb
            JOIN nostro_accounts na ON na.id = nb.account_id
            WHERE na.corridor_id = $1
            ORDER BY nb.polled_at DESC
            LIMIT 1
            "#,
        )
        .bind(corridor_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|(v,)| v).unwrap_or_else(|| BigDecimal::from(0)))
    }

    pub async fn record_liquidity_alert(&self, alert: &LiquidityAlert) -> Result<(), anyhow::Error> {
        sqlx::query(
            r#"
            INSERT INTO nostro_liquidity_alerts
                (account_id, corridor_id, currency, current_balance, safety_buffer_amount, shortfall, alerted_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            "#,
        )
        .bind(alert.account_id)
        .bind(&alert.corridor_id)
        .bind(&alert.currency)
        .bind(&alert.current_balance)
        .bind(&alert.safety_buffer_amount)
        .bind(&alert.shortfall)
        .bind(alert.alerted_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_global_liquidity_map(&self) -> Result<Vec<serde_json::Value>, anyhow::Error> {
        let rows = sqlx::query_as::<_, (String, String, String, Option<BigDecimal>, Option<BigDecimal>, String)>(
            r#"
            SELECT
                na.corridor_id,
                na.currency,
                na.bank_name,
                nb.cleared_balance,
                nb.pending_balance,
                COALESCE(na.corridor_status, 'active') as status
            FROM nostro_accounts na
            LEFT JOIN LATERAL (
                SELECT cleared_balance, pending_balance
                FROM nostro_balances
                WHERE account_id = na.id
                ORDER BY polled_at DESC
                LIMIT 1
            ) nb ON true
            WHERE na.is_active = true
            ORDER BY na.corridor_id
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|(corridor, currency, bank, cleared, pending, status)| {
                serde_json::json!({
                    "corridor_id": corridor,
                    "currency": currency,
                    "bank_name": bank,
                    "cleared_balance": cleared,
                    "pending_balance": pending,
                    "status": status,
                })
            })
            .collect())
    }

    pub async fn get_onchain_burns_for_date(
        &self,
        corridor_id: &str,
        date: NaiveDate,
    ) -> Result<BigDecimal, anyhow::Error> {
        let row: Option<(BigDecimal,)> = sqlx::query_as(
            r#"
            SELECT COALESCE(SUM(cngn_amount), 0)
            FROM transactions
            WHERE metadata->>'corridor_id' = $1
              AND type = 'offramp'
              AND status = 'completed'
              AND DATE(created_at) = $2
            "#,
        )
        .bind(corridor_id)
        .bind(date)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|(v,)| v).unwrap_or_else(|| BigDecimal::from(0)))
    }

    pub async fn get_fiat_outflows_for_date(
        &self,
        account_id: &Uuid,
        date: NaiveDate,
    ) -> Result<BigDecimal, anyhow::Error> {
        let row: Option<(BigDecimal,)> = sqlx::query_as(
            r#"
            SELECT COALESCE(SUM(amount), 0)
            FROM nostro_fiat_outflows
            WHERE account_id = $1 AND DATE(created_at) = $2
            "#,
        )
        .bind(account_id)
        .bind(date)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|(v,)| v).unwrap_or_else(|| BigDecimal::from(0)))
    }

    pub async fn save_eod_result(
        &self,
        account_id: Uuid,
        corridor_id: &str,
        date: NaiveDate,
        onchain_burns: &BigDecimal,
        fiat_outflows: &BigDecimal,
        discrepancy: &BigDecimal,
        status: &str,
    ) -> Result<EodReconciliationResult, anyhow::Error> {
        Ok(sqlx::query_as::<_, EodReconciliationResult>(
            r#"
            INSERT INTO nostro_eod_reconciliation
                (account_id, corridor_id, date, onchain_burns, fiat_outflows, discrepancy, status)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING *
            "#,
        )
        .bind(account_id)
        .bind(corridor_id)
        .bind(date)
        .bind(onchain_burns)
        .bind(fiat_outflows)
        .bind(discrepancy)
        .bind(status)
        .fetch_one(&self.pool)
        .await?)
    }
}
