//! Partner reporting repository — strictly scoped to partner's corridors

use super::models::{CorridorAnalytics, DailySettlementStatement, ReconciliationEntry};
use chrono::{NaiveDate, Utc};
use sqlx::types::BigDecimal;
use sqlx::PgPool;
use uuid::Uuid;

pub struct ReportingRepository {
    pool: PgPool,
}

impl ReportingRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Fetch reconciliation entries for a partner's corridor within a date range.
    /// Strictly scoped — a partner can only see their own corridor data.
    pub async fn get_reconciliation_entries(
        &self,
        partner_id: Uuid,
        corridor_id: &str,
        from: NaiveDate,
        to: NaiveDate,
    ) -> Result<Vec<ReconciliationEntry>, anyhow::Error> {
        // Verify partner owns this corridor first
        self.assert_partner_owns_corridor(partner_id, corridor_id).await?;

        let entries = sqlx::query_as::<_, ReconciliationEntry>(
            r#"
            SELECT
                t.transaction_id,
                t.metadata->>'corridor_id' AS corridor_id,
                t.cngn_amount,
                COALESCE((t.metadata->>'fx_rate')::numeric, 1) AS fx_rate,
                t.to_currency AS destination_currency,
                t.to_amount AS destination_amount,
                COALESCE((t.metadata->>'partner_commission')::numeric, 0) AS partner_commission,
                t.status,
                -- Mask sender PII: show only first 3 chars + ***
                LEFT(t.wallet_address, 3) || '***' AS sender_ref,
                t.created_at,
                t.updated_at AS settled_at
            FROM transactions t
            WHERE t.metadata->>'corridor_id' = $2
              AND t.metadata->>'partner_id' = $1::text
              AND t.type = 'offramp'
              AND DATE(t.created_at) BETWEEN $3 AND $4
            ORDER BY t.created_at DESC
            "#,
        )
        .bind(partner_id)
        .bind(corridor_id)
        .bind(from)
        .bind(to)
        .fetch_all(&self.pool)
        .await?;

        Ok(entries)
    }

    /// Build a daily settlement statement for a partner/corridor
    pub async fn build_daily_statement(
        &self,
        partner_id: Uuid,
        corridor_id: &str,
        date: NaiveDate,
    ) -> Result<DailySettlementStatement, anyhow::Error> {
        let entries = self
            .get_reconciliation_entries(partner_id, corridor_id, date, date)
            .await?;

        let total_transactions = entries.len() as i64;
        let success_count = entries.iter().filter(|e| e.status == "completed").count() as i64;
        let failure_count = total_transactions - success_count;

        let total_cngn_volume = entries
            .iter()
            .fold(BigDecimal::from(0), |acc, e| acc + &e.cngn_amount);

        let total_destination_amount = entries
            .iter()
            .fold(BigDecimal::from(0), |acc, e| acc + &e.destination_amount);

        let total_partner_commission = entries
            .iter()
            .fold(BigDecimal::from(0), |acc, e| acc + &e.partner_commission);

        Ok(DailySettlementStatement {
            partner_id,
            corridor_id: corridor_id.to_string(),
            date,
            total_transactions,
            total_cngn_volume,
            total_destination_amount,
            total_partner_commission,
            success_count,
            failure_count,
            entries,
            generated_at: Utc::now(),
        })
    }

    /// Corridor latency and success rate analytics
    pub async fn get_corridor_analytics(
        &self,
        partner_id: Uuid,
        corridor_id: &str,
        from: NaiveDate,
        to: NaiveDate,
    ) -> Result<CorridorAnalytics, anyhow::Error> {
        self.assert_partner_owns_corridor(partner_id, corridor_id).await?;

        let row: (Option<f64>, Option<f64>, Option<BigDecimal>, Option<i64>) = sqlx::query_as(
            r#"
            SELECT
                AVG(EXTRACT(EPOCH FROM (updated_at - created_at))) AS avg_latency_seconds,
                AVG(CASE WHEN status = 'completed' THEN 1.0 ELSE 0.0 END) AS success_rate,
                SUM(cngn_amount) AS total_volume,
                COUNT(*) AS transaction_count
            FROM transactions
            WHERE metadata->>'corridor_id' = $2
              AND metadata->>'partner_id' = $1::text
              AND type = 'offramp'
              AND DATE(created_at) BETWEEN $3 AND $4
            "#,
        )
        .bind(partner_id)
        .bind(corridor_id)
        .bind(from)
        .bind(to)
        .fetch_one(&self.pool)
        .await?;

        Ok(CorridorAnalytics {
            corridor_id: corridor_id.to_string(),
            partner_id,
            period_start: from,
            period_end: to,
            avg_latency_seconds: row.0.unwrap_or(0.0),
            success_rate: row.1.unwrap_or(0.0),
            total_volume: row.2.unwrap_or_else(|| BigDecimal::from(0)),
            transaction_count: row.3.unwrap_or(0),
        })
    }

    /// Enforce multi-tenant isolation — partner can only access their own corridors
    async fn assert_partner_owns_corridor(
        &self,
        partner_id: Uuid,
        corridor_id: &str,
    ) -> Result<(), anyhow::Error> {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM partner_corridors WHERE partner_id = $1 AND corridor_id = $2)",
        )
        .bind(partner_id)
        .bind(corridor_id)
        .fetch_one(&self.pool)
        .await?;

        if !exists {
            return Err(anyhow::anyhow!(
                "Partner {} does not have access to corridor {}",
                partner_id,
                corridor_id
            ));
        }

        Ok(())
    }
}
