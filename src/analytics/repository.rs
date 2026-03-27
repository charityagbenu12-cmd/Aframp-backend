use crate::analytics::models::*;
use crate::database::error::DatabaseError;
use chrono::{DateTime, Utc};
use sqlx::PgPool;

/// All analytics queries run against a dedicated read-replica pool so they
/// never contend with the primary transactional database.
pub struct AnalyticsRepository {
    /// Read-replica (or primary when a replica is not configured).
    pool: PgPool,
}

impl AnalyticsRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    // ── Transaction Volume ────────────────────────────────────────────────

    pub async fn transaction_volume(
        &self,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
        period: &str,
    ) -> Result<Vec<VolumeByPeriod>, DatabaseError> {
        let trunc = period_trunc(period);
        sqlx::query_as::<_, VolumeByPeriod>(&format!(
            r#"
            SELECT
                date_trunc('{trunc}', created_at)::text AS period,
                from_currency                            AS currency,
                type                                     AS transaction_type,
                status,
                COUNT(*)                                 AS count,
                COALESCE(SUM(from_amount), 0)            AS total_volume
            FROM transactions
            WHERE created_at >= $1
              AND created_at <  $2
            GROUP BY 1, 2, 3, 4
            ORDER BY 1, 2, 3, 4
            "#
        ))
        .bind(from)
        .bind(to)
        .fetch_all(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)
    }

    // ── cNGN Conversions ──────────────────────────────────────────────────

    pub async fn cngn_conversions(
        &self,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
        period: &str,
    ) -> Result<Vec<CngnConversionPeriod>, DatabaseError> {
        let trunc = period_trunc(period);
        sqlx::query_as::<_, CngnConversionPeriod>(&format!(
            r#"
            SELECT
                date_trunc('{trunc}', created_at)::text                                AS period,
                COALESCE(SUM(CASE WHEN type = 'onramp'  THEN cngn_amount ELSE 0 END), 0) AS minted,
                COALESCE(SUM(CASE WHEN type = 'offramp' THEN cngn_amount ELSE 0 END), 0) AS redeemed,
                COALESCE(
                    AVG(CASE WHEN from_amount > 0 THEN to_amount / from_amount END), 0
                )                                                                       AS avg_rate,
                COALESCE(SUM(CASE WHEN type = 'onramp'  THEN  cngn_amount
                                  WHEN type = 'offramp' THEN -cngn_amount
                                  ELSE 0 END), 0)                                      AS net_circulation_change
            FROM transactions
            WHERE created_at >= $1
              AND created_at <  $2
              AND status = 'completed'
            GROUP BY 1
            ORDER BY 1
            "#
        ))
        .bind(from)
        .bind(to)
        .fetch_all(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)
    }

    // ── Provider Performance ──────────────────────────────────────────────

    pub async fn provider_performance(
        &self,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
        period: &str,
    ) -> Result<Vec<ProviderPerformancePeriod>, DatabaseError> {
        let trunc = period_trunc(period);
        sqlx::query_as::<_, ProviderPerformancePeriod>(&format!(
            r#"
            WITH totals AS (
                SELECT date_trunc('{trunc}', created_at) AS p, COUNT(*) AS grand_total
                FROM transactions
                WHERE created_at >= $1 AND created_at < $2
                  AND payment_provider IS NOT NULL
                GROUP BY 1
            )
            SELECT
                date_trunc('{trunc}', t.created_at)::text                          AS period,
                t.payment_provider                                                  AS provider,
                COUNT(*)                                                            AS total_count,
                COUNT(*) FILTER (WHERE t.status = 'completed')                     AS success_count,
                ROUND(
                    100.0 * COUNT(*) FILTER (WHERE t.status = 'completed') / NULLIF(COUNT(*), 0),
                    2
                )                                                                   AS success_rate,
                COALESCE(
                    AVG(EXTRACT(EPOCH FROM (t.updated_at - t.created_at))), 0
                )                                                                   AS avg_processing_seconds,
                ROUND(
                    100.0 * COUNT(*) / NULLIF(tot.grand_total, 0), 2
                )                                                                   AS volume_share_pct
            FROM transactions t
            JOIN totals tot ON date_trunc('{trunc}', t.created_at) = tot.p
            WHERE t.created_at >= $1
              AND t.created_at <  $2
              AND t.payment_provider IS NOT NULL
            GROUP BY 1, 2, tot.grand_total
            ORDER BY 1, 2
            "#
        ))
        .bind(from)
        .bind(to)
        .fetch_all(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)
    }

    pub async fn provider_failure_breakdown(
        &self,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> Result<Vec<ProviderFailureBreakdown>, DatabaseError> {
        sqlx::query_as::<_, ProviderFailureBreakdown>(
            r#"
            SELECT
                payment_provider                                AS provider,
                COALESCE(error_message, 'unknown')             AS failure_reason,
                COUNT(*)                                        AS count
            FROM transactions
            WHERE created_at >= $1
              AND created_at <  $2
              AND status IN ('failed', 'refunded')
              AND payment_provider IS NOT NULL
            GROUP BY 1, 2
            ORDER BY 1, 3 DESC
            "#,
        )
        .bind(from)
        .bind(to)
        .fetch_all(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)
    }

    // ── Summary ───────────────────────────────────────────────────────────

    /// Returns (count, volume) for a single calendar day.
    pub async fn daily_totals(
        &self,
        day_start: DateTime<Utc>,
        day_end: DateTime<Utc>,
    ) -> Result<(i64, sqlx::types::BigDecimal, sqlx::types::BigDecimal, i64), DatabaseError> {
        let row = sqlx::query!(
            r#"
            SELECT
                COUNT(*)                                                AS "count!: i64",
                COALESCE(SUM(from_amount), 0)                          AS "volume!: sqlx::types::BigDecimal",
                COALESCE(SUM(cngn_amount), 0)                          AS "cngn!: sqlx::types::BigDecimal",
                COUNT(DISTINCT wallet_address)                         AS "wallets!: i64"
            FROM transactions
            WHERE created_at >= $1 AND created_at < $2
            "#,
            day_start,
            day_end,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok((row.count, row.volume, row.cngn, row.wallets))
    }

    /// Returns the freshness of the latest exchange rate in seconds.
    pub async fn rate_freshness_seconds(&self) -> Result<i64, DatabaseError> {
        let row = sqlx::query!(
            r#"
            SELECT EXTRACT(EPOCH FROM (NOW() - MAX(fetched_at)))::bigint AS "age!: i64"
            FROM exchange_rate_history
            "#
        )
        .fetch_one(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?;
        Ok(row.age)
    }

    /// Returns the list of currently enabled payment providers.
    pub async fn active_providers(&self) -> Result<Vec<String>, DatabaseError> {
        let rows = sqlx::query!(
            "SELECT provider FROM payment_provider_configs WHERE is_enabled = true ORDER BY provider"
        )
        .fetch_all(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?;
        Ok(rows.into_iter().map(|r| r.provider).collect())
    }
}

// ── helpers ───────────────────────────────────────────────────────────────────

fn period_trunc(period: &str) -> &'static str {
    match period {
        "weekly" => "week",
        "monthly" => "month",
        _ => "day",
    }
}
