use crate::lp_payout::models::{
    AccruedVsPaidSummary, LpAccruedReward, LpPayout, LpPoolSnapshot, LpProvider, LpRewardEpoch,
};
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

pub type RepoResult<T> = Result<T, sqlx::Error>;

pub struct LpPayoutRepository {
    pool: PgPool,
}

impl LpPayoutRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    // ── Providers ────────────────────────────────────────────────────────────

    pub async fn list_active_providers(&self) -> RepoResult<Vec<LpProvider>> {
        sqlx::query_as::<_, LpProvider>(
            "SELECT id, stellar_address, display_name, is_active, whitelisted_at, created_at
             FROM lp_providers WHERE is_active = TRUE",
        )
        .fetch_all(&self.pool)
        .await
    }

    // ── Snapshots ────────────────────────────────────────────────────────────

    pub async fn insert_snapshot(&self, s: &LpPoolSnapshot) -> RepoResult<()> {
        sqlx::query(
            "INSERT INTO lp_pool_snapshots
             (id, snapshot_at, lp_provider_id, pool_id,
              lp_balance_stroops, total_pool_stroops, pro_rata_share, volume_stroops)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
             ON CONFLICT (snapshot_at, lp_provider_id, pool_id) DO NOTHING",
        )
        .bind(s.id)
        .bind(s.snapshot_at)
        .bind(s.lp_provider_id)
        .bind(&s.pool_id)
        .bind(s.lp_balance_stroops)
        .bind(s.total_pool_stroops)
        .bind(&s.pro_rata_share)
        .bind(s.volume_stroops)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn snapshots_for_epoch(
        &self,
        lp_provider_id: Uuid,
        epoch_start: DateTime<Utc>,
        epoch_end: DateTime<Utc>,
    ) -> RepoResult<Vec<LpPoolSnapshot>> {
        sqlx::query_as::<_, LpPoolSnapshot>(
            "SELECT id, snapshot_at, lp_provider_id, pool_id,
                    lp_balance_stroops, total_pool_stroops, pro_rata_share, volume_stroops,
                    created_at
             FROM lp_pool_snapshots
             WHERE lp_provider_id = $1
               AND snapshot_at >= $2
               AND snapshot_at < $3
             ORDER BY snapshot_at ASC",
        )
        .bind(lp_provider_id)
        .bind(epoch_start)
        .bind(epoch_end)
        .fetch_all(&self.pool)
        .await
    }

    // ── Epochs ───────────────────────────────────────────────────────────────

    pub async fn get_or_create_current_epoch(
        &self,
        epoch_start: DateTime<Utc>,
        epoch_end: DateTime<Utc>,
        mining_rate: sqlx::types::BigDecimal,
    ) -> RepoResult<LpRewardEpoch> {
        if let Some(epoch) = sqlx::query_as::<_, LpRewardEpoch>(
            "SELECT id, epoch_start, epoch_end, total_fees_stroops, total_volume_stroops,
                    mining_rate_per_1000, is_finalized, finalized_at, created_at
             FROM lp_reward_epochs
             WHERE epoch_start = $1 AND epoch_end = $2",
        )
        .bind(epoch_start)
        .bind(epoch_end)
        .fetch_optional(&self.pool)
        .await?
        {
            return Ok(epoch);
        }

        sqlx::query_as::<_, LpRewardEpoch>(
            "INSERT INTO lp_reward_epochs (epoch_start, epoch_end, mining_rate_per_1000)
             VALUES ($1, $2, $3)
             ON CONFLICT (epoch_start, epoch_end) DO UPDATE
               SET mining_rate_per_1000 = EXCLUDED.mining_rate_per_1000
             RETURNING id, epoch_start, epoch_end, total_fees_stroops, total_volume_stroops,
                       mining_rate_per_1000, is_finalized, finalized_at, created_at",
        )
        .bind(epoch_start)
        .bind(epoch_end)
        .bind(mining_rate)
        .fetch_one(&self.pool)
        .await
    }

    pub async fn update_epoch_fees(
        &self,
        epoch_id: Uuid,
        total_fees_stroops: i64,
        total_volume_stroops: i64,
    ) -> RepoResult<()> {
        sqlx::query(
            "UPDATE lp_reward_epochs
             SET total_fees_stroops = $2, total_volume_stroops = $3
             WHERE id = $1",
        )
        .bind(epoch_id)
        .bind(total_fees_stroops)
        .bind(total_volume_stroops)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn finalize_epoch(&self, epoch_id: Uuid) -> RepoResult<()> {
        sqlx::query(
            "UPDATE lp_reward_epochs
             SET is_finalized = TRUE, finalized_at = NOW()
             WHERE id = $1",
        )
        .bind(epoch_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_unfinalized_epochs(&self) -> RepoResult<Vec<LpRewardEpoch>> {
        sqlx::query_as::<_, LpRewardEpoch>(
            "SELECT id, epoch_start, epoch_end, total_fees_stroops, total_volume_stroops,
                    mining_rate_per_1000, is_finalized, finalized_at, created_at
             FROM lp_reward_epochs
             WHERE is_finalized = FALSE AND epoch_end <= NOW()
             ORDER BY epoch_end ASC",
        )
        .fetch_all(&self.pool)
        .await
    }

    // ── Accrued rewards ──────────────────────────────────────────────────────

    pub async fn upsert_accrued_reward(
        &self,
        epoch_id: Uuid,
        lp_provider_id: Uuid,
        reward_type: &str,
        accrued_stroops: i64,
        is_wash_trade_excluded: bool,
        compliance_flagged: bool,
        compliance_reason: Option<&str>,
    ) -> RepoResult<()> {
        sqlx::query(
            "INSERT INTO lp_accrued_rewards
             (epoch_id, lp_provider_id, reward_type, accrued_stroops,
              is_wash_trade_excluded, compliance_flagged, compliance_reason, updated_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,NOW())
             ON CONFLICT (epoch_id, lp_provider_id, reward_type) DO UPDATE
               SET accrued_stroops = EXCLUDED.accrued_stroops,
                   is_wash_trade_excluded = EXCLUDED.is_wash_trade_excluded,
                   compliance_flagged = EXCLUDED.compliance_flagged,
                   compliance_reason = EXCLUDED.compliance_reason,
                   updated_at = NOW()",
        )
        .bind(epoch_id)
        .bind(lp_provider_id)
        .bind(reward_type)
        .bind(accrued_stroops)
        .bind(is_wash_trade_excluded)
        .bind(compliance_flagged)
        .bind(compliance_reason)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn accrued_rewards_for_epoch(
        &self,
        epoch_id: Uuid,
    ) -> RepoResult<Vec<LpAccruedReward>> {
        sqlx::query_as::<_, LpAccruedReward>(
            "SELECT id, epoch_id, lp_provider_id, reward_type,
                    accrued_stroops, paid_stroops,
                    is_wash_trade_excluded, compliance_flagged, compliance_reason,
                    updated_at
             FROM lp_accrued_rewards
             WHERE epoch_id = $1",
        )
        .bind(epoch_id)
        .fetch_all(&self.pool)
        .await
    }

    // ── Payouts ──────────────────────────────────────────────────────────────

    pub async fn create_payout(&self, payout: &LpPayout) -> RepoResult<()> {
        sqlx::query(
            "INSERT INTO lp_payouts
             (id, epoch_id, lp_provider_id, stellar_address, total_stroops,
              status, compliance_withheld, compliance_reason)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
             ON CONFLICT (epoch_id, lp_provider_id) DO NOTHING",
        )
        .bind(payout.id)
        .bind(payout.epoch_id)
        .bind(payout.lp_provider_id)
        .bind(&payout.stellar_address)
        .bind(payout.total_stroops)
        .bind(&payout.status)
        .bind(payout.compliance_withheld)
        .bind(&payout.compliance_reason)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn mark_payout_completed(
        &self,
        payout_id: Uuid,
        stellar_tx_hash: &str,
    ) -> RepoResult<()> {
        sqlx::query(
            "UPDATE lp_payouts
             SET status = 'completed', stellar_tx_hash = $2, completed_at = NOW()
             WHERE id = $1",
        )
        .bind(payout_id)
        .bind(stellar_tx_hash)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn mark_payout_failed(&self, payout_id: Uuid) -> RepoResult<()> {
        sqlx::query("UPDATE lp_payouts SET status = 'failed' WHERE id = $1")
            .bind(payout_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn pending_payouts(&self) -> RepoResult<Vec<LpPayout>> {
        sqlx::query_as::<_, LpPayout>(
            "SELECT id, epoch_id, lp_provider_id, stellar_address, total_stroops,
                    status, stellar_tx_hash, compliance_withheld, compliance_reason,
                    attempted_at, completed_at, created_at
             FROM lp_payouts
             WHERE status = 'pending'
             ORDER BY created_at ASC",
        )
        .fetch_all(&self.pool)
        .await
    }

    // ── Analytics: accrued vs paid ────────────────────────────────────────────

    pub async fn accrued_vs_paid(
        &self,
        lp_provider_id: Uuid,
    ) -> RepoResult<Vec<AccruedVsPaidSummary>> {
        #[derive(sqlx::FromRow)]
        struct Row {
            lp_provider_id: Uuid,
            stellar_address: String,
            epoch_id: Uuid,
            epoch_start: DateTime<Utc>,
            epoch_end: DateTime<Utc>,
            accrued_stroops: Option<i64>,
            paid_stroops: Option<i64>,
            compliance_flagged: Option<bool>,
        }

        let rows = sqlx::query_as::<_, Row>(
            "SELECT
               ar.lp_provider_id,
               p.stellar_address,
               ar.epoch_id,
               e.epoch_start,
               e.epoch_end,
               SUM(ar.accrued_stroops)::BIGINT AS accrued_stroops,
               SUM(ar.paid_stroops)::BIGINT    AS paid_stroops,
               BOOL_OR(ar.compliance_flagged)  AS compliance_flagged
             FROM lp_accrued_rewards ar
             JOIN lp_reward_epochs e ON e.id = ar.epoch_id
             JOIN lp_providers p ON p.id = ar.lp_provider_id
             WHERE ar.lp_provider_id = $1
             GROUP BY ar.lp_provider_id, p.stellar_address, ar.epoch_id,
                      e.epoch_start, e.epoch_end
             ORDER BY e.epoch_start DESC",
        )
        .bind(lp_provider_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| {
                let accrued = r.accrued_stroops.unwrap_or(0);
                let paid = r.paid_stroops.unwrap_or(0);
                AccruedVsPaidSummary {
                    lp_provider_id: r.lp_provider_id,
                    stellar_address: r.stellar_address,
                    epoch_id: r.epoch_id,
                    epoch_start: r.epoch_start,
                    epoch_end: r.epoch_end,
                    accrued_stroops: accrued,
                    paid_stroops: paid,
                    pending_stroops: accrued - paid,
                    compliance_flagged: r.compliance_flagged.unwrap_or(false),
                }
            })
            .collect())
    }
}
