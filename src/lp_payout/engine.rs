//! LP Reward Calculation Engine
//!
//! Implements two reward modes:
//!   1. Fee-based  — LP's pro-rata share of dynamic fees collected in the epoch.
//!   2. Mining     — Fixed cNGN per 1,000 NGN provided per hour.
//!
//! Wash-trade detection: any snapshot whose volume exceeds a configurable
//! multiple of the pool's average volume is excluded from reward eligibility.

use crate::lp_payout::{
    models::{compliance_threshold_stroops, default_mining_rate_per_1000, LpPoolSnapshot},
    repository::LpPayoutRepository,
};
use chrono::{DateTime, Datelike, Duration, Utc};
use sqlx::types::BigDecimal;
use std::str::FromStr;
use std::sync::Arc;
use tracing::{info, warn};
use uuid::Uuid;

/// Multiplier above average volume that flags a snapshot as wash-trade.
const WASH_TRADE_VOLUME_MULTIPLIER: f64 = 10.0;

pub struct RewardEngine {
    repo: Arc<LpPayoutRepository>,
}

impl RewardEngine {
    pub fn new(repo: Arc<LpPayoutRepository>) -> Self {
        Self { repo }
    }

    // ── Snapshot ─────────────────────────────────────────────────────────────

    /// Record an hourly snapshot for every active LP.
    /// `pool_data` is a list of `(pool_id, lp_provider_id, lp_balance, total_pool, volume)`.
    pub async fn record_snapshots(
        &self,
        snapshot_at: DateTime<Utc>,
        pool_data: Vec<(String, Uuid, i64, i64, i64)>,
    ) -> anyhow::Result<()> {
        for (pool_id, lp_provider_id, lp_balance, total_pool, volume) in pool_data {
            if total_pool == 0 {
                continue;
            }
            let pro_rata = BigDecimal::from_str(&lp_balance.to_string())?
                / BigDecimal::from_str(&total_pool.to_string())?;

            let snap = crate::lp_payout::models::LpPoolSnapshot {
                id: Uuid::new_v4(),
                snapshot_at,
                lp_provider_id,
                pool_id,
                lp_balance_stroops: lp_balance,
                total_pool_stroops: total_pool,
                pro_rata_share: pro_rata,
                volume_stroops: volume,
                created_at: Utc::now(),
            };
            self.repo.insert_snapshot(&snap).await?;
        }
        Ok(())
    }

    // ── Reward calculation ────────────────────────────────────────────────────

    /// Calculate and persist accrued rewards for all LPs in an epoch.
    pub async fn calculate_epoch_rewards(
        &self,
        epoch_id: Uuid,
        epoch_start: DateTime<Utc>,
        epoch_end: DateTime<Utc>,
        total_fees_stroops: i64,
        total_volume_stroops: i64,
    ) -> anyhow::Result<()> {
        self.repo
            .update_epoch_fees(epoch_id, total_fees_stroops, total_volume_stroops)
            .await?;

        let providers = self.repo.list_active_providers().await?;
        let compliance_threshold = compliance_threshold_stroops();
        let mining_rate = default_mining_rate_per_1000();

        for provider in &providers {
            let snapshots = self
                .repo
                .snapshots_for_epoch(provider.id, epoch_start, epoch_end)
                .await?;

            if snapshots.is_empty() {
                continue;
            }

            let avg_volume = snapshots.iter().map(|s| s.volume_stroops).sum::<i64>()
                / snapshots.len() as i64;

            // ── Fee-based reward ──────────────────────────────────────────────
            let fee_reward = self.calc_fee_reward(&snapshots, total_fees_stroops, avg_volume);

            // ── Mining reward ─────────────────────────────────────────────────
            let mining_reward = self.calc_mining_reward(&snapshots, mining_rate, avg_volume);

            for (reward_type, reward_stroops) in
                [("fee_based", fee_reward), ("liquidity_mining", mining_reward)]
            {
                let wash_excluded = reward_stroops == 0
                    && snapshots
                        .iter()
                        .all(|s| is_wash_trade(s, avg_volume));

                let compliance_flagged = reward_stroops > compliance_threshold;
                let compliance_reason = if compliance_flagged {
                    Some(format!(
                        "Reward {} stroops exceeds threshold {}",
                        reward_stroops, compliance_threshold
                    ))
                } else {
                    None
                };

                if compliance_flagged {
                    warn!(
                        lp = %provider.stellar_address,
                        reward_type,
                        reward_stroops,
                        "LP reward flagged for compliance review"
                    );
                }

                self.repo
                    .upsert_accrued_reward(
                        epoch_id,
                        provider.id,
                        reward_type,
                        reward_stroops,
                        wash_excluded,
                        compliance_flagged,
                        compliance_reason.as_deref(),
                    )
                    .await?;
            }

            info!(
                lp = %provider.stellar_address,
                fee_reward,
                mining_reward,
                "Rewards calculated for LP"
            );
        }

        Ok(())
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn calc_fee_reward(
        &self,
        snapshots: &[LpPoolSnapshot],
        total_fees_stroops: i64,
        avg_volume: i64,
    ) -> i64 {
        if total_fees_stroops == 0 || snapshots.is_empty() {
            return 0;
        }
        // Average pro-rata share across non-wash-trade snapshots
        let valid: Vec<&LpPoolSnapshot> = snapshots
            .iter()
            .filter(|s| !is_wash_trade(s, avg_volume))
            .collect();

        if valid.is_empty() {
            return 0;
        }

        let avg_share: f64 = valid
            .iter()
            .map(|s| {
                s.pro_rata_share
                    .to_string()
                    .parse::<f64>()
                    .unwrap_or(0.0)
            })
            .sum::<f64>()
            / valid.len() as f64;

        (total_fees_stroops as f64 * avg_share) as i64
    }

    fn calc_mining_reward(
        &self,
        snapshots: &[LpPoolSnapshot],
        rate_per_1000: f64,
        avg_volume: i64,
    ) -> i64 {
        // Sum: (lp_balance_stroops / 1000) * rate_per_1000 for each valid hourly snapshot
        snapshots
            .iter()
            .filter(|s| !is_wash_trade(s, avg_volume))
            .map(|s| {
                let units = s.lp_balance_stroops as f64 / 1_000.0;
                (units * rate_per_1000) as i64
            })
            .sum()
    }
}

fn is_wash_trade(snapshot: &LpPoolSnapshot, avg_volume: i64) -> bool {
    avg_volume > 0
        && snapshot.volume_stroops as f64 > avg_volume as f64 * WASH_TRADE_VOLUME_MULTIPLIER
}

// ── Epoch boundary helpers ────────────────────────────────────────────────────

/// Returns the start of the current weekly epoch (Monday 00:00 UTC).
pub fn current_epoch_start() -> DateTime<Utc> {
    let now = Utc::now();
    let days_since_monday = now.weekday().num_days_from_monday() as i64;
    let date = (now - Duration::days(days_since_monday)).date_naive();
    date.and_hms_opt(0, 0, 0).unwrap().and_utc()
}

pub fn epoch_end_from_start(start: DateTime<Utc>) -> DateTime<Utc> {
    start + Duration::weeks(1)
}
