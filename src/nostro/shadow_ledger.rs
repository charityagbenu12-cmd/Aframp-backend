//! Shadow Ledger — mirrors actual balances held in foreign partner banks
//!
//! Provides the authoritative in-platform view of Nostro account balances,
//! enabling instant corridor availability checks without hitting bank APIs.

use super::models::{CorridorStatus, LiquidityAlert, NostroAccount};
use super::repository::NostroRepository;
use crate::services::notification::NotificationService;
use chrono::Utc;
use sqlx::types::BigDecimal;
use std::str::FromStr;
use std::sync::Arc;
use tracing::{info, warn};
use uuid::Uuid;

pub struct ShadowLedger {
    repo: Arc<NostroRepository>,
    notifications: Arc<NotificationService>,
}

impl ShadowLedger {
    pub fn new(repo: Arc<NostroRepository>, notifications: Arc<NotificationService>) -> Self {
        Self { repo, notifications }
    }

    /// Update the shadow balance from a fresh bank poll result.
    /// Automatically disables the corridor and fires a refill alert if below safety buffer.
    pub async fn update_balance(
        &self,
        account_id: Uuid,
        cleared: BigDecimal,
        pending: BigDecimal,
        source: &str,
    ) -> Result<(), anyhow::Error> {
        let account = self.repo.get_account(account_id).await?;

        self.repo
            .upsert_balance(account_id, cleared.clone(), pending.clone(), source)
            .await?;

        // Compute safety buffer amount
        let avg_daily = self.repo.get_average_daily_volume(account_id).await?;
        let buffer_fraction =
            BigDecimal::from_str(&account.safety_buffer_fraction.to_string())?;
        let safety_buffer = &avg_daily * &buffer_fraction;

        if cleared < safety_buffer {
            let shortfall = &safety_buffer - &cleared;

            warn!(
                account_id = %account_id,
                corridor = %account.corridor_id,
                currency = %account.currency,
                cleared = %cleared,
                safety_buffer = %safety_buffer,
                shortfall = %shortfall,
                "Nostro balance below safety buffer — disabling corridor"
            );

            // Disable corridor
            self.repo
                .set_corridor_status(&account.corridor_id, CorridorStatus::DisabledInsufficientFunds)
                .await?;

            // Fire refill alert to Treasury
            let alert = LiquidityAlert {
                account_id,
                corridor_id: account.corridor_id.clone(),
                currency: account.currency.clone(),
                current_balance: cleared,
                safety_buffer_amount: safety_buffer,
                shortfall,
                alerted_at: Utc::now(),
            };

            self.notifications
                .send_system_alert(
                    &account_id.to_string(),
                    &format!(
                        "TREASURY ALERT: Nostro account {} ({}) balance below safety buffer. \
                         Corridor {} disabled. Shortfall: {} {}",
                        account.bank_name,
                        account.account_reference,
                        account.corridor_id,
                        alert.shortfall,
                        account.currency
                    ),
                )
                .await;

            self.repo.record_liquidity_alert(&alert).await?;
        } else {
            // Re-enable corridor if it was disabled due to insufficient funds
            self.repo
                .restore_corridor_if_disabled(&account.corridor_id)
                .await?;
        }

        Ok(())
    }

    /// Check whether a corridor has sufficient liquidity for a given amount
    pub async fn check_corridor_available(
        &self,
        corridor_id: &str,
        required_amount: &BigDecimal,
    ) -> Result<bool, anyhow::Error> {
        let status = self.repo.get_corridor_status(corridor_id).await?;
        if status != CorridorStatus::Active {
            return Ok(false);
        }

        let balance = self.repo.get_corridor_cleared_balance(corridor_id).await?;
        Ok(&balance >= required_amount)
    }

    /// Global liquidity map — all corridors with current balances
    pub async fn global_liquidity_map(
        &self,
    ) -> Result<Vec<serde_json::Value>, anyhow::Error> {
        self.repo.get_global_liquidity_map().await
    }
}
