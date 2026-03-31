//! End-of-Day reconciliation worker
//!
//! Matches on-chain cNGN burns/locks with outgoing fiat bank transfers
//! to identify breakages. Runs at 00:00 UTC daily.

use super::models::EodReconciliationResult;
use super::repository::NostroRepository;
use crate::services::notification::NotificationService;
use chrono::{NaiveDate, Utc};
use sqlx::types::BigDecimal;
use std::sync::Arc;
use tracing::{error, info, warn};

pub struct EodReconciliationWorker {
    repo: Arc<NostroRepository>,
    notifications: Arc<NotificationService>,
}

impl EodReconciliationWorker {
    pub fn new(repo: Arc<NostroRepository>, notifications: Arc<NotificationService>) -> Self {
        Self { repo, notifications }
    }

    /// Run EOD reconciliation for all active corridors for the given date.
    pub async fn run_for_date(&self, date: NaiveDate) -> Result<(), anyhow::Error> {
        let accounts = self.repo.get_all_active_accounts().await?;

        for account in accounts {
            match self.reconcile_corridor(&account.id, &account.corridor_id, date).await {
                Ok(result) => {
                    if result.status == "discrepant" {
                        warn!(
                            corridor = %account.corridor_id,
                            discrepancy = %result.discrepancy,
                            "EOD reconciliation discrepancy detected"
                        );
                        self.notifications
                            .send_system_alert(
                                &result.id.to_string(),
                                &format!(
                                    "EOD RECONCILIATION DISCREPANCY: Corridor {} — \
                                     on-chain burns: {}, fiat outflows: {}, breakage: {}",
                                    account.corridor_id,
                                    result.onchain_burns,
                                    result.fiat_outflows,
                                    result.discrepancy
                                ),
                            )
                            .await;
                    } else {
                        info!(corridor = %account.corridor_id, "EOD reconciliation matched");
                    }
                }
                Err(e) => {
                    error!(
                        corridor = %account.corridor_id,
                        error = %e,
                        "EOD reconciliation failed"
                    );
                }
            }
        }

        Ok(())
    }

    async fn reconcile_corridor(
        &self,
        account_id: &uuid::Uuid,
        corridor_id: &str,
        date: NaiveDate,
    ) -> Result<EodReconciliationResult, anyhow::Error> {
        let onchain_burns = self.repo.get_onchain_burns_for_date(corridor_id, date).await?;
        let fiat_outflows = self.repo.get_fiat_outflows_for_date(account_id, date).await?;

        let discrepancy = &onchain_burns - &fiat_outflows;
        let abs_discrepancy = if discrepancy < BigDecimal::from(0) {
            -discrepancy.clone()
        } else {
            discrepancy.clone()
        };

        // Tolerance: 0.01 (rounding differences)
        let tolerance: BigDecimal = "0.01".parse().unwrap_or_else(|_| BigDecimal::from(0));
        let status = if abs_discrepancy <= tolerance {
            "matched"
        } else {
            "discrepant"
        };

        let result = self
            .repo
            .save_eod_result(*account_id, corridor_id, date, &onchain_burns, &fiat_outflows, &discrepancy, status)
            .await?;

        Ok(result)
    }
}
