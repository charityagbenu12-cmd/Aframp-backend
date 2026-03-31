//! Statement generator — produces CSV daily settlement statements
//! and schedules auto-email at 00:00 UTC.

use super::models::DailySettlementStatement;
use super::repository::ReportingRepository;
use crate::services::notification::NotificationService;
use chrono::{NaiveDate, Utc};
use std::sync::Arc;
use tracing::{error, info};
use uuid::Uuid;

pub struct StatementGenerator {
    repo: Arc<ReportingRepository>,
    notifications: Arc<NotificationService>,
}

impl StatementGenerator {
    pub fn new(repo: Arc<ReportingRepository>, notifications: Arc<NotificationService>) -> Self {
        Self { repo, notifications }
    }

    /// Generate a CSV statement for a partner/corridor/date
    pub async fn generate_csv(
        &self,
        partner_id: Uuid,
        corridor_id: &str,
        date: NaiveDate,
    ) -> Result<String, anyhow::Error> {
        let stmt = self
            .repo
            .build_daily_statement(partner_id, corridor_id, date)
            .await?;

        let mut csv = String::from(
            "transaction_id,corridor_id,cngn_amount,fx_rate,destination_currency,destination_amount,partner_commission,status,sender_ref,created_at\n",
        );

        for entry in &stmt.entries {
            csv.push_str(&format!(
                "{},{},{},{},{},{},{},{},{},{}\n",
                entry.transaction_id,
                entry.corridor_id,
                entry.cngn_amount,
                entry.fx_rate,
                entry.destination_currency,
                entry.destination_amount,
                entry.partner_commission,
                entry.status,
                entry.sender_ref,
                entry.created_at.format("%Y-%m-%dT%H:%M:%SZ"),
            ));
        }

        info!(
            partner_id = %partner_id,
            corridor = %corridor_id,
            date = %date,
            rows = %stmt.entries.len(),
            "Daily settlement statement generated"
        );

        Ok(csv)
    }

    /// Send daily summary emails to all active partners at 00:00 UTC.
    /// Called by the daily scheduler worker.
    pub async fn send_daily_summaries(&self, date: NaiveDate) {
        let partners = match self.repo.get_active_partners_with_corridors().await {
            Ok(p) => p,
            Err(e) => {
                error!(error = %e, "Failed to fetch partners for daily summary");
                return;
            }
        };

        for (partner_id, corridor_id, finance_email) in partners {
            match self.generate_csv(partner_id, &corridor_id, date).await {
                Ok(csv) => {
                    self.notifications
                        .send_system_alert(
                            &partner_id.to_string(),
                            &format!(
                                "Daily Settlement Summary for {} corridor {} on {} — {} bytes of data ready for {}",
                                partner_id, corridor_id, date, csv.len(), finance_email
                            ),
                        )
                        .await;
                }
                Err(e) => {
                    error!(
                        partner_id = %partner_id,
                        corridor = %corridor_id,
                        error = %e,
                        "Failed to generate daily statement"
                    );
                }
            }
        }
    }
}

// Extend ReportingRepository with partner listing (needed by StatementGenerator)
impl ReportingRepository {
    pub async fn get_active_partners_with_corridors(
        &self,
    ) -> Result<Vec<(Uuid, String, String)>, anyhow::Error> {
        Ok(sqlx::query_as::<_, (Uuid, String, String)>(
            r#"
            SELECT pc.partner_id, pc.corridor_id, p.finance_email
            FROM partner_corridors pc
            JOIN partners p ON p.id = pc.partner_id
            WHERE p.is_active = true
            "#,
        )
        .fetch_all(self.pool())
        .await?)
    }
}
