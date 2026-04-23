use crate::lp_onboarding::repository::LpOnboardingRepository;
use chrono::Utc;
use std::sync::Arc;
use tokio::time::{interval, Duration};
use tracing::{error, info};

/// Background worker that fires expiry alerts 30 days and 7 days before an
/// LP agreement expires. Runs on a daily cadence.
pub struct AgreementExpiryWorker {
    repo: Arc<LpOnboardingRepository>,
}

impl AgreementExpiryWorker {
    pub fn new(repo: Arc<LpOnboardingRepository>) -> Self {
        Self { repo }
    }

    pub async fn run(self) {
        let mut ticker = interval(Duration::from_secs(86_400)); // 24 h
        loop {
            ticker.tick().await;
            if let Err(e) = self.check_expiries().await {
                error!(error=%e, "Agreement expiry worker error");
            }
        }
    }

    async fn check_expiries(&self) -> Result<(), sqlx::Error> {
        // 30-day alerts
        let due_30 = self
            .repo
            .agreements_expiring_within(30, "expiry_alert_30d_sent")
            .await?;
        for agreement in due_30 {
            info!(
                agreement_id=%agreement.agreement_id,
                partner_id=%agreement.partner_id,
                expires_on=%agreement.expires_on,
                "Sending 30-day expiry alert"
            );
            // TODO: plug into notification service
            self.repo
                .mark_expiry_alert_sent(agreement.agreement_id, "expiry_alert_30d_sent")
                .await?;
        }

        // 7-day alerts
        let due_7 = self
            .repo
            .agreements_expiring_within(7, "expiry_alert_7d_sent")
            .await?;
        for agreement in due_7 {
            info!(
                agreement_id=%agreement.agreement_id,
                partner_id=%agreement.partner_id,
                expires_on=%agreement.expires_on,
                "Sending 7-day expiry alert"
            );
            self.repo
                .mark_expiry_alert_sent(agreement.agreement_id, "expiry_alert_7d_sent")
                .await?;
        }

        Ok(())
    }
}
