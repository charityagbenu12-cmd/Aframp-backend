//! Background worker: sends license expiry notifications at 90, 60, and 30 days.

use crate::compliance_registry::repository::ComplianceRegistryRepository;
use sqlx::PgPool;
use std::time::Duration;
use tracing::{error, info, warn};

const NOTIFICATION_THRESHOLDS: &[i32] = &[90, 60, 30];

/// Runs the expiry notification loop. Call this from the workers module.
pub async fn run_expiry_notification_worker(pool: PgPool) {
    let repo = ComplianceRegistryRepository::new(pool);
    let mut interval = tokio::time::interval(Duration::from_secs(3600)); // every hour

    loop {
        interval.tick().await;
        check_and_notify(&repo).await;
    }
}

async fn check_and_notify(repo: &ComplianceRegistryRepository) {
    for &days in NOTIFICATION_THRESHOLDS {
        match repo.licenses_due_for_notification(days).await {
            Ok(licenses) => {
                for license in licenses {
                    // Dispatch notification (email/webhook to Legal & Ops teams).
                    // In production this would call a notification service.
                    warn!(
                        license_id = %license.id,
                        license_number = %license.license_number,
                        corridor_id = %license.corridor_id,
                        expiry_date = %license.expiry_date,
                        days_before = days,
                        "⚠️  License expiry notification: {} days remaining",
                        days
                    );

                    // Mark notification as sent so it isn't re-dispatched.
                    if let Err(e) = repo.record_expiry_notification(license.id, days).await {
                        error!(
                            license_id = %license.id,
                            error = %e,
                            "Failed to record expiry notification"
                        );
                    } else {
                        info!(
                            license_id = %license.id,
                            days_before = days,
                            "Expiry notification recorded"
                        );
                    }
                }
            }
            Err(e) => {
                error!(error = %e, days_before = days, "Failed to query licenses for expiry notification");
            }
        }
    }
}
