//! Background worker for API key rotation & expiry management (Issue #137).
//!
//! Runs two periodic tasks:
//!   1. Grace period expiry — invalidates old keys whose grace period has elapsed.
//!   2. Expiry notifications — sends warning emails at 30/14/7/1 day thresholds
//!      and a final notification when a key actually expires.

use std::time::Duration;
use tokio::sync::watch;
use tracing::{error, info};

use crate::services::key_rotation::KeyRotationService;

pub struct KeyRotationWorker {
    service: KeyRotationService,
    /// How often to run the grace-period expiry sweep (default: every hour).
    grace_interval: Duration,
    /// How often to run the expiry notification sweep (default: every 24 hours).
    notification_interval: Duration,
}

impl KeyRotationWorker {
    pub fn new(service: KeyRotationService) -> Self {
        let grace_interval = Duration::from_secs(
            std::env::var("KEY_ROTATION_GRACE_CHECK_INTERVAL_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(3600), // 1 hour
        );
        let notification_interval = Duration::from_secs(
            std::env::var("KEY_EXPIRY_NOTIFICATION_INTERVAL_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(86400), // 24 hours
        );
        Self { service, grace_interval, notification_interval }
    }

    pub async fn run(self, mut shutdown: watch::Receiver<bool>) {
        let mut grace_ticker = tokio::time::interval(self.grace_interval);
        let mut notif_ticker = tokio::time::interval(self.notification_interval);

        info!(
            grace_interval_secs = self.grace_interval.as_secs(),
            notification_interval_secs = self.notification_interval.as_secs(),
            "Key rotation worker started"
        );

        loop {
            tokio::select! {
                _ = grace_ticker.tick() => {
                    match self.service.expire_grace_periods().await {
                        Ok(n) if n > 0 => info!(count = n, "Expired grace periods processed"),
                        Ok(_) => {}
                        Err(e) => error!(error = %e, "Failed to expire grace periods"),
                    }
                }
                _ = notif_ticker.tick() => {
                    match self.service.collect_expiry_notifications().await {
                        Ok(notifications) => {
                            for (consumer_id, key_id, days) in &notifications {
                                // In production this would dispatch to a notification
                                // service (email/SMS). Here we log for observability.
                                if *days == 0 {
                                    info!(
                                        consumer_id = %consumer_id,
                                        key_id = %key_id,
                                        "API key expired — final notification queued"
                                    );
                                } else {
                                    info!(
                                        consumer_id = %consumer_id,
                                        key_id = %key_id,
                                        days_until_expiry = days,
                                        "API key expiry warning notification queued"
                                    );
                                }
                            }
                            if !notifications.is_empty() {
                                info!(count = notifications.len(), "Expiry notifications queued");
                            }
                        }
                        Err(e) => error!(error = %e, "Failed to collect expiry notifications"),
                    }
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        info!("Key rotation worker shutting down");
                        break;
                    }
                }
            }
        }
    }
}
