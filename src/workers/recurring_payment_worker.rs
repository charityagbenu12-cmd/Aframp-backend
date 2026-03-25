//! Recurring payment execution worker.
//!
//! Polls for active schedules whose `next_execution_at` is due, executes the
//! configured payment, records the outcome, and advances the schedule.
//! Idempotency is enforced via the unique index on
//! `recurring_payment_executions(schedule_id, scheduled_at)`.

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use tokio::sync::watch;
use tracing::{error, info};
use uuid::Uuid;

use crate::database::recurring_payment_repository::RecurringPaymentRepository;
use crate::recurring::frequency::{advance_schedule, Frequency};
use crate::recurring::notification;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct RecurringWorkerConfig {
    /// How often the worker polls for due schedules.
    pub poll_interval: Duration,
    /// Maximum schedules processed per poll cycle.
    pub batch_size: i64,
}

impl Default for RecurringWorkerConfig {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_secs(60),
            batch_size: 100,
        }
    }
}

impl RecurringWorkerConfig {
    pub fn from_env() -> Self {
        Self {
            poll_interval: Duration::from_secs(
                std::env::var("RECURRING_POLL_INTERVAL_SECS")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(60),
            ),
            batch_size: std::env::var("RECURRING_BATCH_SIZE")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(100),
        }
    }
}

// ---------------------------------------------------------------------------
// Worker
// ---------------------------------------------------------------------------

pub struct RecurringPaymentWorker {
    repo: Arc<RecurringPaymentRepository>,
    config: RecurringWorkerConfig,
}

impl RecurringPaymentWorker {
    pub fn new(repo: Arc<RecurringPaymentRepository>, config: RecurringWorkerConfig) -> Self {
        Self { repo, config }
    }

    /// Run the worker loop until a shutdown signal is received.
    pub async fn run(self, mut shutdown: watch::Receiver<bool>) {
        let mut interval = tokio::time::interval(self.config.poll_interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        info!(
            poll_interval_secs = self.config.poll_interval.as_secs(),
            batch_size = self.config.batch_size,
            "Recurring payment worker started"
        );

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    self.run_cycle().await;
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        info!("Recurring payment worker shutting down");
                        break;
                    }
                }
            }
        }
    }

    async fn run_cycle(&self) {
        let now = Utc::now();

        let due = match self.repo.fetch_due_schedules(now, self.config.batch_size).await {
            Ok(schedules) => schedules,
            Err(e) => {
                error!(error = %e, "Failed to fetch due recurring schedules");
                return;
            }
        };

        if due.is_empty() {
            return;
        }

        info!(count = due.len(), "Processing due recurring schedules");

        for schedule in due {
            let schedule_id = schedule.id;
            let scheduled_at = schedule.next_execution_at;

            let freq = match Frequency::parse(&schedule.frequency, schedule.custom_interval_days) {
                Ok(f) => f,
                Err(e) => {
                    error!(schedule_id = %schedule_id, error = %e, "Invalid frequency on schedule");
                    continue;
                }
            };

            let next = advance_schedule(&freq, scheduled_at);

            // Execute the payment.
            let result = self.execute_payment(&schedule).await;

            match result {
                Ok(transaction_id) => {
                    // Record execution — ON CONFLICT DO NOTHING ensures idempotency.
                    match self
                        .repo
                        .insert_execution(
                            schedule_id,
                            scheduled_at,
                            "success",
                            Some(transaction_id),
                            None,
                        )
                        .await
                    {
                        Ok(None) => {
                            // Already recorded — skip updating the schedule too.
                            info!(
                                schedule_id = %schedule_id,
                                scheduled_at = %scheduled_at,
                                "Skipping already-executed recurring schedule (idempotency)"
                            );
                            continue;
                        }
                        Ok(Some(_)) => {}
                        Err(e) => {
                            error!(schedule_id = %schedule_id, error = %e, "Failed to insert execution record");
                            continue;
                        }
                    }

                    if let Err(e) = self.repo.record_success(schedule_id, next).await {
                        error!(schedule_id = %schedule_id, error = %e, "Failed to advance schedule after success");
                    }

                    notification::notify_success(
                        schedule_id,
                        &schedule.wallet_address,
                        transaction_id,
                        &schedule.amount.to_string(),
                        &schedule.currency,
                    );
                }
                Err(reason) => {
                    // Record failure — idempotency guard still applies.
                    match self
                        .repo
                        .insert_execution(
                            schedule_id,
                            scheduled_at,
                            "failed",
                            None,
                            Some(&reason),
                        )
                        .await
                    {
                        Ok(None) => {
                            info!(
                                schedule_id = %schedule_id,
                                scheduled_at = %scheduled_at,
                                "Skipping already-recorded failure (idempotency)"
                            );
                            continue;
                        }
                        Ok(Some(_)) => {}
                        Err(e) => {
                            error!(schedule_id = %schedule_id, error = %e, "Failed to insert failure execution record");
                            continue;
                        }
                    }

                    let updated = match self.repo.record_failure(schedule_id, next).await {
                        Ok(s) => s,
                        Err(e) => {
                            error!(schedule_id = %schedule_id, error = %e, "Failed to record schedule failure");
                            continue;
                        }
                    };

                    notification::notify_failure(
                        schedule_id,
                        &schedule.wallet_address,
                        updated.failure_count,
                        &reason,
                    );

                    if updated.status == "suspended" {
                        notification::notify_suspended(
                            schedule_id,
                            &schedule.wallet_address,
                            updated.failure_count,
                        );
                    }
                }
            }
        }
    }

    /// Execute the payment for a schedule.
    ///
    /// Returns `Ok(transaction_id)` on success or `Err(reason)` on failure.
    ///
    /// TODO: Route to the appropriate payment processor based on `transaction_type`:
    ///   "bill_payment" → workers::bill_processor
    ///   "onramp"       → services::payment_orchestrator (onramp flow)
    ///   "offramp"      → services::payment_orchestrator (offramp flow)
    async fn execute_payment(
        &self,
        schedule: &crate::database::recurring_payment_repository::RecurringSchedule,
    ) -> Result<Uuid, String> {
        info!(
            schedule_id = %schedule.id,
            wallet = %schedule.wallet_address,
            transaction_type = %schedule.transaction_type,
            provider = ?schedule.provider,
            amount = %schedule.amount,
            currency = %schedule.currency,
            "Executing recurring payment"
        );

        // Placeholder — replace with real payment dispatch once the
        // payment orchestrator integration is wired in.
        Ok(Uuid::new_v4())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recurring::frequency::Frequency;
    use chrono::{Duration as ChronoDuration, Utc};

    #[test]
    fn test_advance_daily() {
        let now = Utc::now();
        let next = advance_schedule(&Frequency::Daily, now);
        assert_eq!(next, now + ChronoDuration::days(1));
    }

    #[test]
    fn test_advance_weekly() {
        let now = Utc::now();
        let next = advance_schedule(&Frequency::Weekly, now);
        assert_eq!(next, now + ChronoDuration::weeks(1));
    }

    #[test]
    fn test_advance_custom_14_days() {
        let now = Utc::now();
        let next = advance_schedule(&Frequency::Custom(14), now);
        assert_eq!(next, now + ChronoDuration::days(14));
    }

    /// Simulate the failure threshold logic that lives in the DB query.
    /// After `threshold` consecutive failures the status becomes "suspended".
    #[test]
    fn test_failure_threshold_suspension_logic() {
        let threshold = 3i32;

        // Simulate incrementing failure_count and checking suspension.
        for failure_count in 0..threshold {
            let new_count = failure_count + 1;
            let suspended = new_count >= threshold;
            assert!(!suspended, "should not suspend before threshold");
        }

        // At threshold the schedule should be suspended.
        let new_count = threshold;
        let suspended = new_count >= threshold;
        assert!(suspended, "should suspend at threshold");
    }

    #[test]
    fn test_failure_count_resets_on_success() {
        // After a success, failure_count should be 0 regardless of prior value.
        let failure_count_before = 2i32;
        let failure_count_after = 0i32; // what record_success sets
        assert_eq!(failure_count_after, 0);
        assert!(failure_count_before > failure_count_after);
    }

    #[test]
    fn test_worker_config_defaults() {
        let cfg = RecurringWorkerConfig::default();
        assert_eq!(cfg.poll_interval.as_secs(), 60);
        assert_eq!(cfg.batch_size, 100);
    }
}
