//! SLA polling background worker.
//!
//! Spawns a `tokio` task that periodically calls
//! [`BugBountyService::check_sla_breaches`] and fires Prometheus alerts /
//! structured log events on every breach.
//!
//! Requirements: 6.3, 6.4, 6.5, 11.3, 11.4

use std::sync::Arc;

use crate::bug_bounty::{models::BugBountyConfig, service::BugBountyService};

/// Maximum allowed poll interval (5 minutes = 300 seconds).
///
/// Requirement 6.5: "THE Bug_Bounty_System SHALL evaluate SLA deadlines at a
/// configurable polling interval of no greater than 5 minutes."
const MAX_POLL_INTERVAL_SECS: u64 = 300;

/// Background worker that polls for SLA breaches at a configurable interval.
///
/// The worker is intentionally stateless — all state lives in
/// [`BugBountyService`]. `SlaPollingWorker` is a zero-sized type whose only
/// purpose is to expose the [`spawn`](SlaPollingWorker::spawn) associated
/// function.
pub struct SlaPollingWorker;

impl SlaPollingWorker {
    /// Spawn the SLA polling loop as a detached `tokio` task.
    ///
    /// The task runs forever (until the runtime shuts down or the returned
    /// [`JoinHandle`](tokio::task::JoinHandle) is dropped/aborted).
    ///
    /// # Behaviour
    ///
    /// 1. Sleep for `config.sla_poll_interval_secs` (capped at 300 s).
    /// 2. Call [`BugBountyService::check_sla_breaches`].
    ///    - On success: the service emits structured log events and updates
    ///      Prometheus gauges for every breached report.
    ///    - On error: emit `tracing::error!` and continue — the worker must
    ///      never crash due to a transient database or service error.
    pub fn spawn(
        service: Arc<BugBountyService>,
        config: &BugBountyConfig,
    ) -> tokio::task::JoinHandle<()> {
        let interval_secs = config.sla_poll_interval_secs.min(MAX_POLL_INTERVAL_SECS);
        let interval = tokio::time::Duration::from_secs(interval_secs);

        tracing::info!(
            poll_interval_secs = interval_secs,
            "SLA polling worker starting"
        );

        tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;

                if let Err(e) = service.check_sla_breaches().await {
                    tracing::error!(
                        error = %e,
                        "SLA breach check failed; will retry on next interval"
                    );
                }
            }
        })
    }
}
