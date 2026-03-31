//! Background worker that drives the adaptive rate limiting engine.
//!
//! Samples platform health signals at the configured interval, evaluates
//! mode transitions, syncs multipliers to Redis, and persists signal
//! snapshots to the database at a (typically longer) configurable interval.

use std::sync::Arc;
use tokio::sync::watch;
use tracing::{info, warn};

use crate::adaptive_rate_limit::{
    engine::AdaptiveRateLimitEngine,
    repository::AdaptiveRateLimitRepository,
};

pub struct AdaptiveRateLimitWorker {
    engine: Arc<AdaptiveRateLimitEngine>,
    repo: Arc<AdaptiveRateLimitRepository>,
}

impl AdaptiveRateLimitWorker {
    pub fn new(
        engine: Arc<AdaptiveRateLimitEngine>,
        repo: AdaptiveRateLimitRepository,
    ) -> Self {
        Self {
            engine,
            repo: Arc::new(repo),
        }
    }

    pub async fn run(self, mut shutdown_rx: watch::Receiver<bool>) {
        let sampling_interval = self.engine.config.signal_sampling_interval;
        let persist_interval = self.engine.config.signal_persist_interval;

        info!(
            sampling_interval_secs = sampling_interval.as_secs(),
            persist_interval_secs = persist_interval.as_secs(),
            "adaptive rate limit worker started"
        );

        let mut sample_ticker = tokio::time::interval(sampling_interval);
        let mut persist_ticker = tokio::time::interval(persist_interval);
        // Skip missed ticks to avoid burst on startup or after a slow cycle
        sample_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        persist_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        info!("adaptive rate limit worker stopping");
                        break;
                    }
                }

                _ = sample_ticker.tick() => {
                    // Collect signals, evaluate transitions, sync Redis
                    self.engine.run_cycle().await;
                    // Advance per-consumer trend windows
                    self.engine.advance_trend_windows().await;

                    // Update worker heartbeat metric
                    #[cfg(feature = "cache")]
                    crate::metrics::alerting::worker_last_cycle_timestamp()
                        .with_label_values(&["adaptive_rate_limit"])
                        .set(chrono::Utc::now().timestamp() as f64);
                }

                _ = persist_ticker.tick() => {
                    if let Some(snapshot) = self.engine.signals.latest().await {
                        if let Err(e) = self.repo.persist_signal_snapshot(&snapshot).await {
                            warn!(error = %e, "failed to persist adaptive rl signal snapshot");
                        }
                    }
                }
            }
        }

        info!("adaptive rate limit worker stopped");
    }
}
