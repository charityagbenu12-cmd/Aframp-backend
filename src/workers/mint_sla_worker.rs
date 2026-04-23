/// Mint SLA Timer & Escalation Worker
///
/// Runs every 30 minutes via a Tokio interval timer.
/// For every PENDING / PARTIALLY_APPROVED mint request it:
///
///   elapsed < 4h   → no action
///   4h ≤ elapsed < 12h  → fire SLA warning (once, idempotent)
///   12h ≤ elapsed < 24h → fire escalation to Tier-2 manager (once, idempotent)
///   elapsed ≥ 24h       → auto-expire request (once, idempotent)
///
/// State machine for `mint_sla_state.stage`:
///
///   pending → warned → escalated → expired
///          ↘ resolved (any time the request leaves PENDING)
///
/// Idempotency: each worker run is assigned a UUID. A threshold is only
/// fired if the SLA state row has not already recorded it. The worker is
/// safe to run concurrently — DB updates use `WHERE stage = <expected>`
/// optimistic locking.
use crate::services::mint_sla::{MintSlaService, SlaAction};
use sqlx::PgPool;
use std::sync::Arc;
use tokio::sync::watch;
use tokio::time::{interval, Duration};
use tracing::{error, info, warn};
use uuid::Uuid;

/// How often the worker wakes up.
pub const WORKER_INTERVAL: Duration = Duration::from_secs(30 * 60); // 30 minutes

pub struct MintSlaWorker {
    sla_service: Arc<MintSlaService>,
}

impl MintSlaWorker {
    pub fn new(db: PgPool, http: reqwest::Client) -> Self {
        Self {
            sla_service: Arc::new(MintSlaService::new(db, http)),
        }
    }

    /// Main loop — runs until the shutdown signal fires.
    pub async fn run(&self, mut shutdown_rx: watch::Receiver<bool>) {
        info!("MintSlaWorker started (interval = 30 min)");
        let mut ticker = interval(WORKER_INTERVAL);
        // First tick fires immediately so we don't wait 30 min on startup.
        ticker.tick().await;

        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    info!("MintSlaWorker shutting down");
                    break;
                }
                _ = ticker.tick() => {
                    let run_id = Uuid::new_v4();
                    info!(run_id = %run_id, "MintSlaWorker cycle starting");
                    match self.sla_service.run_cycle(run_id).await {
                        Ok(summary) => info!(
                            run_id = %run_id,
                            warned = summary.warned,
                            escalated = summary.escalated,
                            expired = summary.expired,
                            resolved = summary.resolved,
                            "MintSlaWorker cycle complete"
                        ),
                        Err(e) => error!(
                            run_id = %run_id,
                            error = %e,
                            "MintSlaWorker cycle failed"
                        ),
                    }
                }
            }
        }
    }
}
