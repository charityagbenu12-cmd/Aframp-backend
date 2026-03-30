use crate::services::reconciliation::{ReconciliationService, ReconciliationType};
use std::time::Duration;
use tokio::sync::watch;
use tokio::time::interval;
use tracing::{error, info, instrument};

pub struct ReconciliationWorker {
    service: ReconciliationService,
    soft_interval: Duration,
    deep_interval: Duration,
}

impl ReconciliationWorker {
    pub fn new(service: ReconciliationService) -> Self {
        Self {
            service,
            soft_interval: Duration::from_secs(15 * 60), // 15 mins
            deep_interval: Duration::from_secs(6 * 60 * 60), // 6 hours
        }
    }

    pub async fn run(self, mut shutdown_rx: watch::Receiver<bool>) {
        info!("Triple-Way Reconciliation Worker starting...");

        let mut soft_ticker = interval(self.soft_interval);
        let mut deep_ticker = interval(self.deep_interval);

        loop {
            tokio::select! {
                _ = soft_ticker.tick() => {
                    if let Err(e) = self.service.run_reconciliation(ReconciliationType::Soft).await {
                        error!(error = %e, "Soft reconciliation cycle failed");
                    }
                }
                _ = deep_ticker.tick() => {
                    if let Err(e) = self.service.run_reconciliation(ReconciliationType::Deep).await {
                        error!(error = %e, "Deep reconciliation cycle failed");
                    }
                }
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        info!("Reconciliation Worker shutting down");
                        break;
                    }
                }
            }
        }
    }
}
