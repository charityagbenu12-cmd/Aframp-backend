/// Async audit log writer with configurable channel buffer and synchronous fallback.
///
/// Normal path: middleware sends a `PendingAuditEntry` to the channel; the
/// background task drains it, computes the hash chain, persists to DB, and
/// publishes to Redis pub/sub.
///
/// Overflow path: if the channel is full, the middleware falls back to a
/// synchronous (blocking-in-async) write so no audit event is ever dropped.
use crate::audit::{
    models::{AuditLogEntry, AuditOutcome, PendingAuditEntry},
    redaction::{compute_entry_hash, entry_content},
    repository::AuditLogRepository,
    streaming::AuditStreamer,
};
use chrono::Utc;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{error, warn};
use uuid::Uuid;

const DEFAULT_BUFFER: usize = 4_096;
const CHANNEL_WARN_THRESHOLD: f64 = 0.80; // 80 % full → alert

#[derive(Clone)]
pub struct AuditWriter {
    tx: mpsc::Sender<PendingAuditEntry>,
    /// Kept for synchronous fallback and metrics.
    repo: Arc<AuditLogRepository>,
    streamer: Arc<AuditStreamer>,
    buffer_size: usize,
}

impl AuditWriter {
    pub fn new(
        repo: Arc<AuditLogRepository>,
        streamer: Arc<AuditStreamer>,
        buffer_size: Option<usize>,
    ) -> (Self, mpsc::Receiver<PendingAuditEntry>) {
        let cap = buffer_size.unwrap_or(DEFAULT_BUFFER);
        let (tx, rx) = mpsc::channel(cap);
        (
            Self {
                tx,
                repo,
                streamer,
                buffer_size: cap,
            },
            rx,
        )
    }

    /// Send an entry to the async writer channel.
    /// Falls back to synchronous write if the channel is full.
    pub async fn write(&self, entry: PendingAuditEntry) {
        // Update channel utilisation metric
        let utilisation = 1.0 - (self.tx.capacity() as f64 / self.buffer_size as f64);
        crate::audit::metrics::writer_channel_utilisation().set(utilisation);

        if utilisation >= CHANNEL_WARN_THRESHOLD {
            warn!(
                utilisation = utilisation,
                "Audit writer channel utilisation above threshold"
            );
        }

        match self.tx.try_send(entry) {
            Ok(_) => {}
            Err(mpsc::error::TrySendError::Full(entry)) => {
                error!("Audit writer channel full — falling back to synchronous write");
                crate::audit::metrics::overflow_fallbacks_total()
                    .with_label_values(&["channel_full"])
                    .inc();
                self.write_sync(entry).await;
            }
            Err(mpsc::error::TrySendError::Closed(entry)) => {
                error!("Audit writer channel closed — falling back to synchronous write");
                crate::audit::metrics::overflow_fallbacks_total()
                    .with_label_values(&["channel_closed"])
                    .inc();
                self.write_sync(entry).await;
            }
        }
    }

    /// Synchronous (direct) write path — used as fallback.
    async fn write_sync(&self, entry: PendingAuditEntry) {
        match persist_entry(&self.repo, &self.streamer, entry).await {
            Ok(_) => {}
            Err(e) => error!(error = %e, "Synchronous audit write failed"),
        }
    }
}

/// Background task that drains the channel and persists entries.
pub async fn run_writer_task(
    repo: Arc<AuditLogRepository>,
    streamer: Arc<AuditStreamer>,
    mut rx: mpsc::Receiver<PendingAuditEntry>,
) {
    while let Some(entry) = rx.recv().await {
        if let Err(e) = persist_entry(&repo, &streamer, entry).await {
            error!(error = %e, "Audit writer task failed to persist entry");
        }
    }
}

/// Core persistence logic: compute hash chain → insert → publish.
async fn persist_entry(
    repo: &AuditLogRepository,
    streamer: &AuditStreamer,
    pending: PendingAuditEntry,
) -> Result<(), String> {
    let start = std::time::Instant::now();

    let id = Uuid::new_v4();
    let created_at = Utc::now();

    // Fetch previous hash (for hash chain)
    let prev_hash = repo
        .last_entry_hash()
        .await
        .map_err(|e| e.to_string())?
        .unwrap_or_else(|| "0".repeat(64));

    let content = entry_content(&pending, id, &created_at);
    let current_hash = compute_entry_hash(&prev_hash, &content);

    let hash_duration = start.elapsed().as_secs_f64();
    crate::audit::metrics::hash_chain_duration_seconds()
        .with_label_values(&["compute"])
        .observe(hash_duration);

    let entry = AuditLogEntry {
        id,
        event_type: pending.event_type.clone(),
        event_category: pending.event_category,
        actor_type: pending.actor_type,
        actor_id: pending.actor_id.clone(),
        actor_ip: pending.actor_ip.clone(),
        actor_consumer_type: pending.actor_consumer_type.clone(),
        session_id: pending.session_id.clone(),
        target_resource_type: pending.target_resource_type.clone(),
        target_resource_id: pending.target_resource_id.clone(),
        request_method: pending.request_method.clone(),
        request_path: pending.request_path.clone(),
        request_body_hash: pending.request_body_hash.clone(),
        response_status: pending.response_status,
        response_latency_ms: pending.response_latency_ms,
        outcome: pending.outcome,
        failure_reason: pending.failure_reason.clone(),
        environment: pending.environment.clone(),
        previous_entry_hash: Some(prev_hash),
        current_entry_hash: current_hash,
        created_at,
    };

    repo.insert(&entry).await.map_err(|e| e.to_string())?;

    crate::audit::metrics::entries_total()
        .with_label_values(&[entry.event_category.as_str()])
        .inc();

    // Publish to Redis pub/sub (non-blocking — failure is logged, not fatal)
    streamer.publish(&entry).await;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::models::{AuditActorType, AuditEventCategory};

    fn make_pending() -> PendingAuditEntry {
        PendingAuditEntry {
            event_type: "test.event".to_string(),
            event_category: AuditEventCategory::DataAccess,
            actor_type: AuditActorType::Consumer,
            actor_id: Some("user-123".to_string()),
            actor_ip: Some("127.0.0.1".to_string()),
            actor_consumer_type: Some("mobile_client".to_string()),
            session_id: Some("sess-abc".to_string()),
            target_resource_type: Some("wallet".to_string()),
            target_resource_id: Some("wallet-456".to_string()),
            request_method: "GET".to_string(),
            request_path: "/api/wallet/balance".to_string(),
            request_body_hash: None,
            response_status: 200,
            response_latency_ms: 42,
            outcome: AuditOutcome::Success,
            failure_reason: None,
            environment: "testnet".to_string(),
        }
    }

    #[test]
    fn test_hash_chain_deterministic() {
        use crate::audit::redaction::{compute_entry_hash, entry_content};
        let pending = make_pending();
        let id = Uuid::new_v4();
        let ts = Utc::now();
        let content = entry_content(&pending, id, &ts);
        let h1 = compute_entry_hash("0".repeat(64).as_str(), &content);
        let h2 = compute_entry_hash("0".repeat(64).as_str(), &content);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
    }

    #[test]
    fn test_hash_chain_links() {
        use crate::audit::redaction::{compute_entry_hash, entry_content};
        let p1 = make_pending();
        let p2 = make_pending();
        let id1 = Uuid::new_v4();
        let id2 = Uuid::new_v4();
        let ts = Utc::now();
        let genesis = "0".repeat(64);
        let h1 = compute_entry_hash(&genesis, &entry_content(&p1, id1, &ts));
        let h2 = compute_entry_hash(&h1, &entry_content(&p2, id2, &ts));
        assert_ne!(h1, h2);
        // Tampering with h1 breaks h2
        let h1_tampered = "f".repeat(64);
        let h2_bad = compute_entry_hash(&h1_tampered, &entry_content(&p2, id2, &ts));
        assert_ne!(h2, h2_bad);
    }
}
