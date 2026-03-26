//! Shared DDoS protection state wired into the Axum application.

use std::sync::Arc;
use tokio::sync::RwLock;

use crate::cache::RedisCache;
use crate::ddos::{
    cdn::CdnClient,
    challenge::ChallengeService,
    config::DdosConfig,
    detector::AttackDetector,
    lockdown::LockdownManager,
    queue::FairQueue,
};

/// Blocked IP entry stored in Redis and synced to CDN.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BlockedEntry {
    pub target: String, // IP, CIDR, or ASN
    pub reason: String,
    pub blocked_at: chrono::DateTime<chrono::Utc>,
    pub blocked_by: String,
}

#[derive(Clone)]
pub struct DdosState {
    pub config: Arc<DdosConfig>,
    pub detector: Arc<AttackDetector>,
    pub queue: Arc<FairQueue>,
    pub lockdown: Arc<LockdownManager>,
    pub cdn: Arc<CdnClient>,
    pub challenge: Arc<ChallengeService>,
    pub cache: Arc<RedisCache>,
    // In-memory blocked IPs (also persisted to Redis)
    pub blocked_ips: Arc<RwLock<Vec<BlockedEntry>>>,
}

impl DdosState {
    pub fn new(config: DdosConfig, cache: RedisCache) -> Self {
        let config = Arc::new(config);
        let cache = Arc::new(cache);

        Self {
            detector: AttackDetector::new(config.clone()),
            queue: FairQueue::new(config.clone()),
            lockdown: LockdownManager::new(config.clone()),
            cdn: Arc::new(CdnClient::new(config.clone())),
            challenge: Arc::new(ChallengeService::new(config.clone(), cache.clone())),
            blocked_ips: Arc::new(RwLock::new(Vec::new())),
            config,
            cache,
        }
    }

    /// Block an IP/CIDR/ASN at the application layer and push to CDN.
    pub async fn block_target(&self, target: &str, reason: &str, blocked_by: &str) {
        let entry = BlockedEntry {
            target: target.to_string(),
            reason: reason.to_string(),
            blocked_at: chrono::Utc::now(),
            blocked_by: blocked_by.to_string(),
        };

        // Persist to Redis
        let key = format!("ddos:blocked:{}", target);
        let ttl = std::time::Duration::from_secs(86400); // 24h default
        let _ = <RedisCache as crate::cache::Cache<BlockedEntry>>::set(
            &self.cache,
            &key,
            &entry,
            Some(ttl),
        )
        .await;

        self.blocked_ips.write().await.push(entry);

        // Sync to CDN
        self.cdn.sync_blocked_ips(&[target.to_string()]).await;

        tracing::warn!(target = target, reason = reason, "IP/CIDR blocked");
    }

    pub async fn is_blocked(&self, ip: &str) -> bool {
        let blocked = self.blocked_ips.read().await;
        blocked.iter().any(|e| e.target == ip || ip.starts_with(&e.target))
    }

    /// Load blocked IPs from Redis on startup.
    pub async fn load_blocked_from_redis(&self) {
        // In production, scan ddos:blocked:* keys and populate in-memory list
        // Omitted here to avoid a full SCAN in startup path
    }

    /// Periodic CDN sync task — call from a background worker.
    pub async fn sync_cdn_blocklist(&self) {
        let blocked = self.blocked_ips.read().await;
        let ips: Vec<String> = blocked.iter().map(|e| e.target.clone()).collect();
        drop(blocked);
        self.cdn.sync_blocked_ips(&ips).await;
    }
}
