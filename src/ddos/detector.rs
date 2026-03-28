//! Attack detection: volumetric spikes, endpoint floods, slow HTTP, fingerprinting.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::ddos::config::DdosConfig;
use crate::ddos::fingerprint::RequestFingerprint;

/// Classification of a detected attack.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttackClass {
    VolumetricSpike,
    EndpointFlood { endpoint: String },
    SlowHttp,
    MalformedFlood,
    SuspiciousUserAgent,
    FingerprintCluster { cluster_id: String },
}

/// A recorded attack event.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AttackEvent {
    pub id: String,
    pub class: AttackClass,
    pub detected_at: chrono::DateTime<chrono::Utc>,
    pub peak_rps: f64,
    pub mitigation: String,
    pub resolved_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Current protection mode.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtectionMode {
    Passive,
    ActiveRateEnforcement,
    SelectiveBlocking,
    EmergencyLockdown,
}

/// Shared detector state — updated by the middleware on every request.
pub struct AttackDetector {
    config: Arc<DdosConfig>,
    // Rolling window: (timestamp, count) per second bucket
    global_rps_window: RwLock<Vec<(Instant, u64)>>,
    endpoint_counts: RwLock<HashMap<String, Vec<Instant>>>,
    active_attacks: RwLock<Vec<AttackEvent>>,
    attack_history: RwLock<Vec<AttackEvent>>,
    pub mode: RwLock<ProtectionMode>,
    // Slow HTTP: track (ip, first_byte_time, bytes_received)
    slow_connections: RwLock<HashMap<String, SlowConnState>>,
    // Fingerprint clusters: cluster_id -> count in last window
    fingerprint_clusters: RwLock<HashMap<String, Vec<Instant>>>,
}

#[derive(Debug, Clone)]
pub struct SlowConnState {
    pub started_at: Instant,
    pub bytes_received: u64,
    pub flagged: bool,
}

impl AttackDetector {
    pub fn new(config: Arc<DdosConfig>) -> Arc<Self> {
        Arc::new(Self {
            config,
            global_rps_window: RwLock::new(Vec::new()),
            endpoint_counts: RwLock::new(HashMap::new()),
            active_attacks: RwLock::new(Vec::new()),
            attack_history: RwLock::new(Vec::new()),
            mode: RwLock::new(ProtectionMode::Passive),
            slow_connections: RwLock::new(HashMap::new()),
            fingerprint_clusters: RwLock::new(HashMap::new()),
        })
    }

    /// Record an incoming request and check for attack patterns.
    pub async fn record_request(
        &self,
        endpoint: &str,
        ip: &str,
        fingerprint: &RequestFingerprint,
    ) {
        let now = Instant::now();

        // Update global RPS window (1-second buckets, keep last 60s)
        {
            let mut window = self.global_rps_window.write().await;
            window.push((now, 1));
            window.retain(|(t, _)| now.duration_since(*t) < Duration::from_secs(60));
        }

        // Update per-endpoint counts
        {
            let mut ep = self.endpoint_counts.write().await;
            let counts = ep.entry(endpoint.to_string()).or_default();
            counts.push(now);
            counts.retain(|t| now.duration_since(*t) < Duration::from_secs(10));
        }

        // Update fingerprint clusters
        {
            let mut clusters = self.fingerprint_clusters.write().await;
            let bucket = clusters.entry(fingerprint.cluster_key.clone()).or_default();
            bucket.push(now);
            bucket.retain(|t| now.duration_since(*t) < Duration::from_secs(10));
        }

        // Run detection checks
        self.check_volumetric_spike().await;
        self.check_endpoint_flood(endpoint).await;
        self.check_fingerprint_cluster(&fingerprint.cluster_key).await;
    }

    /// Returns current global RPS over the last second.
    pub async fn current_rps(&self) -> f64 {
        let window = self.global_rps_window.read().await;
        let now = Instant::now();
        let count = window
            .iter()
            .filter(|(t, _)| now.duration_since(*t) < Duration::from_secs(1))
            .count();
        count as f64
    }

    async fn check_volumetric_spike(&self) {
        let rps = self.current_rps().await;
        let threshold = self.config.baseline_rps * self.config.spike_multiplier;
        if rps > threshold {
            let event = AttackEvent {
                id: uuid::Uuid::new_v4().to_string(),
                class: AttackClass::VolumetricSpike,
                detected_at: chrono::Utc::now(),
                peak_rps: rps,
                mitigation: "active_rate_enforcement".to_string(),
                resolved_at: None,
            };
            warn!(
                rps = rps,
                threshold = threshold,
                "Volumetric spike detected"
            );
            self.record_attack(event).await;
            *self.mode.write().await = ProtectionMode::ActiveRateEnforcement;
        }
    }

    async fn check_endpoint_flood(&self, endpoint: &str) {
        let ep = self.endpoint_counts.read().await;
        let global = self.global_rps_window.read().await;
        let now = Instant::now();

        let ep_count = ep
            .get(endpoint)
            .map(|v| v.iter().filter(|t| now.duration_since(**t) < Duration::from_secs(10)).count())
            .unwrap_or(0) as f64;

        let global_count = global
            .iter()
            .filter(|(t, _)| now.duration_since(*t) < Duration::from_secs(10))
            .count() as f64;

        if global_count > 0.0 && ep_count / global_count > self.config.endpoint_flood_share {
            let event = AttackEvent {
                id: uuid::Uuid::new_v4().to_string(),
                class: AttackClass::EndpointFlood { endpoint: endpoint.to_string() },
                detected_at: chrono::Utc::now(),
                peak_rps: ep_count / 10.0,
                mitigation: "selective_blocking".to_string(),
                resolved_at: None,
            };
            warn!(endpoint = endpoint, share = ep_count / global_count, "Endpoint flood detected");
            self.record_attack(event).await;
        }
    }

    async fn check_fingerprint_cluster(&self, cluster_key: &str) {
        let clusters = self.fingerprint_clusters.read().await;
        let now = Instant::now();
        let count = clusters
            .get(cluster_key)
            .map(|v| v.iter().filter(|t| now.duration_since(**t) < Duration::from_secs(10)).count())
            .unwrap_or(0);

        // If a single fingerprint cluster accounts for >100 req/10s, flag it
        if count > 100 {
            let event = AttackEvent {
                id: uuid::Uuid::new_v4().to_string(),
                class: AttackClass::FingerprintCluster { cluster_id: cluster_key.to_string() },
                detected_at: chrono::Utc::now(),
                peak_rps: count as f64 / 10.0,
                mitigation: "selective_blocking".to_string(),
                resolved_at: None,
            };
            warn!(cluster = cluster_key, count = count, "Fingerprint cluster attack detected");
            self.record_attack(event).await;
        }
    }

    /// Track a connection for slow HTTP detection.
    pub async fn track_connection(&self, conn_id: &str) {
        let mut slow = self.slow_connections.write().await;
        slow.insert(conn_id.to_string(), SlowConnState {
            started_at: Instant::now(),
            bytes_received: 0,
            flagged: false,
        });
    }

    /// Update bytes received for a connection; returns true if it should be terminated.
    pub async fn update_connection_bytes(&self, conn_id: &str, bytes: u64) -> bool {
        let mut slow = self.slow_connections.write().await;
        if let Some(state) = slow.get_mut(conn_id) {
            state.bytes_received += bytes;
            let elapsed = state.started_at.elapsed().as_secs();
            if elapsed > 0 {
                let rate = state.bytes_received / elapsed;
                if rate < self.config.slow_bytes_threshold
                    && state.started_at.elapsed() > self.config.slow_request_timeout()
                {
                    state.flagged = true;
                    warn!(conn_id = conn_id, rate = rate, "Slow HTTP connection flagged");
                    return true;
                }
            }
        }
        false
    }

    pub async fn remove_connection(&self, conn_id: &str) {
        self.slow_connections.write().await.remove(conn_id);
    }

    async fn record_attack(&self, event: AttackEvent) {
        let mut active = self.active_attacks.write().await;
        // Deduplicate by class within last 60s
        let already_active = active.iter().any(|e| {
            std::mem::discriminant(&e.class) == std::mem::discriminant(&event.class)
                && e.resolved_at.is_none()
        });
        if !already_active {
            info!(
                attack_id = %event.id,
                class = ?event.class,
                peak_rps = event.peak_rps,
                "Attack event recorded"
            );
            crate::ddos::metrics::dropped_requests()
                .with_label_values(&["attack_detected"])
                .inc();
            active.push(event.clone());
            self.attack_history.write().await.push(event);
        }
    }

    pub async fn active_attacks(&self) -> Vec<AttackEvent> {
        self.active_attacks.read().await.clone()
    }

    pub async fn attack_history(&self, page: usize, per_page: usize) -> Vec<AttackEvent> {
        let history = self.attack_history.read().await;
        let start = page * per_page;
        history
            .iter()
            .rev()
            .skip(start)
            .take(per_page)
            .cloned()
            .collect()
    }

    pub async fn resolve_attack(&self, attack_id: &str) {
        let mut active = self.active_attacks.write().await;
        if let Some(event) = active.iter_mut().find(|e| e.id == attack_id) {
            event.resolved_at = Some(chrono::Utc::now());
        }
        active.retain(|e| e.resolved_at.is_none());

        // If no active attacks, downgrade mode
        if active.is_empty() {
            *self.mode.write().await = ProtectionMode::Passive;
        }
    }

    pub async fn current_mode(&self) -> ProtectionMode {
        self.mode.read().await.clone()
    }

    /// Per-endpoint RPS over the last 10 seconds.
    pub async fn endpoint_rps(&self) -> HashMap<String, f64> {
        let ep = self.endpoint_counts.read().await;
        let now = Instant::now();
        ep.iter()
            .map(|(k, v)| {
                let count = v.iter().filter(|t| now.duration_since(**t) < Duration::from_secs(10)).count();
                (k.clone(), count as f64 / 10.0)
            })
            .collect()
    }
}
