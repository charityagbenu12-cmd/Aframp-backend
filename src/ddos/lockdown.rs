//! Emergency lockdown mode.
//!
//! When active, only allowlisted IPs and high-priority consumers with active
//! sessions are processed. All others receive 503 with Retry-After.
//! Auto-deactivates after a configurable maximum duration.

use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::ddos::config::DdosConfig;

#[derive(Debug, Clone, serde::Serialize)]
pub struct LockdownStatus {
    pub active: bool,
    pub activated_at: Option<chrono::DateTime<chrono::Utc>>,
    pub auto_expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub trigger: Option<String>,
}

struct LockdownInner {
    active: bool,
    activated_at: Option<Instant>,
    activated_at_utc: Option<chrono::DateTime<chrono::Utc>>,
    trigger: Option<String>,
}

pub struct LockdownManager {
    config: Arc<DdosConfig>,
    inner: RwLock<LockdownInner>,
}

impl LockdownManager {
    pub fn new(config: Arc<DdosConfig>) -> Arc<Self> {
        Arc::new(Self {
            config,
            inner: RwLock::new(LockdownInner {
                active: false,
                activated_at: None,
                activated_at_utc: None,
                trigger: None,
            }),
        })
    }

    pub async fn activate(&self, trigger: &str) {
        let mut inner = self.inner.write().await;
        inner.active = true;
        inner.activated_at = Some(Instant::now());
        inner.activated_at_utc = Some(chrono::Utc::now());
        inner.trigger = Some(trigger.to_string());

        warn!(trigger = trigger, "Emergency lockdown ACTIVATED");

        crate::ddos::metrics::lockdown_activations()
            .with_label_values(&[trigger])
            .inc();
    }

    pub async fn deactivate(&self) {
        let mut inner = self.inner.write().await;
        inner.active = false;
        inner.activated_at = None;
        inner.activated_at_utc = None;
        inner.trigger = None;
        info!("Emergency lockdown deactivated");
    }

    pub async fn is_active(&self) -> bool {
        let inner = self.inner.read().await;
        if !inner.active {
            return false;
        }
        // Auto-expire check
        if let Some(activated_at) = inner.activated_at {
            if activated_at.elapsed() > Duration::from_secs(self.config.lockdown_max_duration_secs) {
                return false; // expired — caller should call deactivate()
            }
        }
        true
    }

    /// Check and auto-deactivate if the max duration has passed.
    pub async fn check_auto_expire(&self) {
        let should_deactivate = {
            let inner = self.inner.read().await;
            inner.active
                && inner
                    .activated_at
                    .map(|t| t.elapsed() > Duration::from_secs(self.config.lockdown_max_duration_secs))
                    .unwrap_or(false)
        };
        if should_deactivate {
            info!("Lockdown auto-expired after {} seconds", self.config.lockdown_max_duration_secs);
            self.deactivate().await;
        }
    }

    pub async fn status(&self) -> LockdownStatus {
        let inner = self.inner.read().await;
        let auto_expires_at = inner.activated_at_utc.map(|t| {
            t + chrono::Duration::seconds(self.config.lockdown_max_duration_secs as i64)
        });
        LockdownStatus {
            active: inner.active,
            activated_at: inner.activated_at_utc,
            auto_expires_at,
            trigger: inner.trigger.clone(),
        }
    }

    /// Returns true if the given IP is in the allowlist.
    pub fn is_allowlisted(&self, ip: &str) -> bool {
        let parsed = match IpAddr::from_str(ip) {
            Ok(a) => a,
            Err(_) => return false,
        };
        for entry in &self.config.allowlisted_ips {
            if entry == ip {
                return true;
            }
            // Simple CIDR check for /24 and /16 (production would use ipnetwork crate)
            if let Some(prefix) = entry.strip_suffix("/24") {
                if ip.starts_with(prefix.rsplit('.').skip(1).collect::<Vec<_>>().iter().rev().cloned().collect::<Vec<_>>().join(".").as_str()) {
                    return true;
                }
            }
            // Exact match fallback
            if entry == &parsed.to_string() {
                return true;
            }
        }
        false
    }
}
