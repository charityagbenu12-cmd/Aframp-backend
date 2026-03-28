//! IP Detection Background Worker
//!
//! Handles periodic tasks for IP reputation management:
//! - Cleanup of expired temporary blocks
//! - Monitoring of automated blocking rates
//! - Cache management and health checks

use crate::database::ip_reputation_repository::IpReputationRepository;
use crate::database::Repository;
use crate::metrics;
use crate::services::ip_detection::{IpDetectionConfig, IpDetectionService};
use crate::cache::RedisCache;
use std::sync::Arc;
use std::time::Duration;
use tokio::time;
use tracing::{error, info, warn};

/// Configuration for the IP detection worker
#[derive(Debug, Clone)]
pub struct IpDetectionWorkerConfig {
    pub cleanup_interval_secs: u64,
    pub blocking_rate_check_interval_secs: u64,
    pub blocking_rate_threshold_per_minute: f64,
}

impl Default for IpDetectionWorkerConfig {
    fn default() -> Self {
        Self {
            cleanup_interval_secs: 300, // 5 minutes
            blocking_rate_check_interval_secs: 60, // 1 minute
            blocking_rate_threshold_per_minute: 10.0, // Alert if > 10 blocks per minute
        }
    }
}

impl IpDetectionWorkerConfig {
    pub fn from_env() -> Self {
        Self {
            cleanup_interval_secs: std::env::var("IP_DETECTION_CLEANUP_INTERVAL_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(300),
            blocking_rate_check_interval_secs: std::env::var("IP_DETECTION_RATE_CHECK_INTERVAL_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(60),
            blocking_rate_threshold_per_minute: std::env::var("IP_DETECTION_BLOCKING_RATE_THRESHOLD")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(10.0),
        }
    }
}

/// IP Detection background worker
pub struct IpDetectionWorker {
    repo: IpReputationRepository,
    detection_service: Arc<IpDetectionService>,
    config: IpDetectionWorkerConfig,
}

impl IpDetectionWorker {
    pub fn new(
        repo: IpReputationRepository,
        detection_service: Arc<IpDetectionService>,
        config: IpDetectionWorkerConfig,
    ) -> Self {
        Self {
            repo,
            detection_service,
            config,
        }
    }

    /// Run the worker with shutdown signal handling
    pub async fn run(mut self, mut shutdown: tokio::sync::watch::Receiver<bool>) {
        info!(
            cleanup_interval_secs = self.config.cleanup_interval_secs,
            rate_check_interval_secs = self.config.blocking_rate_check_interval_secs,
            "Starting IP detection worker"
        );

        let mut cleanup_interval = time::interval(Duration::from_secs(self.config.cleanup_interval_secs));
        let mut rate_check_interval = time::interval(Duration::from_secs(self.config.blocking_rate_check_interval_secs));

        // Track blocking rate over the last 5 minutes
        let mut recent_blocks: Vec<chrono::DateTime<chrono::Utc>> = Vec::new();

        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    info!("IP detection worker received shutdown signal");
                    break;
                }
                _ = cleanup_interval.tick() => {
                    if let Err(e) = self.run_cleanup_cycle().await {
                        error!(error = %e, "Failed to run IP detection cleanup cycle");
                    }
                }
                _ = rate_check_interval.tick() => {
                    if let Err(e) = self.check_blocking_rate(&mut recent_blocks).await {
                        error!(error = %e, "Failed to check blocking rate");
                    }
                }
            }
        }

        info!("IP detection worker stopped");
    }

    /// Run cleanup cycle - remove expired blocks and update cache
    async fn run_cleanup_cycle(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("Running IP detection cleanup cycle");

        // Clean up expired blocks in database
        let cleaned_count = self.detection_service.cleanup_expired_blocks().await?;

        if cleaned_count > 0 {
            info!(cleaned_count, "Cleaned up expired IP blocks");

            // Bootstrap cache with updated blocked IPs
            self.detection_service.bootstrap_blocked_ips_cache().await?;
        }

        Ok(())
    }

    /// Check automated blocking rate and alert if threshold exceeded
    async fn check_blocking_rate(
        &self,
        recent_blocks: &mut Vec<chrono::DateTime<chrono::Utc>>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let now = chrono::Utc::now();

        // Remove blocks older than 5 minutes
        recent_blocks.retain(|block_time| {
            now.signed_duration_since(*block_time) < chrono::Duration::minutes(5)
        });

        // Calculate current rate (blocks per minute over last 5 minutes)
        let rate_per_minute = if recent_blocks.len() >= 2 {
            let time_span_minutes = recent_blocks.len() as f64 * 5.0 / recent_blocks.len() as f64;
            recent_blocks.len() as f64 / time_span_minutes
        } else {
            0.0
        };

        // Update Prometheus metric
        metrics::ip_detection::ip_automated_blocking_rate()
            .with_label_values(&[])
            .set(rate_per_minute);

        // Check against threshold
        if rate_per_minute > self.config.blocking_rate_threshold_per_minute {
            warn!(
                rate_per_minute,
                threshold = self.config.blocking_rate_threshold_per_minute,
                recent_blocks = recent_blocks.len(),
                "Automated IP blocking rate exceeds threshold - possible large scale attack"
            );

            // TODO: Send alert notification (integrate with notification service)
        }

        Ok(())
    }

    /// Record a new automated block for rate monitoring
    pub fn record_automated_block(&self, recent_blocks: &mut Vec<chrono::DateTime<chrono::Utc>>) {
        recent_blocks.push(chrono::Utc::now());

        // Keep only last 100 blocks to prevent unbounded growth
        if recent_blocks.len() > 100 {
            recent_blocks.remove(0);
        }
    }
}