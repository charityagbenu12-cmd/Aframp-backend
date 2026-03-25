//! Background job for cleaning up expired tokens
//!
//! Periodically removes:
//! - Expired refresh tokens
//! - Expired token families
//! - Revoked tokens older than retention period

use chrono::{Duration, Utc};
use std::sync::Arc;
use tokio::time::{interval, Duration as TokioDuration};
use tracing::{error, info};

use crate::database::refresh_token_repository::RefreshTokenRepository;

// ── Cleanup Configuration ────────────────────────────────────────────────────

pub struct TokenCleanupConfig {
    /// Interval between cleanup runs (in seconds)
    pub cleanup_interval_secs: u64,
    /// Retention period for revoked tokens (in days)
    pub revoked_token_retention_days: i64,
}

impl Default for TokenCleanupConfig {
    fn default() -> Self {
        Self {
            cleanup_interval_secs: 3600, // 1 hour
            revoked_token_retention_days: 7,
        }
    }
}

// ── Token Cleanup Job ────────────────────────────────────────────────────────

pub struct TokenCleanupJob {
    repo: Arc<RefreshTokenRepository>,
    config: TokenCleanupConfig,
}

impl TokenCleanupJob {
    pub fn new(repo: Arc<RefreshTokenRepository>, config: TokenCleanupConfig) -> Self {
        Self { repo, config }
    }

    /// Start the cleanup job (runs in background)
    pub fn start(self) {
        tokio::spawn(async move {
            let mut interval = interval(TokioDuration::from_secs(self.config.cleanup_interval_secs));

            loop {
                interval.tick().await;
                if let Err(e) = self.run_cleanup().await {
                    error!("Token cleanup job failed: {}", e);
                }
            }
        });
    }

    /// Run a single cleanup cycle
    pub async fn run_cleanup(&self) -> Result<(), String> {
        let now = Utc::now();

        // Delete expired tokens
        let expired_count = self
            .repo
            .delete_expired(now)
            .await
            .map_err(|e| format!("Failed to delete expired tokens: {}", e))?;

        if expired_count > 0 {
            info!("Deleted {} expired tokens", expired_count);
        }

        // Delete expired families
        let expired_families = self
            .repo
            .delete_expired_families(now)
            .await
            .map_err(|e| format!("Failed to delete expired families: {}", e))?;

        if expired_families > 0 {
            info!("Deleted {} expired token families", expired_families);
        }

        // Get statistics
        let stats = self
            .repo
            .get_stats()
            .await
            .map_err(|e| format!("Failed to get token stats: {}", e))?;

        info!(
            total_tokens = stats.total_tokens,
            active_tokens = stats.active_tokens,
            used_tokens = stats.used_tokens,
            revoked_tokens = stats.revoked_tokens,
            expired_tokens = stats.expired_tokens,
            total_families = stats.total_families,
            "Token cleanup cycle completed"
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cleanup_config_default() {
        let config = TokenCleanupConfig::default();
        assert_eq!(config.cleanup_interval_secs, 3600);
        assert_eq!(config.revoked_token_retention_days, 7);
    }

    #[test]
    fn test_cleanup_config_custom() {
        let config = TokenCleanupConfig {
            cleanup_interval_secs: 1800,
            revoked_token_retention_days: 14,
        };
        assert_eq!(config.cleanup_interval_secs, 1800);
        assert_eq!(config.revoked_token_retention_days, 14);
    }
}
