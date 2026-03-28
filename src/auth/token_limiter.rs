//! Rate limiting for token issuance
//!
//! Enforces:
//! - Max active tokens per consumer
//! - Max issuance rate per client (per time window)
//! - Uses Redis for distributed rate limiting

use crate::cache::{Cache, RedisCache};
use std::time::Duration;
use tracing::warn;

// ── Rate limit configuration ─────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Maximum active tokens per consumer
    pub max_active_tokens_per_consumer: u32,
    /// Maximum token issuance requests per client per window
    pub max_issuance_per_client_per_window: u32,
    /// Time window for rate limiting (in seconds)
    pub rate_limit_window_secs: u64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_active_tokens_per_consumer: 10,
            max_issuance_per_client_per_window: 100,
            rate_limit_window_secs: 60,
        }
    }
}

// ── Rate limiter ─────────────────────────────────────────────────────────────

pub struct TokenRateLimiter {
    cache: RedisCache,
    config: RateLimitConfig,
}

impl TokenRateLimiter {
    pub fn new(cache: RedisCache, config: RateLimitConfig) -> Self {
        Self { cache, config }
    }

    /// Check if consumer can issue a new token
    pub async fn check_consumer_limit(&self, consumer_id: &str) -> Result<bool, RateLimitError> {
        let key = format!("token_count:{}", consumer_id);
        let count = self.get_counter(&key).await?;

        if count >= self.config.max_active_tokens_per_consumer as i64 {
            warn!(
                consumer_id = %consumer_id,
                count = count,
                max = self.config.max_active_tokens_per_consumer,
                "consumer token limit exceeded"
            );
            return Ok(false);
        }

        Ok(true)
    }

    /// Check if client can issue a token (rate limit)
    pub async fn check_client_rate_limit(&self, client_id: &str) -> Result<bool, RateLimitError> {
        let key = format!("token_issuance_rate:{}", client_id);
        let count = self.get_counter(&key).await?;

        if count >= self.config.max_issuance_per_client_per_window as i64 {
            warn!(
                client_id = %client_id,
                count = count,
                max = self.config.max_issuance_per_client_per_window,
                "client rate limit exceeded"
            );
            return Ok(false);
        }

        Ok(true)
    }

    /// Increment consumer token count
    pub async fn increment_consumer_count(&self, consumer_id: &str) -> Result<(), RateLimitError> {
        let key = format!("token_count:{}", consumer_id);
        let _ = <RedisCache as Cache<i64>>::increment(&self.cache, &key, 1).await;

        // Set expiry if not already set
        let _ = <RedisCache as Cache<i64>>::expire(
            &self.cache,
            &key,
            Duration::from_secs(86400), // 24 hours
        )
        .await;

        Ok(())
    }

    /// Decrement consumer token count (on revocation)
    pub async fn decrement_consumer_count(&self, consumer_id: &str) -> Result<(), RateLimitError> {
        let key = format!("token_count:{}", consumer_id);
        let _ = <RedisCache as Cache<i64>>::decrement(&self.cache, &key, 1).await;
        Ok(())
    }

    /// Increment client issuance rate counter
    pub async fn increment_client_rate(&self, client_id: &str) -> Result<(), RateLimitError> {
        let key = format!("token_issuance_rate:{}", client_id);
        let _ = <RedisCache as Cache<i64>>::increment(&self.cache, &key, 1).await;

        // Set expiry to the rate limit window
        let _ = <RedisCache as Cache<i64>>::expire(
            &self.cache,
            &key,
            Duration::from_secs(self.config.rate_limit_window_secs),
        )
        .await;

        Ok(())
    }

    /// Get current counter value
    async fn get_counter(&self, key: &str) -> Result<i64, RateLimitError> {
        match <RedisCache as Cache<i64>>::get(&self.cache, key).await {
            Ok(Some(count)) => Ok(count),
            Ok(None) => Ok(0),
            Err(e) => {
                warn!("failed to get counter from cache: {}", e);
                // Graceful degradation: assume limit not exceeded
                Ok(0)
            }
        }
    }
}

// ── Error types ──────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum RateLimitError {
    #[error("rate limit exceeded")]
    RateLimitExceeded,
    #[error("cache error: {0}")]
    CacheError(String),
    #[error("internal error: {0}")]
    Internal(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limit_config_default() {
        let config = RateLimitConfig::default();
        assert_eq!(config.max_active_tokens_per_consumer, 10);
        assert_eq!(config.max_issuance_per_client_per_window, 100);
        assert_eq!(config.rate_limit_window_secs, 60);
    }

    #[test]
    fn test_rate_limit_config_custom() {
        let config = RateLimitConfig {
            max_active_tokens_per_consumer: 5,
            max_issuance_per_client_per_window: 50,
            rate_limit_window_secs: 30,
        };

        assert_eq!(config.max_active_tokens_per_consumer, 5);
        assert_eq!(config.max_issuance_per_client_per_window, 50);
        assert_eq!(config.rate_limit_window_secs, 30);
    }
}
