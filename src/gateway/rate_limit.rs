//! Gateway-level rate limiting — per-IP and per-API-key-prefix.
//! Thresholds are significantly higher than app-level limits (catch egregious abuse only).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Simple in-process sliding window counter for gateway rate limiting.
/// In production this would be backed by Redis for multi-instance consistency.
#[derive(Default)]
struct Window {
    count: u64,
    window_start: Option<Instant>,
}

#[derive(Clone)]
pub struct GatewayRateLimiter {
    ip_windows: Arc<Mutex<HashMap<String, Window>>>,
    key_windows: Arc<Mutex<HashMap<String, Window>>>,
    ip_limit: u64,
    key_limit: u64,
    window: Duration,
}

impl GatewayRateLimiter {
    pub fn new(ip_limit: u64, key_limit: u64) -> Self {
        Self {
            ip_windows: Arc::new(Mutex::new(HashMap::new())),
            key_windows: Arc::new(Mutex::new(HashMap::new())),
            ip_limit,
            key_limit,
            window: Duration::from_secs(60),
        }
    }

    /// Check and increment the per-IP counter. Returns Ok(remaining) or Err(()).
    pub fn check_ip(&self, ip: &str) -> Result<u64, ()> {
        self.check(&self.ip_windows, ip, self.ip_limit)
    }

    /// Check and increment the per-key-prefix counter. Returns Ok(remaining) or Err(()).
    pub fn check_key_prefix(&self, prefix: &str) -> Result<u64, ()> {
        self.check(&self.key_windows, prefix, self.key_limit)
    }

    fn check(&self, map: &Arc<Mutex<HashMap<String, Window>>>, key: &str, limit: u64) -> Result<u64, ()> {
        let mut guard = map.lock().unwrap();
        let entry = guard.entry(key.to_string()).or_default();
        let now = Instant::now();

        match entry.window_start {
            None => {
                entry.window_start = Some(now);
                entry.count = 1;
            }
            Some(start) if now.duration_since(start) >= self.window => {
                entry.window_start = Some(now);
                entry.count = 1;
            }
            _ => {
                entry.count += 1;
            }
        }

        if entry.count > limit {
            Err(())
        } else {
            Ok(limit - entry.count)
        }
    }
}

/// Extract the API key prefix (first 8 chars) from the X-API-Key header value.
pub fn api_key_prefix(key: &str) -> &str {
    &key[..key.len().min(8)]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_rate_limit_allows_under_limit() {
        let limiter = GatewayRateLimiter::new(10, 50);
        for _ in 0..10 {
            assert!(limiter.check_ip("1.2.3.4").is_ok());
        }
    }

    #[test]
    fn test_ip_rate_limit_rejects_over_limit() {
        let limiter = GatewayRateLimiter::new(5, 50);
        for _ in 0..5 {
            let _ = limiter.check_ip("1.2.3.5");
        }
        assert!(limiter.check_ip("1.2.3.5").is_err());
    }

    #[test]
    fn test_key_prefix_rate_limit() {
        let limiter = GatewayRateLimiter::new(1000, 3);
        for _ in 0..3 {
            let _ = limiter.check_key_prefix("ak_12345");
        }
        assert!(limiter.check_key_prefix("ak_12345").is_err());
    }

    #[test]
    fn test_different_ips_independent() {
        let limiter = GatewayRateLimiter::new(2, 100);
        assert!(limiter.check_ip("10.0.0.1").is_ok());
        assert!(limiter.check_ip("10.0.0.1").is_ok());
        assert!(limiter.check_ip("10.0.0.1").is_err());
        // Different IP is unaffected
        assert!(limiter.check_ip("10.0.0.2").is_ok());
    }

    #[test]
    fn test_api_key_prefix_extraction() {
        assert_eq!(api_key_prefix("ak_live_abcdefghijklmn"), "ak_live_");
        assert_eq!(api_key_prefix("short"), "short");
    }
}
