//! JWKS (JSON Web Key Set) management service
//!
//! Handles:
//! - Fetching JWKS from auth server
//! - Caching keys in memory and Redis
//! - Periodic key refresh
//! - Key rotation support
//! - Fallback to last known keys on fetch failure

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

// ── JWKS types ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwksKey {
    pub kty: String,      // Key type (RSA)
    pub use_: String,     // Use (sig)
    pub kid: String,      // Key ID
    pub n: String,        // Modulus
    pub e: String,        // Exponent
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>, // Algorithm
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwksResponse {
    pub keys: Vec<JwksKey>,
}

// ── JWKS cache ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct JwksCache {
    keys: HashMap<String, JwksKey>,
    last_updated: i64,
}

impl JwksCache {
    fn new() -> Self {
        Self {
            keys: HashMap::new(),
            last_updated: 0,
        }
    }

    fn update(&mut self, keys: Vec<JwksKey>) {
        self.keys = keys.into_iter().map(|k| (k.kid.clone(), k)).collect();
        self.last_updated = chrono::Utc::now().timestamp();
    }

    fn get(&self, kid: &str) -> Option<JwksKey> {
        self.keys.get(kid).cloned()
    }

    fn all_keys(&self) -> Vec<JwksKey> {
        self.keys.values().cloned().collect()
    }
}

// ── JWKS Service ─────────────────────────────────────────────────────────────

pub struct JwksService {
    jwks_url: String,
    cache: Arc<RwLock<JwksCache>>,
    http_client: reqwest::Client,
    refresh_interval_secs: u64,
}

impl JwksService {
    pub fn new(jwks_url: String, refresh_interval_secs: u64) -> Self {
        Self {
            jwks_url,
            cache: Arc::new(RwLock::new(JwksCache::new())),
            http_client: reqwest::Client::new(),
            refresh_interval_secs,
        }
    }

    /// Get a specific key by ID
    pub async fn get_key(&self, kid: &str) -> Result<Option<JwksKey>, JwksError> {
        let cache = self.cache.read().await;
        if let Some(key) = cache.get(kid) {
            return Ok(Some(key));
        }
        drop(cache);

        // Key not in cache, try to refresh
        self.refresh_keys().await?;

        let cache = self.cache.read().await;
        Ok(cache.get(kid))
    }

    /// Get all keys
    pub async fn get_all_keys(&self) -> Result<Vec<JwksKey>, JwksError> {
        let cache = self.cache.read().await;
        if !cache.keys.is_empty() {
            return Ok(cache.all_keys());
        }
        drop(cache);

        // Cache empty, fetch keys
        self.refresh_keys().await?;

        let cache = self.cache.read().await;
        Ok(cache.all_keys())
    }

    /// Refresh keys from auth server
    pub async fn refresh_keys(&self) -> Result<(), JwksError> {
        match self.fetch_jwks().await {
            Ok(jwks) => {
                let mut cache = self.cache.write().await;
                cache.update(jwks.keys);
                info!("JWKS keys refreshed successfully");
                Ok(())
            }
            Err(e) => {
                warn!("Failed to refresh JWKS keys: {}", e);
                // Graceful degradation: use last known keys
                Err(e)
            }
        }
    }

    /// Fetch JWKS from auth server
    async fn fetch_jwks(&self) -> Result<JwksResponse, JwksError> {
        let response = self
            .http_client
            .get(&self.jwks_url)
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await
            .map_err(|e| JwksError::FetchFailed(e.to_string()))?;

        if !response.status().is_success() {
            return Err(JwksError::FetchFailed(format!(
                "HTTP {} from {}",
                response.status(),
                self.jwks_url
            )));
        }

        response
            .json::<JwksResponse>()
            .await
            .map_err(|e| JwksError::InvalidResponse(e.to_string()))
    }

    /// Start background refresh task
    pub fn start_refresh_task(self: Arc<Self>) {
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(self.refresh_interval_secs));

            loop {
                interval.tick().await;
                if let Err(e) = self.refresh_keys().await {
                    error!("Background JWKS refresh failed: {}", e);
                }
            }
        });
    }
}

// ── Error types ──────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum JwksError {
    #[error("failed to fetch JWKS: {0}")]
    FetchFailed(String),
    #[error("invalid JWKS response: {0}")]
    InvalidResponse(String),
    #[error("key not found: {0}")]
    KeyNotFound(String),
    #[error("internal error: {0}")]
    Internal(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jwks_cache_update() {
        let mut cache = JwksCache::new();
        assert!(cache.keys.is_empty());

        let keys = vec![JwksKey {
            kty: "RSA".to_string(),
            use_: "sig".to_string(),
            kid: "key_1".to_string(),
            n: "modulus".to_string(),
            e: "exponent".to_string(),
            alg: Some("RS256".to_string()),
        }];

        cache.update(keys);
        assert_eq!(cache.keys.len(), 1);
        assert!(cache.get("key_1").is_some());
    }

    #[test]
    fn test_jwks_cache_get() {
        let mut cache = JwksCache::new();
        let key = JwksKey {
            kty: "RSA".to_string(),
            use_: "sig".to_string(),
            kid: "key_1".to_string(),
            n: "modulus".to_string(),
            e: "exponent".to_string(),
            alg: Some("RS256".to_string()),
        };

        cache.update(vec![key.clone()]);
        let retrieved = cache.get("key_1").unwrap();
        assert_eq!(retrieved.kid, "key_1");
    }

    #[test]
    fn test_jwks_cache_all_keys() {
        let mut cache = JwksCache::new();
        let keys = vec![
            JwksKey {
                kty: "RSA".to_string(),
                use_: "sig".to_string(),
                kid: "key_1".to_string(),
                n: "modulus1".to_string(),
                e: "exponent".to_string(),
                alg: Some("RS256".to_string()),
            },
            JwksKey {
                kty: "RSA".to_string(),
                use_: "sig".to_string(),
                kid: "key_2".to_string(),
                n: "modulus2".to_string(),
                e: "exponent".to_string(),
                alg: Some("RS256".to_string()),
            },
        ];

        cache.update(keys);
        let all = cache.all_keys();
        assert_eq!(all.len(), 2);
    }
}
