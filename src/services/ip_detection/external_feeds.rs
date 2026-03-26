//! External Threat Intelligence Feeds
//!
//! Integrates with external IP reputation services like AbuseIPDB.

use crate::cache::RedisCache;
use crate::error::AppError;
use crate::services::ip_detection::IpDetectionConfig;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{error, info, warn};

#[derive(Debug, Clone)]
pub struct ExternalFeedService {
    cache: Arc<RedisCache>,
    config: IpDetectionConfig,
    http_client: Client,
}

impl ExternalFeedService {
    pub fn new(cache: Arc<RedisCache>, config: IpDetectionConfig) -> Self {
        Self {
            cache,
            config,
            http_client: Client::new(),
        }
    }

    /// Check IP reputation against external feeds
    pub async fn check_ip_reputation(&self, ip: &str) -> Result<rust_decimal::Decimal, AppError> {
        let cache_key = format!("external_reputation:{}", ip);

        // Check cache first
        if let Some(cached_score) = self.cache.get::<String>(&cache_key).await? {
            if let Ok(score) = cached_score.parse::<rust_decimal::Decimal>() {
                return Ok(score);
            }
        }

        // Fetch from external feed
        let score = self.fetch_abuseipdb_reputation(ip).await?;

        // Cache the result
        self.cache.set_ex(
            &cache_key,
            &score.to_string(),
            self.config.external_feed_cache_ttl_secs as usize,
        ).await?;

        Ok(score)
    }

    /// Fetch reputation from AbuseIPDB
    async fn fetch_abuseipdb_reputation(&self, ip: &str) -> Result<rust_decimal::Decimal, AppError> {
        let api_key = std::env::var("ABUSEIPDB_API_KEY").ok();
        let api_url = std::env::var("ABUSEIPDB_API_URL")
            .unwrap_or_else(|_| "https://api.abuseipdb.com/api/v2/check".to_string());

        if api_key.is_none() {
            // Return neutral score if no API key configured
            return Ok(rust_decimal::Decimal::ZERO);
        }

        let api_key = api_key.unwrap();

        let response = self.http_client
            .get(&api_url)
            .query(&[("ipAddress", ip)])
            .header("Key", api_key)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| {
                error!(error = %e, ip = %ip, "Failed to query AbuseIPDB");
                AppError::ExternalServiceError(e.to_string())
            })?;

        if !response.status().is_success() {
            warn!(status = %response.status(), ip = %ip, "AbuseIPDB API error");
            return Ok(rust_decimal::Decimal::ZERO);
        }

        let abuse_response: AbuseIpDbResponse = response.json().await
            .map_err(|e| {
                error!(error = %e, ip = %ip, "Failed to parse AbuseIPDB response");
                AppError::ExternalServiceError(e.to_string())
            })?;

        // Convert AbuseIPDB score (0-100) to our scale (-100 to 0)
        // Higher AbuseIPDB score = more abusive = lower reputation score
        let abuse_score = abuse_response.data.abuse_confidence_score as i64;
        let reputation_score = -rust_decimal::Decimal::new(abuse_score * 100, 2); // Scale to -100.00 max

        info!(
            ip = %ip,
            abuse_score = abuse_score,
            reputation_score = %reputation_score,
            "Fetched external reputation"
        );

        Ok(reputation_score)
    }
}

#[derive(Debug, Deserialize)]
struct AbuseIpDbResponse {
    data: AbuseIpDbData,
}

#[derive(Debug, Deserialize)]
struct AbuseIpDbData {
    #[serde(rename = "abuseConfidenceScore")]
    abuse_confidence_score: u32,
}