//! Geolocation Service
//!
//! Provides IP-to-country resolution using MaxMind GeoIP2 database.

use crate::cache::RedisCache;
use crate::error::AppError;
use maxminddb::{geoip2, Reader};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

/// Configuration for geolocation service
#[derive(Debug, Clone)]
pub struct GeolocationConfig {
    pub database_path: PathBuf,
    pub update_interval_hours: u64,
    pub redis_cache_ttl_secs: i64,
    pub default_policy_for_unresolvable: String, // 'allowed', 'restricted', 'blocked'
}

impl Default for GeolocationConfig {
    fn default() -> Self {
        Self {
            database_path: PathBuf::from("/var/lib/geoip/GeoLite2-Country.mmdb"),
            update_interval_hours: 168, // 1 week
            redis_cache_ttl_secs: 86400, // 24 hours
            default_policy_for_unresolvable: "allowed".to_string(),
        }
    }
}

impl GeolocationConfig {
    pub fn from_env() -> Self {
        Self {
            database_path: std::env::var("GEOIP_DATABASE_PATH")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("/var/lib/geoip/GeoLite2-Country.mmdb")),
            update_interval_hours: std::env::var("GEOIP_UPDATE_INTERVAL_HOURS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(168),
            redis_cache_ttl_secs: std::env::var("GEOIP_CACHE_TTL_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(86400),
            default_policy_for_unresolvable: std::env::var("GEOIP_DEFAULT_POLICY")
                .unwrap_or_else(|_| "allowed".to_string()),
        }
    }
}

/// Geolocation resolution result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeolocationResult {
    pub country_code: Option<String>,
    pub country_name: Option<String>,
    pub is_resolvable: bool,
}

/// Geolocation service
pub struct GeolocationService {
    config: GeolocationConfig,
    cache: Arc<RedisCache>,
    reader: Arc<RwLock<Option<Reader<Vec<u8>>>>>,
}

impl GeolocationService {
    pub fn new(cache: Arc<RedisCache>, config: GeolocationConfig) -> Self {
        Self {
            config,
            cache,
            reader: Arc::new(RwLock::new(None)),
        }
    }

    /// Initialize the geolocation database
    pub async fn initialize(&self) -> Result<(), AppError> {
        self.load_database().await?;
        info!("Geolocation service initialized with database: {:?}", self.config.database_path);
        Ok(())
    }

    /// Resolve IP address to country code
    pub async fn resolve_country(&self, ip: &str) -> Result<GeolocationResult, AppError> {
        // Check cache first
        let cache_key = format!("geo:{}", ip);
        if let Some(cached_result) = self.cache.get::<String>(&cache_key).await? {
            if let Ok(result) = serde_json::from_str::<GeolocationResult>(&cached_result) {
                return Ok(result);
            }
        }

        // Parse IP address
        let ip_addr: IpAddr = ip.parse().map_err(|_| {
            AppError::ValidationError(format!("Invalid IP address: {}", ip))
        })?;

        // Check if IP is private/reserved
        if self.is_private_or_reserved_ip(ip_addr) {
            let result = GeolocationResult {
                country_code: None,
                country_name: None,
                is_resolvable: false,
            };
            self.cache_result(&cache_key, &result).await?;
            return Ok(result);
        }

        // Lookup in database
        let result = self.lookup_country(ip_addr).await?;

        // Cache the result
        self.cache_result(&cache_key, &result).await?;

        Ok(result)
    }

    /// Lookup country in MaxMind database
    async fn lookup_country(&self, ip: IpAddr) -> Result<GeolocationResult, AppError> {
        let reader_guard = self.reader.read().await;
        let reader = reader_guard.as_ref().ok_or_else(|| {
            AppError::InternalError("Geolocation database not loaded".to_string())
        })?;

        match reader.lookup::<geoip2::Country>(ip) {
            Ok(country) => {
                let country_code = country.country
                    .and_then(|c| c.iso_code)
                    .map(|code| code.to_string());
                let country_name = country.country
                    .and_then(|c| c.names)
                    .and_then(|names| names.get("en"))
                    .map(|name| name.to_string());

                Ok(GeolocationResult {
                    country_code,
                    country_name,
                    is_resolvable: true,
                })
            }
            Err(e) => {
                warn!("Failed to lookup IP {} in geolocation database: {}", ip, e);
                Ok(GeolocationResult {
                    country_code: None,
                    country_name: None,
                    is_resolvable: false,
                })
            }
        }
    }

    /// Load MaxMind database into memory
    async fn load_database(&self) -> Result<(), AppError> {
        if !self.config.database_path.exists() {
            return Err(AppError::ConfigurationError(format!(
                "Geolocation database not found at: {:?}",
                self.config.database_path
            )));
        }

        let buffer = tokio::fs::read(&self.config.database_path).await
            .map_err(|e| AppError::InternalError(format!("Failed to read geolocation database: {}", e)))?;

        let reader = Reader::from_source(buffer)
            .map_err(|e| AppError::InternalError(format!("Failed to load geolocation database: {}", e)))?;

        let mut writer = self.reader.write().await;
        *writer = Some(reader);

        info!("Loaded geolocation database from {:?}", self.config.database_path);
        Ok(())
    }

    /// Update geolocation database (called periodically)
    pub async fn update_database(&self) -> Result<(), AppError> {
        // This would typically download the latest database from MaxMind
        // For now, we'll just reload the existing file
        info!("Updating geolocation database...");
        self.load_database().await?;
        info!("Geolocation database updated successfully");
        Ok(())
    }

    /// Check if IP is private, reserved, or unresolvable
    fn is_private_or_reserved_ip(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(ipv4) => {
                // Private networks: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
                ipv4.is_private() ||
                // Link-local: 169.254.0.0/16
                ipv4.is_link_local() ||
                // Loopback: 127.0.0.0/8
                ipv4.is_loopback() ||
                // Reserved ranges
                ipv4.is_broadcast() ||
                ipv4.is_documentation()
            }
            IpAddr::V6(ipv6) => {
                // IPv6 private/reserved ranges
                ipv6.is_loopback() ||
                // Unique local address (ULA): fc00::/7
                (ipv6.segments()[0] & 0xfe00) == 0xfc00 ||
                // Link-local: fe80::/10
                (ipv6.segments()[0] & 0xffc0) == 0xfe80
            }
        }
    }

    /// Cache geolocation result
    async fn cache_result(&self, cache_key: &str, result: &GeolocationResult) -> Result<(), AppError> {
        let json = serde_json::to_string(result)
            .map_err(|e| AppError::InternalError(format!("Failed to serialize geolocation result: {}", e)))?;

        self.cache.set_ex(cache_key, &json, self.config.redis_cache_ttl_secs as usize).await?;
        Ok(())
    }

    /// Get default policy for unresolvable IPs
    pub fn default_policy_for_unresolvable(&self) -> &str {
        &self.config.default_policy_for_unresolvable
    }

    /// Clear geolocation cache (useful after policy updates)
    pub async fn clear_cache(&self) -> Result<(), AppError> {
        // This would need to be implemented in RedisCache
        // For now, we'll just log
        info!("Geolocation cache clearing requested - implement Redis key pattern deletion");
        Ok(())
    }
}