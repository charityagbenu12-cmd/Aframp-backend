//! DDoS protection configuration loaded from environment variables.

use std::time::Duration;

#[derive(Debug, Clone)]
pub struct DdosConfig {
    // Connection limits
    pub max_connections_per_ip: u32,
    pub max_connections_per_consumer: u32,
    pub slow_request_timeout_secs: u64,
    pub slow_bytes_threshold: u64, // bytes/sec below which a connection is "slow"

    // Volumetric detection
    pub baseline_rps: f64,
    pub spike_multiplier: f64, // e.g. 5.0 = 5x baseline triggers alert
    pub endpoint_flood_share: f64, // fraction of total traffic to one endpoint = flood

    // Traffic shaping
    pub high_priority_min_slots: u32,
    pub standard_priority_slots: u32,
    pub total_processing_slots: u32,
    pub wred_low_threshold: f64,  // queue fill fraction to start dropping low-priority
    pub wred_high_threshold: f64, // queue fill fraction for max drop probability

    // Challenge-response
    pub pow_difficulty_low: u32,
    pub pow_difficulty_high: u32,
    pub challenge_ttl_secs: u64,

    // CDN
    pub cdn_sync_interval_secs: u64,
    pub cdn_provider: CdnProvider,
    pub cdn_api_token: Option<String>,
    pub cdn_zone_id: Option<String>,

    // Lockdown
    pub lockdown_max_duration_secs: u64,

    // Allowlisted IPs (CIDR or exact) that bypass lockdown
    pub allowlisted_ips: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CdnProvider {
    Cloudflare,
    CloudFront,
    None,
}

impl Default for DdosConfig {
    fn default() -> Self {
        Self {
            max_connections_per_ip: 100,
            max_connections_per_consumer: 50,
            slow_request_timeout_secs: 10,
            slow_bytes_threshold: 100,
            baseline_rps: 100.0,
            spike_multiplier: 5.0,
            endpoint_flood_share: 0.5,
            high_priority_min_slots: 20,
            standard_priority_slots: 60,
            total_processing_slots: 100,
            wred_low_threshold: 0.5,
            wred_high_threshold: 0.9,
            pow_difficulty_low: 16,
            pow_difficulty_high: 24,
            challenge_ttl_secs: 300,
            cdn_sync_interval_secs: 60,
            cdn_provider: CdnProvider::None,
            cdn_api_token: None,
            cdn_zone_id: None,
            lockdown_max_duration_secs: 3600,
            allowlisted_ips: Vec::new(),
        }
    }
}

impl DdosConfig {
    pub fn from_env() -> Self {
        let cdn_provider = match std::env::var("DDOS_CDN_PROVIDER")
            .unwrap_or_default()
            .to_lowercase()
            .as_str()
        {
            "cloudflare" => CdnProvider::Cloudflare,
            "cloudfront" => CdnProvider::CloudFront,
            _ => CdnProvider::None,
        };

        let allowlisted_ips = std::env::var("DDOS_ALLOWLISTED_IPS")
            .unwrap_or_default()
            .split(',')
            .filter(|s| !s.is_empty())
            .map(|s| s.trim().to_string())
            .collect();

        Self {
            max_connections_per_ip: env_u32("DDOS_MAX_CONN_PER_IP", 100),
            max_connections_per_consumer: env_u32("DDOS_MAX_CONN_PER_CONSUMER", 50),
            slow_request_timeout_secs: env_u64("DDOS_SLOW_REQUEST_TIMEOUT_SECS", 10),
            slow_bytes_threshold: env_u64("DDOS_SLOW_BYTES_THRESHOLD", 100),
            baseline_rps: env_f64("DDOS_BASELINE_RPS", 100.0),
            spike_multiplier: env_f64("DDOS_SPIKE_MULTIPLIER", 5.0),
            endpoint_flood_share: env_f64("DDOS_ENDPOINT_FLOOD_SHARE", 0.5),
            high_priority_min_slots: env_u32("DDOS_HIGH_PRIORITY_MIN_SLOTS", 20),
            standard_priority_slots: env_u32("DDOS_STANDARD_PRIORITY_SLOTS", 60),
            total_processing_slots: env_u32("DDOS_TOTAL_SLOTS", 100),
            wred_low_threshold: env_f64("DDOS_WRED_LOW_THRESHOLD", 0.5),
            wred_high_threshold: env_f64("DDOS_WRED_HIGH_THRESHOLD", 0.9),
            pow_difficulty_low: env_u32("DDOS_POW_DIFFICULTY_LOW", 16),
            pow_difficulty_high: env_u32("DDOS_POW_DIFFICULTY_HIGH", 24),
            challenge_ttl_secs: env_u64("DDOS_CHALLENGE_TTL_SECS", 300),
            cdn_sync_interval_secs: env_u64("DDOS_CDN_SYNC_INTERVAL_SECS", 60),
            cdn_provider,
            cdn_api_token: std::env::var("DDOS_CDN_API_TOKEN").ok(),
            cdn_zone_id: std::env::var("DDOS_CDN_ZONE_ID").ok(),
            lockdown_max_duration_secs: env_u64("DDOS_LOCKDOWN_MAX_DURATION_SECS", 3600),
            allowlisted_ips,
        }
    }

    pub fn slow_request_timeout(&self) -> Duration {
        Duration::from_secs(self.slow_request_timeout_secs)
    }
}

fn env_u32(key: &str, default: u32) -> u32 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn env_f64(key: &str, default: f64) -> f64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}
