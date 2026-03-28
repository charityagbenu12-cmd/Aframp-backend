//! IP Detection Service
//!
//! Implements suspicious IP detection signals and automated blocking logic.

use crate::cache::RedisCache;
use crate::database::ip_reputation_repository::{IpEvidenceEntity, IpReputationEntity, IpReputationRepository};
use crate::database::Repository;
use crate::error::AppError;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tracing::{error, info, warn};

pub mod external_feeds;

// ── Configuration ────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct IpDetectionConfig {
    pub auth_failure_threshold: u32,        // failures per minute
    pub auth_failure_window_secs: i64,      // rolling window in seconds
    pub signature_failure_threshold: u32,   // failures per minute
    pub signature_failure_window_secs: i64, // rolling window in seconds
    pub rate_limit_breach_threshold: u32,   // breaches per hour
    pub rate_limit_breach_window_secs: i64, // rolling window in seconds
    pub impossible_travel_max_hours: i64,   // max hours between location changes
    pub high_value_threshold: rust_decimal::Decimal, // cNGN amount threshold
    pub scanning_endpoint_threshold: u32,   // distinct endpoints per minute
    pub scanning_window_secs: i64,          // rolling window in seconds
    pub composite_risk_threshold: rust_decimal::Decimal, // threshold for auto-blocking
    pub temporary_block_duration_mins: i64, // temporary block duration
    pub severe_block_duration_hours: i64,   // severe violation block duration
    pub external_feed_cache_ttl_secs: i64,  // external reputation cache TTL
    pub external_feed_threshold: rust_decimal::Decimal, // external reputation threshold
}

impl Default for IpDetectionConfig {
    fn default() -> Self {
        Self {
            auth_failure_threshold: 10,
            auth_failure_window_secs: 60,
            signature_failure_threshold: 5,
            signature_failure_window_secs: 60,
            rate_limit_breach_threshold: 5,
            rate_limit_breach_window_secs: 3600,
            impossible_travel_max_hours: 2,
            high_value_threshold: rust_decimal::Decimal::new(100000, 2), // 1000.00 cNGN
            scanning_endpoint_threshold: 20,
            scanning_window_secs: 60,
            composite_risk_threshold: rust_decimal::Decimal::new(-500, 2), // -5.00
            temporary_block_duration_mins: 15,
            severe_block_duration_hours: 24,
            external_feed_cache_ttl_secs: 3600, // 1 hour
            external_feed_threshold: rust_decimal::Decimal::new(-300, 2), // -3.00
        }
    }
}

// ── Detection Signals ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DetectionSignal {
    AuthFailureRate { count: u32, threshold: u32 },
    SignatureVerificationFailure { count: u32, threshold: u32 },
    RateLimitBreach { count: u32, threshold: u32 },
    ImpossibleTravel { previous_location: String, current_location: String, hours_diff: i64 },
    NewIpHighValueTransaction { amount: rust_decimal::Decimal, threshold: rust_decimal::Decimal },
    ScanningPattern { endpoints: u32, threshold: u32 },
    ExternalThreatFeed { score: rust_decimal::Decimal, feed_name: String },
}

impl DetectionSignal {
    pub fn risk_score(&self) -> rust_decimal::Decimal {
        match self {
            DetectionSignal::AuthFailureRate { .. } => rust_decimal::Decimal::new(-50, 2),
            DetectionSignal::SignatureVerificationFailure { .. } => rust_decimal::Decimal::new(-75, 2),
            DetectionSignal::RateLimitBreach { .. } => rust_decimal::Decimal::new(-30, 2),
            DetectionSignal::ImpossibleTravel { .. } => rust_decimal::Decimal::new(-100, 2),
            DetectionSignal::NewIpHighValueTransaction { .. } => rust_decimal::Decimal::new(-40, 2),
            DetectionSignal::ScanningPattern { .. } => rust_decimal::Decimal::new(-60, 2),
            DetectionSignal::ExternalThreatFeed { score, .. } => *score,
        }
    }

    pub fn evidence_type(&self) -> &'static str {
        match self {
            DetectionSignal::AuthFailureRate { .. } => "auth_failure_rate",
            DetectionSignal::SignatureVerificationFailure { .. } => "signature_verification_failure",
            DetectionSignal::RateLimitBreach { .. } => "rate_limit_breach",
            DetectionSignal::ImpossibleTravel { .. } => "impossible_travel",
            DetectionSignal::NewIpHighValueTransaction { .. } => "new_ip_high_value_transaction",
            DetectionSignal::ScanningPattern { .. } => "scanning_pattern",
            DetectionSignal::ExternalThreatFeed { .. } => "external_threat_feed",
        }
    }

    pub fn to_evidence_detail(&self) -> serde_json::Value {
        match self {
            DetectionSignal::AuthFailureRate { count, threshold } => {
                json!({ "count": count, "threshold": threshold })
            }
            DetectionSignal::SignatureVerificationFailure { count, threshold } => {
                json!({ "count": count, "threshold": threshold })
            }
            DetectionSignal::RateLimitBreach { count, threshold } => {
                json!({ "count": count, "threshold": threshold })
            }
            DetectionSignal::ImpossibleTravel { previous_location, current_location, hours_diff } => {
                json!({
                    "previous_location": previous_location,
                    "current_location": current_location,
                    "hours_diff": hours_diff
                })
            }
            DetectionSignal::NewIpHighValueTransaction { amount, threshold } => {
                json!({ "amount": amount.to_string(), "threshold": threshold.to_string() })
            }
            DetectionSignal::ScanningPattern { endpoints, threshold } => {
                json!({ "endpoints": endpoints, "threshold": threshold })
            }
            DetectionSignal::ExternalThreatFeed { score, feed_name } => {
                json!({ "score": score.to_string(), "feed_name": feed_name })
            }
        }
    }
}

// ── IP Detection Service ─────────────────────────────────────────────────────

pub struct IpDetectionService {
    repo: IpReputationRepository,
    cache: Arc<RedisCache>,
    config: IpDetectionConfig,
    external_feeds: external_feeds::ExternalFeedService,
}

impl IpDetectionService {
    pub fn new(
        repo: IpReputationRepository,
        cache: Arc<RedisCache>,
        config: IpDetectionConfig,
    ) -> Self {
        Self {
            repo,
            cache,
            config,
            external_feeds: external_feeds::ExternalFeedService::new(cache.clone(), config.clone()),
        }
    }

    /// Check IP against all detection signals
    pub async fn check_ip(&self, ip: &str, consumer_id: Option<&str>) -> Result<Vec<DetectionSignal>, AppError> {
        let mut signals = Vec::new();

        // Check authentication failure rate
        if let Some(signal) = self.check_auth_failure_rate(ip).await? {
            signals.push(signal);
        }

        // Check signature verification failures
        if let Some(signal) = self.check_signature_failure_rate(ip).await? {
            signals.push(signal);
        }

        // Check rate limit breaches
        if let Some(signal) = self.check_rate_limit_breaches(ip).await? {
            signals.push(signal);
        }

        // Check impossible travel
        if let Some(consumer_id) = consumer_id {
            if let Some(signal) = self.check_impossible_travel(ip, consumer_id).await? {
                signals.push(signal);
            }
        }

        // Check scanning patterns
        if let Some(signal) = self.check_scanning_pattern(ip).await? {
            signals.push(signal);
        }

        // Check external threat feeds
        if let Some(signal) = self.check_external_feeds(ip).await? {
            signals.push(signal);
        }

        Ok(signals)
    }

    /// Process high-value transaction from new IP
    pub async fn process_high_value_transaction(
        &self,
        ip: &str,
        amount: rust_decimal::Decimal,
        consumer_id: Option<&str>,
    ) -> Result<Option<DetectionSignal>, AppError> {
        // Check if IP is new (first seen recently)
        let reputation = self.repo.get_reputation(ip).await?;
        let is_new_ip = reputation
            .as_ref()
            .map(|r| r.first_seen_at > Utc::now() - Duration::hours(24))
            .unwrap_or(true);

        if is_new_ip && amount >= self.config.high_value_threshold {
            let signal = DetectionSignal::NewIpHighValueTransaction {
                amount,
                threshold: self.config.high_value_threshold,
            };
            self.record_signal(ip, &signal, consumer_id).await?;
            return Ok(Some(signal));
        }

        Ok(None)
    }

    /// Record detection signal and update reputation
    pub async fn record_signal(
        &self,
        ip: &str,
        signal: &DetectionSignal,
        consumer_id: Option<&str>,
    ) -> Result<(), AppError> {
        // Get or create reputation record
        let reputation = self.repo.get_or_create_reputation(ip, "internal").await?;

        // Add evidence record
        self.repo.add_evidence(
            ip,
            signal.evidence_type(),
            signal.to_evidence_detail(),
            consumer_id,
        ).await?;

        // Update reputation score
        let new_score = reputation.reputation_score + signal.risk_score();
        self.repo.update_reputation_score(ip, new_score).await?;

        // Check if auto-blocking threshold is reached
        if new_score <= self.config.composite_risk_threshold && !reputation.is_whitelisted {
            self.apply_automated_block(ip, &reputation, new_score).await?;
        }

        Ok(())
    }

    /// Apply automated block based on risk score
    async fn apply_automated_block(
        &self,
        ip: &str,
        reputation: &IpReputationEntity,
        score: rust_decimal::Decimal,
    ) -> Result<(), AppError> {
        let (block_type, expiry) = if score <= rust_decimal::Decimal::new(-800, 2) {
            // Severe violations - longer block
            ("temporary", Some(Utc::now() + Duration::hours(self.config.severe_block_duration_hours)))
        } else {
            // Standard violations - shorter block
            ("temporary", Some(Utc::now() + Duration::minutes(self.config.temporary_block_duration_mins)))
        };

        self.repo.apply_block(ip, block_type, expiry).await?;

        // Update Redis blocked IP set
        self.update_blocked_ip_cache(ip, true).await?;

        info!(
            ip = %ip,
            block_type = %block_type,
            score = %score,
            expiry = ?expiry,
            "Applied automated IP block"
        );

        Ok(())
    }

    /// Check authentication failure rate
    async fn check_auth_failure_rate(&self, ip: &str) -> Result<Option<DetectionSignal>, AppError> {
        // This would typically query Redis for auth failure counters
        // For now, return None as we need to integrate with existing auth system
        Ok(None)
    }

    /// Check signature verification failure rate
    async fn check_signature_failure_rate(&self, ip: &str) -> Result<Option<DetectionSignal>, AppError> {
        // This would query Redis for signature verification failures
        Ok(None)
    }

    /// Check rate limit breach frequency
    async fn check_rate_limit_breaches(&self, ip: &str) -> Result<Option<DetectionSignal>, AppError> {
        // This would query Redis for rate limit breach counters
        Ok(None)
    }

    /// Check for impossible travel patterns
    async fn check_impossible_travel(&self, _ip: &str, _consumer_id: &str) -> Result<Option<DetectionSignal>, AppError> {
        // This would require geolocation data and consumer location history
        // Implementation depends on existing user location tracking
        Ok(None)
    }

    /// Check for API scanning patterns
    async fn check_scanning_pattern(&self, ip: &str) -> Result<Option<DetectionSignal>, AppError> {
        // This would track distinct endpoints accessed by IP in a time window
        Ok(None)
    }

    /// Check external threat intelligence feeds
    async fn check_external_feeds(&self, ip: &str) -> Result<Option<DetectionSignal>, AppError> {
        let score = self.external_feeds.check_ip_reputation(ip).await?;
        if score <= self.config.external_feed_threshold {
            let signal = DetectionSignal::ExternalThreatFeed {
                score,
                feed_name: "abuseipdb".to_string(), // Default feed
            };
            return Ok(Some(signal));
        }
        Ok(None)
    }

    /// Update Redis blocked IP cache
    async fn update_blocked_ip_cache(&self, ip: &str, blocked: bool) -> Result<(), AppError> {
        let key = "blocked_ips";
        if blocked {
            self.cache.set_add(key, ip).await?;
        } else {
            self.cache.set_remove(key, ip).await?;
        }
        Ok(())
    }

    /// Bootstrap Redis blocked IP set from database
    pub async fn bootstrap_blocked_ips_cache(&self) -> Result<(), AppError> {
        let blocked_ips = self.repo.get_all_blocked_ips().await?;
        let key = "blocked_ips";

        // Clear existing set
        self.cache.delete(key).await?;

        // Add all blocked IPs
        for ip_record in blocked_ips {
            self.cache.set_add(key, &ip_record.ip_address_or_cidr).await?;
        }

        info!(count = blocked_ips.len(), "Bootstrapped blocked IPs cache");
        Ok(())
    }

    /// Check if IP is blocked (fast Redis check)
    pub async fn is_ip_blocked(&self, ip: &str) -> Result<bool, AppError> {
        let key = "blocked_ips";
        let is_member = self.cache.set_is_member(key, ip).await?;
        Ok(is_member)
    }

    /// Get IP reputation with caching
    pub async fn get_ip_reputation(&self, ip: &str) -> Result<Option<IpReputationEntity>, AppError> {
        self.repo.get_reputation(ip).await.map_err(Into::into)
    }

    /// Clean up expired blocks
    pub async fn cleanup_expired_blocks(&self) -> Result<i64, AppError> {
        let cleaned_count = self.repo.cleanup_expired_blocks().await?;

        if cleaned_count > 0 {
            // Re-bootstrap cache after cleanup
            self.bootstrap_blocked_ips_cache().await?;
            info!(count = cleaned_count, "Cleaned up expired IP blocks");
        }

        Ok(cleaned_count)
    }
}

#[cfg(test)]
mod tests;