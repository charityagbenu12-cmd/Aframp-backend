//! Core abuse detection engine

use super::config::AbuseDetectionConfig;
use super::response::{CredentialSuspension, RateLimitAdjustment, ResponseAction, ResponseTier};
use super::signals::{DetectionResult, DetectionSignal, DetectionWindow};
use crate::cache::RedisCache;
use chrono::{Duration, Utc};
use rust_decimal::Decimal;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{info, warn};
use uuid::Uuid;

pub struct AbuseDetector {
    config: Arc<AbuseDetectionConfig>,
    cache: Arc<RedisCache>,
}

impl AbuseDetector {
    pub fn new(config: Arc<AbuseDetectionConfig>, cache: Arc<RedisCache>) -> Self {
        Self { config, cache }
    }

    /// Process detection signals and determine response
    pub async fn process_signals(
        &self,
        signals: Vec<DetectionSignal>,
        window: DetectionWindow,
    ) -> Result<Option<ResponseAction>, Box<dyn std::error::Error + Send + Sync>> {
        if signals.is_empty() {
            return Ok(None);
        }

        let result = DetectionResult::new(signals, window);
        let confidence = result.composite_confidence;

        info!(
            confidence = %confidence,
            signal_count = result.signals.len(),
            "Processing abuse detection signals"
        );

        // Determine response tier
        let tier = ResponseTier::from_confidence(
            confidence,
            self.config.monitor_confidence_threshold,
            self.config.soft_response_confidence_threshold,
            self.config.hard_response_confidence_threshold,
            self.config.critical_response_confidence_threshold,
        );

        if tier == ResponseTier::Monitor && confidence < self.config.monitor_confidence_threshold {
            return Ok(None);
        }

        let consumer_ids = result.affected_consumers();
        let case_id = Uuid::new_v4(); // Will be created in case management

        let duration = match tier {
            ResponseTier::Monitor => None,
            ResponseTier::Soft => Some(Duration::minutes(self.config.soft_response_duration_mins as i64)),
            ResponseTier::Hard => Some(Duration::hours(self.config.hard_response_duration_hours as i64)),
            ResponseTier::Critical => {
                if self.config.critical_response_permanent {
                    None
                } else {
                    Some(Duration::hours(self.config.hard_response_duration_hours as i64))
                }
            }
        };

        let reason = result
            .signals
            .iter()
            .map(|s| s.description())
            .collect::<Vec<_>>()
            .join("; ");

        let action = ResponseAction::new(tier, consumer_ids, reason, case_id, duration);

        Ok(Some(action))
    }

    /// Check authentication failure rate for credential stuffing
    pub async fn check_credential_stuffing(
        &self,
        consumer_id: Uuid,
        ip_address: &str,
    ) -> Result<Option<DetectionSignal>, Box<dyn std::error::Error + Send + Sync>> {
        let key = format!("abuse:auth_failures:{}:{}", consumer_id, ip_address);
        let window_secs = self.config.credential_stuffing_window_secs;

        let count = self.get_counter_in_window(&key, window_secs).await?;

        if count >= self.config.credential_stuffing_threshold {
            Ok(Some(DetectionSignal::CredentialStuffing {
                consumer_id,
                ip_address: ip_address.to_string(),
                attempt_count: count,
                threshold: self.config.credential_stuffing_threshold,
                window: DetectionWindow::Short,
                varying_credentials: vec![], // Populated from audit logs
            }))
        } else {
            Ok(None)
        }
    }

    /// Check brute force attempts against single account
    pub async fn check_brute_force(
        &self,
        ip_address: &str,
        target_account: &str,
    ) -> Result<Option<DetectionSignal>, Box<dyn std::error::Error + Send + Sync>> {
        let key = format!("abuse:brute_force:{}:{}", ip_address, target_account);
        let window_secs = self.config.brute_force_window_secs;

        let count = self.get_counter_in_window(&key, window_secs).await?;

        if count >= self.config.brute_force_threshold {
            Ok(Some(DetectionSignal::BruteForce {
                consumer_id: None,
                ip_address: ip_address.to_string(),
                target_account: target_account.to_string(),
                failure_count: count,
                threshold: self.config.brute_force_threshold,
                window: DetectionWindow::Short,
            }))
        } else {
            Ok(None)
        }
    }

    /// Check token harvesting (high issuance, low usage)
    pub async fn check_token_harvesting(
        &self,
        consumer_id: Uuid,
    ) -> Result<Option<DetectionSignal>, Box<dyn std::error::Error + Send + Sync>> {
        let issuance_key = format!("abuse:token_issuance:{}", consumer_id);
        let usage_key = format!("abuse:token_usage:{}", consumer_id);
        let window_secs = self.config.token_harvesting_window_secs;

        let issuance_count = self.get_counter_in_window(&issuance_key, window_secs).await?;
        let usage_count = self.get_counter_in_window(&usage_key, window_secs).await?;

        if issuance_count >= self.config.token_harvesting_threshold && usage_count > 0 {
            let ratio = Decimal::from(issuance_count) / Decimal::from(usage_count);

            if ratio > self.config.token_usage_ratio_threshold {
                return Ok(Some(DetectionSignal::TokenHarvesting {
                    consumer_id,
                    issuance_count,
                    usage_count,
                    ratio,
                    threshold: self.config.token_usage_ratio_threshold,
                    window: DetectionWindow::Medium,
                }));
            }
        }

        Ok(None)
    }

    /// Check API key enumeration
    pub async fn check_key_enumeration(
        &self,
        ip_address: &str,
    ) -> Result<Option<DetectionSignal>, Box<dyn std::error::Error + Send + Sync>> {
        let count_key = format!("abuse:key_enum_count:{}", ip_address);
        let prefixes_key = format!("abuse:key_enum_prefixes:{}", ip_address);
        let window_secs = self.config.key_enumeration_window_secs;

        let invalid_count = self.get_counter_in_window(&count_key, window_secs).await?;
        let unique_prefixes = self.get_set_size(&prefixes_key).await?;

        if invalid_count >= self.config.key_enumeration_threshold
            && unique_prefixes >= self.config.invalid_key_variety_threshold
        {
            Ok(Some(DetectionSignal::ApiKeyEnumeration {
                ip_address: ip_address.to_string(),
                invalid_key_count: invalid_count,
                unique_prefix_count: unique_prefixes,
                threshold: self.config.key_enumeration_threshold,
                window: DetectionWindow::Short,
            }))
        } else {
            Ok(None)
        }
    }

    /// Check scraping patterns
    pub async fn check_scraping(
        &self,
        consumer_id: Uuid,
        ip_address: &str,
        resource_type: &str,
    ) -> Result<Option<DetectionSignal>, Box<dyn std::error::Error + Send + Sync>> {
        let key = format!("abuse:scraping:{}:{}:{}", consumer_id, ip_address, resource_type);
        let window_secs = self.config.scraping_window_secs;

        let distinct_resources = self.get_set_size(&key).await?;

        if distinct_resources >= self.config.scraping_distinct_resources_threshold {
            Ok(Some(DetectionSignal::Scraping {
                consumer_id,
                ip_address: ip_address.to_string(),
                distinct_resources,
                threshold: self.config.scraping_distinct_resources_threshold,
                resource_type: resource_type.to_string(),
                window: DetectionWindow::Short,
            }))
        } else {
            Ok(None)
        }
    }

    /// Check quote farming
    pub async fn check_quote_farming(
        &self,
        consumer_id: Uuid,
    ) -> Result<Option<DetectionSignal>, Box<dyn std::error::Error + Send + Sync>> {
        let quote_key = format!("abuse:quotes:{}", consumer_id);
        let initiation_key = format!("abuse:initiations:{}", consumer_id);
        let window_secs = self.config.quote_farming_window_secs;

        let quote_count = self.get_counter_in_window(&quote_key, window_secs).await?;
        let initiation_count = self.get_counter_in_window(&initiation_key, window_secs).await?;

        if quote_count >= self.config.quote_farming_threshold && initiation_count > 0 {
            let ratio = Decimal::from(quote_count) / Decimal::from(initiation_count);

            if ratio > self.config.quote_initiation_ratio_threshold {
                return Ok(Some(DetectionSignal::QuoteFarming {
                    consumer_id,
                    quote_count,
                    initiation_count,
                    ratio,
                    threshold: self.config.quote_initiation_ratio_threshold,
                    window: DetectionWindow::Medium,
                }));
            }
        }

        Ok(None)
    }

    /// Record authentication failure
    pub async fn record_auth_failure(
        &self,
        consumer_id: Uuid,
        ip_address: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let key = format!("abuse:auth_failures:{}:{}", consumer_id, ip_address);
        self.increment_counter(&key, self.config.credential_stuffing_window_secs).await
    }

    /// Record token issuance
    pub async fn record_token_issuance(
        &self,
        consumer_id: Uuid,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let key = format!("abuse:token_issuance:{}", consumer_id);
        self.increment_counter(&key, self.config.token_harvesting_window_secs).await
    }

    /// Record token usage
    pub async fn record_token_usage(
        &self,
        consumer_id: Uuid,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let key = format!("abuse:token_usage:{}", consumer_id);
        self.increment_counter(&key, self.config.token_harvesting_window_secs).await
    }

    /// Record invalid API key attempt
    pub async fn record_invalid_key(
        &self,
        ip_address: &str,
        key_prefix: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let count_key = format!("abuse:key_enum_count:{}", ip_address);
        let prefixes_key = format!("abuse:key_enum_prefixes:{}", ip_address);

        self.increment_counter(&count_key, self.config.key_enumeration_window_secs).await?;
        self.add_to_set(&prefixes_key, key_prefix, self.config.key_enumeration_window_secs).await
    }

    /// Record resource access for scraping detection
    pub async fn record_resource_access(
        &self,
        consumer_id: Uuid,
        ip_address: &str,
        resource_type: &str,
        resource_id: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let key = format!("abuse:scraping:{}:{}:{}", consumer_id, ip_address, resource_type);
        self.add_to_set(&key, resource_id, self.config.scraping_window_secs).await
    }

    /// Record quote generation
    pub async fn record_quote(
        &self,
        consumer_id: Uuid,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let key = format!("abuse:quotes:{}", consumer_id);
        self.increment_counter(&key, self.config.quote_farming_window_secs).await
    }

    /// Record transaction initiation
    pub async fn record_initiation(
        &self,
        consumer_id: Uuid,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let key = format!("abuse:initiations:{}", consumer_id);
        self.increment_counter(&key, self.config.quote_farming_window_secs).await
    }

    // Helper methods for Redis operations
    async fn increment_counter(
        &self,
        key: &str,
        ttl_secs: u64,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut conn = self.cache.get_connection().await?;
        redis::cmd("INCR")
            .arg(key)
            .query_async::<_, ()>(&mut *conn)
            .await?;
        redis::cmd("EXPIRE")
            .arg(key)
            .arg(ttl_secs)
            .query_async::<_, ()>(&mut *conn)
            .await?;
        Ok(())
    }

    async fn get_counter_in_window(
        &self,
        key: &str,
        _window_secs: u64,
    ) -> Result<u32, Box<dyn std::error::Error + Send + Sync>> {
        let mut conn = self.cache.get_connection().await?;
        let count: Option<u32> = redis::cmd("GET")
            .arg(key)
            .query_async(&mut *conn)
            .await?;
        Ok(count.unwrap_or(0))
    }

    async fn add_to_set(
        &self,
        key: &str,
        member: &str,
        ttl_secs: u64,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut conn = self.cache.get_connection().await?;
        redis::cmd("SADD")
            .arg(key)
            .arg(member)
            .query_async::<_, ()>(&mut *conn)
            .await?;
        redis::cmd("EXPIRE")
            .arg(key)
            .arg(ttl_secs)
            .query_async::<_, ()>(&mut *conn)
            .await?;
        Ok(())
    }

    async fn get_set_size(
        &self,
        key: &str,
    ) -> Result<u32, Box<dyn std::error::Error + Send + Sync>> {
        let mut conn = self.cache.get_connection().await?;
        let size: u32 = redis::cmd("SCARD")
            .arg(key)
            .query_async(&mut *conn)
            .await?;
        Ok(size)
    }
}
