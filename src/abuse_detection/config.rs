//! Abuse detection configuration with thresholds for all detection signals

use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbuseDetectionConfig {
    // Authentication abuse thresholds
    pub credential_stuffing_threshold: u32,
    pub credential_stuffing_window_secs: u64,
    pub brute_force_threshold: u32,
    pub brute_force_window_secs: u64,
    pub token_harvesting_threshold: u32,
    pub token_harvesting_window_secs: u64,
    pub token_usage_ratio_threshold: Decimal, // issuance/usage ratio
    pub key_enumeration_threshold: u32,
    pub key_enumeration_window_secs: u64,
    pub invalid_key_variety_threshold: u32,

    // Endpoint abuse thresholds
    pub scraping_distinct_resources_threshold: u32,
    pub scraping_window_secs: u64,
    pub quote_farming_threshold: u32,
    pub quote_farming_window_secs: u64,
    pub quote_initiation_ratio_threshold: Decimal, // quotes/initiations ratio
    pub status_polling_threshold: u32,
    pub status_polling_window_secs: u64,
    pub status_polling_frequency_threshold: Decimal, // requests per second
    pub error_farming_threshold: u32,
    pub error_farming_window_secs: u64,
    pub error_rate_threshold: Decimal, // 4xx errors / total requests

    // Transaction abuse thresholds
    pub structuring_threshold: u32, // transactions near threshold
    pub structuring_window_secs: u64,
    pub structuring_amount_threshold: Decimal, // amount just below reporting threshold
    pub structuring_proximity_percent: Decimal, // % below threshold to flag
    pub velocity_multiplier_threshold: Decimal, // multiplier of historical average
    pub velocity_window_secs: u64,
    pub round_trip_window_secs: u64,
    pub round_trip_amount_similarity_percent: Decimal,
    pub new_consumer_high_value_threshold: Decimal,
    pub new_consumer_age_hours: u64,

    // Coordinated abuse thresholds
    pub coordination_consumer_count_threshold: u32,
    pub coordination_time_window_secs: u64,
    pub coordination_similarity_threshold: Decimal, // 0-1 similarity score
    pub distributed_credential_stuffing_threshold: u32,
    pub distributed_window_secs: u64,
    pub sybil_similarity_threshold: Decimal,
    pub sybil_account_count_threshold: u32,

    // Confidence scoring
    pub monitor_confidence_threshold: Decimal,
    pub soft_response_confidence_threshold: Decimal,
    pub hard_response_confidence_threshold: Decimal,
    pub critical_response_confidence_threshold: Decimal,

    // Response durations
    pub soft_response_duration_mins: u64,
    pub hard_response_duration_hours: u64,
    pub critical_response_permanent: bool,

    // Detection windows
    pub short_window_secs: u64,  // 1 minute
    pub medium_window_secs: u64, // 1 hour
    pub long_window_secs: u64,   // 24 hours
}

impl Default for AbuseDetectionConfig {
    fn default() -> Self {
        Self {
            // Authentication abuse
            credential_stuffing_threshold: 50,
            credential_stuffing_window_secs: 60,
            brute_force_threshold: 10,
            brute_force_window_secs: 60,
            token_harvesting_threshold: 100,
            token_harvesting_window_secs: 300,
            token_usage_ratio_threshold: Decimal::new(50, 1), // 5.0
            key_enumeration_threshold: 20,
            key_enumeration_window_secs: 60,
            invalid_key_variety_threshold: 10,

            // Endpoint abuse
            scraping_distinct_resources_threshold: 100,
            scraping_window_secs: 60,
            quote_farming_threshold: 50,
            quote_farming_window_secs: 300,
            quote_initiation_ratio_threshold: Decimal::new(100, 1), // 10.0
            status_polling_threshold: 100,
            status_polling_window_secs: 60,
            status_polling_frequency_threshold: Decimal::new(10, 1), // 1.0 req/sec
            error_farming_threshold: 50,
            error_farming_window_secs: 60,
            error_rate_threshold: Decimal::new(50, 2), // 0.50 (50%)

            // Transaction abuse
            structuring_threshold: 5,
            structuring_window_secs: 3600,
            structuring_amount_threshold: Decimal::new(10000, 2), // 100.00
            structuring_proximity_percent: Decimal::new(5, 2), // 0.05 (5%)
            velocity_multiplier_threshold: Decimal::new(50, 1), // 5.0x
            velocity_window_secs: 3600,
            round_trip_window_secs: 3600,
            round_trip_amount_similarity_percent: Decimal::new(95, 2), // 0.95 (95%)
            new_consumer_high_value_threshold: Decimal::new(100000, 2), // 1000.00
            new_consumer_age_hours: 24,

            // Coordinated abuse
            coordination_consumer_count_threshold: 3,
            coordination_time_window_secs: 300,
            coordination_similarity_threshold: Decimal::new(80, 2), // 0.80
            distributed_credential_stuffing_threshold: 100,
            distributed_window_secs: 300,
            sybil_similarity_threshold: Decimal::new(85, 2), // 0.85
            sybil_account_count_threshold: 5,

            // Confidence thresholds
            monitor_confidence_threshold: Decimal::new(30, 2), // 0.30
            soft_response_confidence_threshold: Decimal::new(60, 2), // 0.60
            hard_response_confidence_threshold: Decimal::new(80, 2), // 0.80
            critical_response_confidence_threshold: Decimal::new(95, 2), // 0.95

            // Response durations
            soft_response_duration_mins: 15,
            hard_response_duration_hours: 24,
            critical_response_permanent: true,

            // Detection windows
            short_window_secs: 60,
            medium_window_secs: 3600,
            long_window_secs: 86400,
        }
    }
}

impl AbuseDetectionConfig {
    pub fn from_env() -> Self {
        // Load from environment variables with defaults
        Self::default()
    }

    pub fn short_window(&self) -> Duration {
        Duration::from_secs(self.short_window_secs)
    }

    pub fn medium_window(&self) -> Duration {
        Duration::from_secs(self.medium_window_secs)
    }

    pub fn long_window(&self) -> Duration {
        Duration::from_secs(self.long_window_secs)
    }
}
