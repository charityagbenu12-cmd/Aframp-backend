//! Detection signals for all abuse categories

use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalCategory {
    AuthenticationAbuse,
    EndpointAbuse,
    TransactionAbuse,
    CoordinatedAbuse,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectionWindow {
    Short,  // 1 minute
    Medium, // 1 hour
    Long,   // 24 hours
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DetectionSignal {
    // Authentication Abuse
    CredentialStuffing {
        consumer_id: Uuid,
        ip_address: String,
        attempt_count: u32,
        threshold: u32,
        window: DetectionWindow,
        varying_credentials: Vec<String>, // masked
    },
    BruteForce {
        consumer_id: Option<Uuid>,
        ip_address: String,
        target_account: String, // masked
        failure_count: u32,
        threshold: u32,
        window: DetectionWindow,
    },
    TokenHarvesting {
        consumer_id: Uuid,
        issuance_count: u32,
        usage_count: u32,
        ratio: Decimal,
        threshold: Decimal,
        window: DetectionWindow,
    },
    ApiKeyEnumeration {
        ip_address: String,
        invalid_key_count: u32,
        unique_prefix_count: u32,
        threshold: u32,
        window: DetectionWindow,
    },

    // Endpoint Abuse
    Scraping {
        consumer_id: Uuid,
        ip_address: String,
        distinct_resources: u32,
        threshold: u32,
        resource_type: String,
        window: DetectionWindow,
    },
    QuoteFarming {
        consumer_id: Uuid,
        quote_count: u32,
        initiation_count: u32,
        ratio: Decimal,
        threshold: Decimal,
        window: DetectionWindow,
    },
    StatusPollingAbuse {
        consumer_id: Uuid,
        transaction_id: Uuid,
        poll_count: u32,
        frequency: Decimal, // requests per second
        threshold: u32,
        window: DetectionWindow,
    },
    ErrorFarming {
        consumer_id: Uuid,
        ip_address: String,
        error_count: u32,
        total_requests: u32,
        error_rate: Decimal,
        threshold: Decimal,
        window: DetectionWindow,
    },

    // Transaction Abuse
    Structuring {
        consumer_id: Uuid,
        transaction_count: u32,
        amounts: Vec<Decimal>,
        reporting_threshold: Decimal,
        proximity_percent: Decimal,
        window: DetectionWindow,
    },
    VelocityAbuse {
        consumer_id: Uuid,
        current_velocity: Decimal, // transactions per hour
        historical_average: Decimal,
        multiplier: Decimal,
        threshold: Decimal,
        window: DetectionWindow,
    },
    RoundTrip {
        consumer_id: Uuid,
        onramp_tx_id: Uuid,
        offramp_tx_id: Uuid,
        amount_similarity: Decimal,
        time_diff_secs: u64,
        window: DetectionWindow,
    },
    NewConsumerHighValue {
        consumer_id: Uuid,
        account_age_hours: u64,
        transaction_amount: Decimal,
        threshold: Decimal,
    },

    // Coordinated Abuse
    MultiConsumerCoordination {
        consumer_ids: Vec<Uuid>,
        correlation_type: String, // "same_ip", "same_timing", "same_amounts"
        similarity_score: Decimal,
        evidence: serde_json::Value,
        window: DetectionWindow,
    },
    DistributedCredentialStuffing {
        consumer_ids: Vec<Uuid>,
        ip_addresses: Vec<String>,
        total_attempts: u32,
        threshold: u32,
        window: DetectionWindow,
    },
    SybilDetection {
        consumer_ids: Vec<Uuid>,
        similarity_score: Decimal,
        similarity_factors: Vec<String>,
        account_count: u32,
        threshold: u32,
    },
}

impl DetectionSignal {
    /// Calculate confidence score for this signal (0.0 - 1.0)
    pub fn confidence_score(&self) -> Decimal {
        match self {
            // Authentication abuse - high confidence
            DetectionSignal::CredentialStuffing { attempt_count, threshold, .. } => {
                let ratio = Decimal::from(*attempt_count) / Decimal::from(*threshold);
                (ratio * Decimal::new(30, 2)).min(Decimal::new(95, 2)) // 0.30 - 0.95
            }
            DetectionSignal::BruteForce { failure_count, threshold, .. } => {
                let ratio = Decimal::from(*failure_count) / Decimal::from(*threshold);
                (ratio * Decimal::new(35, 2)).min(Decimal::new(90, 2)) // 0.35 - 0.90
            }
            DetectionSignal::TokenHarvesting { ratio, threshold, .. } => {
                if *ratio > *threshold {
                    Decimal::new(75, 2) // 0.75
                } else {
                    Decimal::new(50, 2) // 0.50
                }
            }
            DetectionSignal::ApiKeyEnumeration { unique_prefix_count, threshold, .. } => {
                let ratio = Decimal::from(*unique_prefix_count) / Decimal::from(*threshold);
                (ratio * Decimal::new(40, 2)).min(Decimal::new(85, 2)) // 0.40 - 0.85
            }

            // Endpoint abuse - medium to high confidence
            DetectionSignal::Scraping { distinct_resources, threshold, .. } => {
                let ratio = Decimal::from(*distinct_resources) / Decimal::from(*threshold);
                (ratio * Decimal::new(25, 2)).min(Decimal::new(80, 2)) // 0.25 - 0.80
            }
            DetectionSignal::QuoteFarming { ratio, threshold, .. } => {
                if *ratio > *threshold {
                    Decimal::new(70, 2) // 0.70
                } else {
                    Decimal::new(45, 2) // 0.45
                }
            }
            DetectionSignal::StatusPollingAbuse { poll_count, threshold, .. } => {
                let ratio = Decimal::from(*poll_count) / Decimal::from(*threshold);
                (ratio * Decimal::new(30, 2)).min(Decimal::new(75, 2)) // 0.30 - 0.75
            }
            DetectionSignal::ErrorFarming { error_rate, threshold, .. } => {
                if *error_rate > *threshold {
                    Decimal::new(65, 2) // 0.65
                } else {
                    Decimal::new(40, 2) // 0.40
                }
            }

            // Transaction abuse - high confidence
            DetectionSignal::Structuring { transaction_count, .. } => {
                let base = Decimal::new(60, 2); // 0.60
                let bonus = Decimal::from(*transaction_count) * Decimal::new(5, 2); // 0.05 per tx
                (base + bonus).min(Decimal::new(95, 2)) // 0.60 - 0.95
            }
            DetectionSignal::VelocityAbuse { multiplier, threshold, .. } => {
                if *multiplier > *threshold {
                    Decimal::new(80, 2) // 0.80
                } else {
                    Decimal::new(55, 2) // 0.55
                }
            }
            DetectionSignal::RoundTrip { amount_similarity, .. } => {
                *amount_similarity * Decimal::new(85, 2) / Decimal::new(100, 2) // 0.00 - 0.85
            }
            DetectionSignal::NewConsumerHighValue { transaction_amount, threshold, .. } => {
                let ratio = *transaction_amount / *threshold;
                (ratio * Decimal::new(40, 2)).min(Decimal::new(75, 2)) // 0.40 - 0.75
            }

            // Coordinated abuse - very high confidence
            DetectionSignal::MultiConsumerCoordination { similarity_score, consumer_ids, .. } => {
                let base = *similarity_score;
                let count_bonus = Decimal::from(consumer_ids.len() as u32) * Decimal::new(5, 2); // 0.05 per consumer
                (base + count_bonus).min(Decimal::new(98, 2)) // up to 0.98
            }
            DetectionSignal::DistributedCredentialStuffing { total_attempts, threshold, .. } => {
                let ratio = Decimal::from(*total_attempts) / Decimal::from(*threshold);
                (ratio * Decimal::new(50, 2)).min(Decimal::new(95, 2)) // 0.50 - 0.95
            }
            DetectionSignal::SybilDetection { similarity_score, account_count, .. } => {
                let base = *similarity_score;
                let count_bonus = Decimal::from(*account_count) * Decimal::new(3, 2); // 0.03 per account
                (base + count_bonus).min(Decimal::new(97, 2)) // up to 0.97
            }
        }
    }

    /// Get the signal category
    pub fn category(&self) -> SignalCategory {
        match self {
            DetectionSignal::CredentialStuffing { .. }
            | DetectionSignal::BruteForce { .. }
            | DetectionSignal::TokenHarvesting { .. }
            | DetectionSignal::ApiKeyEnumeration { .. } => SignalCategory::AuthenticationAbuse,

            DetectionSignal::Scraping { .. }
            | DetectionSignal::QuoteFarming { .. }
            | DetectionSignal::StatusPollingAbuse { .. }
            | DetectionSignal::ErrorFarming { .. } => SignalCategory::EndpointAbuse,

            DetectionSignal::Structuring { .. }
            | DetectionSignal::VelocityAbuse { .. }
            | DetectionSignal::RoundTrip { .. }
            | DetectionSignal::NewConsumerHighValue { .. } => SignalCategory::TransactionAbuse,

            DetectionSignal::MultiConsumerCoordination { .. }
            | DetectionSignal::DistributedCredentialStuffing { .. }
            | DetectionSignal::SybilDetection { .. } => SignalCategory::CoordinatedAbuse,
        }
    }

    /// Get the detection window
    pub fn window(&self) -> DetectionWindow {
        match self {
            DetectionSignal::CredentialStuffing { window, .. }
            | DetectionSignal::BruteForce { window, .. }
            | DetectionSignal::TokenHarvesting { window, .. }
            | DetectionSignal::ApiKeyEnumeration { window, .. }
            | DetectionSignal::Scraping { window, .. }
            | DetectionSignal::QuoteFarming { window, .. }
            | DetectionSignal::StatusPollingAbuse { window, .. }
            | DetectionSignal::ErrorFarming { window, .. }
            | DetectionSignal::Structuring { window, .. }
            | DetectionSignal::VelocityAbuse { window, .. }
            | DetectionSignal::RoundTrip { window, .. }
            | DetectionSignal::MultiConsumerCoordination { window, .. }
            | DetectionSignal::DistributedCredentialStuffing { window, .. } => *window,
            DetectionSignal::NewConsumerHighValue { .. }
            | DetectionSignal::SybilDetection { .. } => DetectionWindow::Long,
        }
    }

    /// Get affected consumer IDs
    pub fn consumer_ids(&self) -> Vec<Uuid> {
        match self {
            DetectionSignal::CredentialStuffing { consumer_id, .. }
            | DetectionSignal::TokenHarvesting { consumer_id, .. }
            | DetectionSignal::Scraping { consumer_id, .. }
            | DetectionSignal::QuoteFarming { consumer_id, .. }
            | DetectionSignal::StatusPollingAbuse { consumer_id, .. }
            | DetectionSignal::ErrorFarming { consumer_id, .. }
            | DetectionSignal::Structuring { consumer_id, .. }
            | DetectionSignal::VelocityAbuse { consumer_id, .. }
            | DetectionSignal::RoundTrip { consumer_id, .. }
            | DetectionSignal::NewConsumerHighValue { consumer_id, .. } => vec![*consumer_id],

            DetectionSignal::BruteForce { consumer_id, .. } => {
                consumer_id.map(|id| vec![id]).unwrap_or_default()
            }

            DetectionSignal::MultiConsumerCoordination { consumer_ids, .. }
            | DetectionSignal::DistributedCredentialStuffing { consumer_ids, .. }
            | DetectionSignal::SybilDetection { consumer_ids, .. } => consumer_ids.clone(),

            DetectionSignal::ApiKeyEnumeration { .. } => vec![],
        }
    }

    /// Get a human-readable description
    pub fn description(&self) -> String {
        match self {
            DetectionSignal::CredentialStuffing { attempt_count, .. } => {
                format!("Credential stuffing detected: {} authentication attempts with varying credentials", attempt_count)
            }
            DetectionSignal::BruteForce { failure_count, .. } => {
                format!("Brute force attack detected: {} failed authentication attempts", failure_count)
            }
            DetectionSignal::TokenHarvesting { issuance_count, usage_count, ratio, .. } => {
                format!("Token harvesting detected: {} tokens issued but only {} used (ratio: {})", issuance_count, usage_count, ratio)
            }
            DetectionSignal::ApiKeyEnumeration { invalid_key_count, unique_prefix_count, .. } => {
                format!("API key enumeration detected: {} invalid keys with {} unique prefixes", invalid_key_count, unique_prefix_count)
            }
            DetectionSignal::Scraping { distinct_resources, resource_type, .. } => {
                format!("Scraping detected: {} distinct {} accessed sequentially", distinct_resources, resource_type)
            }
            DetectionSignal::QuoteFarming { quote_count, initiation_count, .. } => {
                format!("Quote farming detected: {} quotes generated but only {} transactions initiated", quote_count, initiation_count)
            }
            DetectionSignal::StatusPollingAbuse { poll_count, frequency, .. } => {
                format!("Status polling abuse detected: {} polls at {} req/sec", poll_count, frequency)
            }
            DetectionSignal::ErrorFarming { error_count, error_rate, .. } => {
                format!("Error farming detected: {} errors ({}% error rate)", error_count, error_rate * Decimal::new(100, 0))
            }
            DetectionSignal::Structuring { transaction_count, amounts, .. } => {
                format!("Transaction structuring detected: {} transactions just below reporting threshold", transaction_count)
            }
            DetectionSignal::VelocityAbuse { current_velocity, historical_average, multiplier, .. } => {
                format!("Velocity abuse detected: current rate {} is {}x historical average {}", current_velocity, multiplier, historical_average)
            }
            DetectionSignal::RoundTrip { amount_similarity, time_diff_secs, .. } => {
                format!("Round-trip transaction detected: {}% amount similarity within {} seconds", amount_similarity * Decimal::new(100, 0), time_diff_secs)
            }
            DetectionSignal::NewConsumerHighValue { transaction_amount, account_age_hours, .. } => {
                format!("New consumer high-value transaction: {} amount from {}-hour-old account", transaction_amount, account_age_hours)
            }
            DetectionSignal::MultiConsumerCoordination { consumer_ids, correlation_type, similarity_score, .. } => {
                format!("Coordinated abuse detected: {} consumers with {} correlation ({}% similarity)", consumer_ids.len(), correlation_type, similarity_score * Decimal::new(100, 0))
            }
            DetectionSignal::DistributedCredentialStuffing { consumer_ids, total_attempts, .. } => {
                format!("Distributed credential stuffing detected: {} attempts across {} consumers", total_attempts, consumer_ids.len())
            }
            DetectionSignal::SybilDetection { account_count, similarity_score, .. } => {
                format!("Sybil attack detected: {} similar accounts ({}% similarity)", account_count, similarity_score * Decimal::new(100, 0))
            }
        }
    }
}

/// Composite detection result with aggregated confidence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionResult {
    pub signals: Vec<DetectionSignal>,
    pub composite_confidence: Decimal,
    pub detected_at: DateTime<Utc>,
    pub window: DetectionWindow,
}

impl DetectionResult {
    pub fn new(signals: Vec<DetectionSignal>, window: DetectionWindow) -> Self {
        let composite_confidence = Self::calculate_composite_confidence(&signals);
        Self {
            signals,
            composite_confidence,
            detected_at: Utc::now(),
            window,
        }
    }

    /// Calculate composite confidence score from multiple signals
    /// Uses weighted average with diminishing returns for multiple signals
    fn calculate_composite_confidence(signals: &[DetectionSignal]) -> Decimal {
        if signals.is_empty() {
            return Decimal::ZERO;
        }

        let mut scores: Vec<Decimal> = signals.iter().map(|s| s.confidence_score()).collect();
        scores.sort_by(|a, b| b.cmp(a)); // Sort descending

        let mut composite = Decimal::ZERO;
        for (i, score) in scores.iter().enumerate() {
            // Apply diminishing weight: 1.0, 0.7, 0.5, 0.3, 0.2, ...
            let weight = match i {
                0 => Decimal::ONE,
                1 => Decimal::new(70, 2),
                2 => Decimal::new(50, 2),
                3 => Decimal::new(30, 2),
                _ => Decimal::new(20, 2),
            };
            composite += *score * weight;
        }

        // Normalize and cap at 1.0
        let normalizer = Decimal::new(
            (100 + 70 + 50 + 30 + (signals.len().saturating_sub(4) * 20) as i64).min(340),
            2,
        );
        (composite / normalizer).min(Decimal::ONE)
    }

    pub fn affected_consumers(&self) -> Vec<Uuid> {
        let mut consumers = Vec::new();
        for signal in &self.signals {
            consumers.extend(signal.consumer_ids());
        }
        consumers.sort();
        consumers.dedup();
        consumers
    }
}
