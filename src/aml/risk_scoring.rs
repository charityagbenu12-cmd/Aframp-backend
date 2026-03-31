//! Corridor-specific risk scoring and velocity/pattern analysis
//!
//! - Assigns risk weights based on Basel AML Index / FATF Grey List status
//! - Detects smurfing (multiple small transactions to same recipient)
//! - Detects rapid-flip (on-ramp → immediate off-ramp to high-risk jurisdiction)

use super::models::{AmlFlag, AmlFlagLevel, AmlScreeningRequest, CorridorRiskWeight, VelocityPattern};
use crate::cache::RedisCache;
use chrono::Utc;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{info, warn};
use uuid::Uuid;

/// Thresholds for velocity pattern detection
#[derive(Debug, Clone)]
pub struct VelocityConfig {
    /// Number of transactions to same recipient within window that triggers smurfing flag
    pub smurfing_tx_threshold: u32,
    /// Window in hours for smurfing detection
    pub smurfing_window_hours: u32,
    /// Minutes within which an on-ramp followed by off-ramp is considered a rapid flip
    pub rapid_flip_window_minutes: u32,
}

impl Default for VelocityConfig {
    fn default() -> Self {
        Self {
            smurfing_tx_threshold: 5,
            smurfing_window_hours: 24,
            rapid_flip_window_minutes: 60,
        }
    }
}

pub struct CorridorRiskScorer {
    /// country_pair → weight, keyed as "NG-KE", "NG-GH", etc.
    corridor_weights: HashMap<String, CorridorRiskWeight>,
    velocity_config: VelocityConfig,
    cache: Arc<RedisCache>,
}

impl CorridorRiskScorer {
    pub fn new(
        corridor_weights: Vec<CorridorRiskWeight>,
        velocity_config: VelocityConfig,
        cache: Arc<RedisCache>,
    ) -> Self {
        let weights = corridor_weights
            .into_iter()
            .map(|w| {
                let key = format!("{}-{}", w.origin_country, w.destination_country);
                (key, w)
            })
            .collect();

        Self {
            corridor_weights: weights,
            velocity_config,
            cache,
        }
    }

    /// Build default weights from FATF Grey List / Basel AML Index (2024 data)
    pub fn default_weights() -> Vec<CorridorRiskWeight> {
        vec![
            CorridorRiskWeight {
                origin_country: "NG".into(),
                destination_country: "KE".into(),
                weight: 0.4,
                reason: "Moderate risk corridor".into(),
            },
            CorridorRiskWeight {
                origin_country: "NG".into(),
                destination_country: "GH".into(),
                weight: 0.35,
                reason: "Moderate risk corridor".into(),
            },
            CorridorRiskWeight {
                origin_country: "NG".into(),
                destination_country: "ZA".into(),
                weight: 0.3,
                reason: "Lower risk corridor".into(),
            },
            // High-risk destinations (FATF Grey List)
            CorridorRiskWeight {
                origin_country: "NG".into(),
                destination_country: "MM".into(),
                weight: 0.9,
                reason: "FATF Grey List — Myanmar".into(),
            },
            CorridorRiskWeight {
                origin_country: "NG".into(),
                destination_country: "PK".into(),
                weight: 0.8,
                reason: "FATF Grey List — Pakistan".into(),
            },
        ]
    }

    /// Compute corridor risk score and return any flags
    pub fn score_corridor(
        &self,
        req: &AmlScreeningRequest,
    ) -> (f64, Vec<AmlFlag>) {
        let key = format!("{}-{}", req.origin_country, req.destination_country);
        let mut flags = Vec::new();
        let mut score = 0.0;

        if let Some(weight) = self.corridor_weights.get(&key) {
            score = weight.weight;
            if score >= 0.7 {
                warn!(
                    corridor = %key,
                    score = %score,
                    reason = %weight.reason,
                    "High-risk corridor detected"
                );
                flags.push(AmlFlag::HighCorridorRisk {
                    corridor: key.clone(),
                    risk_score: score,
                    reason: weight.reason.clone(),
                });
            }
        }

        (score, flags)
    }

    /// Detect smurfing: multiple small transactions to same recipient within window
    pub async fn detect_smurfing(
        &self,
        req: &AmlScreeningRequest,
    ) -> Option<AmlFlag> {
        let cache_key = format!(
            "aml:velocity:{}:{}",
            req.wallet_address, req.recipient_id
        );

        // Increment counter in Redis with TTL
        let count: u32 = match self
            .cache
            .increment_with_ttl(
                &cache_key,
                self.velocity_config.smurfing_window_hours as u64 * 3600,
            )
            .await
        {
            Ok(c) => c as u32,
            Err(_) => return None,
        };

        if count >= self.velocity_config.smurfing_tx_threshold {
            warn!(
                wallet = %req.wallet_address,
                recipient = %req.recipient_id,
                count = %count,
                "Smurfing pattern detected"
            );
            return Some(AmlFlag::SmurfingDetected {
                tx_count: count,
                window_hours: self.velocity_config.smurfing_window_hours,
                total_amount: req.amount.clone(),
            });
        }

        None
    }

    /// Detect rapid-flip: on-ramp in cNGN followed immediately by off-ramp to high-risk corridor
    pub async fn detect_rapid_flip(
        &self,
        req: &AmlScreeningRequest,
        on_ramp_tx_id: Option<Uuid>,
        on_ramp_created_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Option<AmlFlag> {
        let Some(on_ramp_id) = on_ramp_tx_id else {
            return None;
        };
        let Some(on_ramp_time) = on_ramp_created_at else {
            return None;
        };

        let elapsed = Utc::now()
            .signed_duration_since(on_ramp_time)
            .num_minutes();

        if elapsed < 0 {
            return None;
        }

        let corridor_key = format!("{}-{}", req.origin_country, req.destination_country);
        let is_high_risk = self
            .corridor_weights
            .get(&corridor_key)
            .map(|w| w.weight >= 0.7)
            .unwrap_or(false);

        if is_high_risk
            && elapsed <= self.velocity_config.rapid_flip_window_minutes as i64
        {
            warn!(
                wallet = %req.wallet_address,
                on_ramp_tx = %on_ramp_id,
                corridor = %corridor_key,
                elapsed_minutes = %elapsed,
                "Rapid-flip pattern detected"
            );
            return Some(AmlFlag::RapidFlip {
                on_ramp_tx_id: on_ramp_id,
                off_ramp_corridor: corridor_key,
                elapsed_minutes: elapsed as u32,
            });
        }

        None
    }

    /// Determine flag level from composite risk score
    pub fn flag_level_from_score(score: f64) -> Option<AmlFlagLevel> {
        if score >= 0.8 {
            Some(AmlFlagLevel::Critical)
        } else if score >= 0.5 {
            Some(AmlFlagLevel::Medium)
        } else if score >= 0.3 {
            Some(AmlFlagLevel::Low)
        } else {
            None
        }
    }
}
