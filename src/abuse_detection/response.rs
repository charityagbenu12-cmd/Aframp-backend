//! Automated response actions based on abuse confidence scores

use chrono::{DateTime, Duration, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseTier {
    Monitor,   // Log and alert only
    Soft,      // Rate limit tightening, re-auth
    Hard,      // Temporary suspension
    Critical,  // Immediate revocation
}

impl ResponseTier {
    /// Select response tier based on confidence score
    pub fn from_confidence(
        confidence: Decimal,
        monitor_threshold: Decimal,
        soft_threshold: Decimal,
        hard_threshold: Decimal,
        critical_threshold: Decimal,
    ) -> Self {
        if confidence >= critical_threshold {
            ResponseTier::Critical
        } else if confidence >= hard_threshold {
            ResponseTier::Hard
        } else if confidence >= soft_threshold {
            ResponseTier::Soft
        } else if confidence >= monitor_threshold {
            ResponseTier::Monitor
        } else {
            ResponseTier::Monitor // Default to monitor for low confidence
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            ResponseTier::Monitor => "monitor",
            ResponseTier::Soft => "soft",
            ResponseTier::Hard => "hard",
            ResponseTier::Critical => "critical",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseAction {
    pub id: Uuid,
    pub tier: ResponseTier,
    pub consumer_ids: Vec<Uuid>,
    pub applied_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub reason: String,
    pub evidence_case_id: Uuid,
    pub actions_taken: Vec<String>,
    pub notification_sent: bool,
}

impl ResponseAction {
    pub fn new(
        tier: ResponseTier,
        consumer_ids: Vec<Uuid>,
        reason: String,
        evidence_case_id: Uuid,
        duration: Option<Duration>,
    ) -> Self {
        let applied_at = Utc::now();
        let expires_at = duration.map(|d| applied_at + d);

        let actions_taken = match tier {
            ResponseTier::Monitor => vec!["logged_event".to_string(), "sent_alert".to_string()],
            ResponseTier::Soft => vec![
                "applied_rate_limit_tightening".to_string(),
                "logged_event".to_string(),
            ],
            ResponseTier::Hard => vec![
                "suspended_api_keys".to_string(),
                "revoked_tokens".to_string(),
                "notified_consumer".to_string(),
                "logged_event".to_string(),
            ],
            ResponseTier::Critical => vec![
                "revoked_all_credentials".to_string(),
                "flagged_account".to_string(),
                "notified_consumer".to_string(),
                "notified_security_team".to_string(),
                "logged_event".to_string(),
            ],
        };

        Self {
            id: Uuid::new_v4(),
            tier,
            consumer_ids,
            applied_at,
            expires_at,
            reason,
            evidence_case_id,
            actions_taken,
            notification_sent: false,
        }
    }

    pub fn is_expired(&self) -> bool {
        self.expires_at.map(|exp| exp < Utc::now()).unwrap_or(false)
    }

    pub fn is_active(&self) -> bool {
        !self.is_expired()
    }
}

/// Rate limit adjustment for soft responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitAdjustment {
    pub consumer_id: Uuid,
    pub original_limit: i64,
    pub adjusted_limit: i64,
    pub reduction_percent: Decimal,
    pub applied_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl RateLimitAdjustment {
    pub fn new(
        consumer_id: Uuid,
        original_limit: i64,
        reduction_percent: Decimal,
        duration: Duration,
    ) -> Self {
        let adjusted_limit = (Decimal::from(original_limit)
            * (Decimal::ONE - reduction_percent / Decimal::new(100, 0)))
        .to_i64()
        .unwrap_or(1)
        .max(1);

        let applied_at = Utc::now();
        let expires_at = applied_at + duration;

        Self {
            consumer_id,
            original_limit,
            adjusted_limit,
            reduction_percent,
            applied_at,
            expires_at,
        }
    }

    pub fn is_expired(&self) -> bool {
        self.expires_at < Utc::now()
    }
}

/// Credential suspension for hard/critical responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialSuspension {
    pub consumer_id: Uuid,
    pub suspended_keys: Vec<Uuid>,
    pub suspended_tokens: Vec<String>, // JTI values
    pub suspension_type: ResponseTier,
    pub reason: String,
    pub suspended_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub appeal_url: Option<String>,
}

impl CredentialSuspension {
    pub fn new(
        consumer_id: Uuid,
        suspended_keys: Vec<Uuid>,
        suspended_tokens: Vec<String>,
        suspension_type: ResponseTier,
        reason: String,
        duration: Option<Duration>,
    ) -> Self {
        let suspended_at = Utc::now();
        let expires_at = duration.map(|d| suspended_at + d);

        Self {
            consumer_id,
            suspended_keys,
            suspended_tokens,
            suspension_type,
            reason,
            suspended_at,
            expires_at,
            appeal_url: Some(format!("/api/admin/abuse/cases/{}/appeal", consumer_id)),
        }
    }

    pub fn is_expired(&self) -> bool {
        self.expires_at.map(|exp| exp < Utc::now()).unwrap_or(false)
    }

    pub fn is_permanent(&self) -> bool {
        self.expires_at.is_none() && self.suspension_type == ResponseTier::Critical
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_response_tier_from_confidence() {
        let tier = ResponseTier::from_confidence(
            Decimal::new(95, 2),
            Decimal::new(30, 2),
            Decimal::new(60, 2),
            Decimal::new(80, 2),
            Decimal::new(95, 2),
        );
        assert_eq!(tier, ResponseTier::Critical);

        let tier = ResponseTier::from_confidence(
            Decimal::new(85, 2),
            Decimal::new(30, 2),
            Decimal::new(60, 2),
            Decimal::new(80, 2),
            Decimal::new(95, 2),
        );
        assert_eq!(tier, ResponseTier::Hard);

        let tier = ResponseTier::from_confidence(
            Decimal::new(65, 2),
            Decimal::new(30, 2),
            Decimal::new(60, 2),
            Decimal::new(80, 2),
            Decimal::new(95, 2),
        );
        assert_eq!(tier, ResponseTier::Soft);

        let tier = ResponseTier::from_confidence(
            Decimal::new(35, 2),
            Decimal::new(30, 2),
            Decimal::new(60, 2),
            Decimal::new(80, 2),
            Decimal::new(95, 2),
        );
        assert_eq!(tier, ResponseTier::Monitor);
    }

    #[test]
    fn test_rate_limit_adjustment() {
        let adjustment = RateLimitAdjustment::new(
            Uuid::new_v4(),
            100,
            Decimal::new(50, 0), // 50% reduction
            Duration::minutes(15),
        );

        assert_eq!(adjustment.adjusted_limit, 50);
        assert!(!adjustment.is_expired());
    }

    #[test]
    fn test_credential_suspension() {
        let suspension = CredentialSuspension::new(
            Uuid::new_v4(),
            vec![Uuid::new_v4()],
            vec!["jti_123".to_string()],
            ResponseTier::Hard,
            "Abuse detected".to_string(),
            Some(Duration::hours(24)),
        );

        assert!(!suspension.is_expired());
        assert!(!suspension.is_permanent());
    }
}
