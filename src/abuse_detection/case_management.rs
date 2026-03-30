//! Abuse case management for tracking and resolving abuse incidents

use super::response::{ResponseAction, ResponseTier};
use super::signals::{DetectionSignal, SignalCategory};
use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "abuse_case_status", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum AbuseCaseStatus {
    Open,
    Escalated,
    Dismissed,
    Resolved,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbuseCase {
    pub id: Uuid,
    pub consumer_ids: Vec<Uuid>,
    pub detection_signals: Vec<DetectionSignal>,
    pub composite_confidence: Decimal,
    pub response_tier: ResponseTier,
    pub status: AbuseCaseStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub resolution_notes: Option<String>,
    pub escalated_by: Option<Uuid>,
    pub resolved_by: Option<Uuid>,
    pub false_positive: bool,
    pub whitelisted_signals: Vec<String>,
}

impl AbuseCase {
    pub fn new(
        consumer_ids: Vec<Uuid>,
        detection_signals: Vec<DetectionSignal>,
        composite_confidence: Decimal,
        response_tier: ResponseTier,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            consumer_ids,
            detection_signals,
            composite_confidence,
            response_tier,
            status: AbuseCaseStatus::Open,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            resolved_at: None,
            resolution_notes: None,
            escalated_by: None,
            resolved_by: None,
            false_positive: false,
            whitelisted_signals: vec![],
        }
    }

    pub fn escalate(&mut self, admin_id: Uuid, new_tier: ResponseTier) {
        self.response_tier = new_tier;
        self.status = AbuseCaseStatus::Escalated;
        self.escalated_by = Some(admin_id);
        self.updated_at = Utc::now();
    }

    pub fn dismiss(&mut self, admin_id: Uuid, reason: String, whitelist_signals: Vec<String>) {
        self.status = AbuseCaseStatus::Dismissed;
        self.resolved_by = Some(admin_id);
        self.resolved_at = Some(Utc::now());
        self.resolution_notes = Some(reason);
        self.false_positive = true;
        self.whitelisted_signals = whitelist_signals;
        self.updated_at = Utc::now();
    }

    pub fn resolve(&mut self, admin_id: Uuid, notes: String) {
        self.status = AbuseCaseStatus::Resolved;
        self.resolved_by = Some(admin_id);
        self.resolved_at = Some(Utc::now());
        self.resolution_notes = Some(notes);
        self.updated_at = Utc::now();
    }

    pub fn signal_categories(&self) -> Vec<SignalCategory> {
        let mut categories: Vec<_> = self
            .detection_signals
            .iter()
            .map(|s| s.category())
            .collect();
        categories.sort_by_key(|c| format!("{:?}", c));
        categories.dedup();
        categories
    }

    pub fn signal_count_by_category(&self) -> std::collections::HashMap<SignalCategory, usize> {
        let mut counts = std::collections::HashMap::new();
        for signal in &self.detection_signals {
            *counts.entry(signal.category()).or_insert(0) += 1;
        }
        counts
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbuseCaseSummary {
    pub id: Uuid,
    pub consumer_ids: Vec<Uuid>,
    pub signal_count: usize,
    pub categories: Vec<SignalCategory>,
    pub composite_confidence: Decimal,
    pub response_tier: ResponseTier,
    pub status: AbuseCaseStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<AbuseCase> for AbuseCaseSummary {
    fn from(case: AbuseCase) -> Self {
        Self {
            id: case.id,
            consumer_ids: case.consumer_ids,
            signal_count: case.detection_signals.len(),
            categories: case.signal_categories(),
            composite_confidence: case.composite_confidence,
            response_tier: case.response_tier,
            status: case.status,
            created_at: case.created_at,
            updated_at: case.updated_at,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseEscalationRequest {
    pub new_tier: ResponseTier,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseDismissalRequest {
    pub reason: String,
    pub whitelist_signal_types: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseResolutionRequest {
    pub notes: String,
    pub actions_taken: Vec<String>,
}
