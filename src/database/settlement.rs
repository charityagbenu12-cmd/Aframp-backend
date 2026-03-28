//! Settlement batch status types and utilities

use serde::{Deserialize, Serialize};
use std::fmt;

/// Settlement batch states matching DB CHECK constraint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementBatchStatus {
    Pending,
    Processing,
    Settled,
    Failed,
    Reconciled,
    Discrepant,
}

impl SettlementBatchStatus {
    /// Database string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            SettlementBatchStatus::Pending => "pending",
            SettlementBatchStatus::Processing => "processing",
            SettlementBatchStatus::Settled => "settled",
            SettlementBatchStatus::Failed => "failed",
            SettlementBatchStatus::Reconciled => "reconciled",
            SettlementBatchStatus::Discrepant => "discrepant",
        }
    }

    /// Parse from database string.
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "pending" => Some(SettlementBatchStatus::Pending),
            "processing" => Some(SettlementBatchStatus::Processing),
            "settled" => Some(SettlementBatchStatus::Settled),
            "failed" => Some(SettlementBatchStatus::Failed),
            "reconciled" => Some(SettlementBatchStatus::Reconciled),
            "discrepant" => Some(SettlementBatchStatus::Discrepant),
            _ => None,
        }
    }

    /// Validate state transitions (simple for now).
    pub fn can_transition_to(&self, next: &Self) -> bool {
        match (self, next) {
            // Normal flow
            (SettlementBatchStatus::Pending, SettlementBatchStatus::Processing) => true,
            (SettlementBatchStatus::Processing, SettlementBatchStatus::Settled) => true,
            (SettlementBatchStatus::Processing, SettlementBatchStatus::Failed) => true,
            
            // Reconciliation flow
            (SettlementBatchStatus::Settled, SettlementBatchStatus::Reconciled) => true,
            (SettlementBatchStatus::Settled, SettlementBatchStatus::Discrepant) => true,
            
            // Terminal states (no further transitions)
            (SettlementBatchStatus::Reconciled, _) => false,
            (SettlementBatchStatus::Discrepant, _) => false,
            (SettlementBatchStatus::Failed, _) => false,
            
            _ => false,
        }
    }
}

impl fmt::Display for SettlementBatchStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Reconciliation report status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReconciliationStatus {
    Pending,
    Matched,
    Discrepant,
    PendingManual,
}

impl ReconciliationStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            ReconciliationStatus::Pending => "pending",
            ReconciliationStatus::Matched => "matched",
            ReconciliationStatus::Discrepant => "discrepant",
            ReconciliationStatus::PendingManual => "pending_manual",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "pending" => Some(ReconciliationStatus::Pending),
            "matched" => Some(ReconciliationStatus::Matched),
            "discrepant" => Some(ReconciliationStatus::Discrepant),
            "pending_manual" => Some(ReconciliationStatus::PendingManual),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_string_roundtrip() {
        let statuses = [
            SettlementBatchStatus::Pending,
            SettlementBatchStatus::Processing,
            SettlementBatchStatus::Settled,
            SettlementBatchStatus::Failed,
            SettlementBatchStatus::Reconciled,
            SettlementBatchStatus::Discrepant,
        ];

        for status in statuses {
            let s = status.as_str();
            let parsed = SettlementBatchStatus::from_str(s).unwrap();
            assert_eq!(parsed, status);
        }
    }

    #[test]
    fn valid_state_transitions() {
        assert!(SettlementBatchStatus::Pending.can_transition_to(&SettlementBatchStatus::Processing));
        assert!(SettlementBatchStatus::Processing.can_transition_to(&SettlementBatchStatus::Settled));
        assert!(SettlementBatchStatus::Processing.can_transition_to(&SettlementBatchStatus::Failed));
        assert!(SettlementBatchStatus::Settled.can_transition_to(&SettlementBatchStatus::Reconciled));
        
        assert!(!SettlementBatchStatus::Reconciled.can_transition_to(&SettlementBatchStatus::Failed));
        assert!(!SettlementBatchStatus::Pending.can_transition_to(&SettlementBatchStatus::Reconciled));
    }

    #[test]
    fn invalid_status_parsing() {
        assert_eq!(SettlementBatchStatus::from_str("invalid"), None);
    }
}

