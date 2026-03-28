//! Settlement worker metadata types

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

/// Metadata stored in settlement_batches.metadata JSONB column.
/// Tracks batch composition, provider responses, reconciliation data.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SettlementMetadata {
    /// Array of transaction_ids included in this settlement batch.
    #[serde(default)]
    pub transactions_included: Vec<String>,
    
    /// Provider-specific charge details (detected or estimated).
    #[serde(default)]
    pub provider_charges: JsonValue,
    
    /// Fee calculation breakdown.
    #[serde(default)]
    pub fee_breakdown: JsonValue,
    
    /// Provider response from initial settlement request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initial_provider_response: Option<JsonValue>,
    
    /// Provider settlement confirmation response.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub settlement_confirmation: Option<JsonValue>,
    
    /// Retry tracking.
    #[serde(default)]
    pub retry_count: u32,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_retry_at: Option<String>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_retry_after: Option<String>,
    
    /// Failure details.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_reason: Option<String>,
    
    /// Reconciliation-specific.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_reported_amount: Option<String>,
    
    /// Raw provider reconciliation data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_reconciliation_data: Option<JsonValue>,
}

impl SettlementMetadata {
    /// Create new metadata for a batch.
    pub fn new(transactions: Vec<String>) -> Self {
        Self {
            transactions_included: transactions,
            ..Default::default()
        }
    }
    
    /// Convert to JSONB-compatible value for DB storage.
    pub fn to_json(&self) -> JsonValue {
        serde_json::to_value(self).unwrap_or_default()
    }
    
    /// Parse from JSONB database value.
    pub fn from_json(value: &JsonValue) -> Result<Self, serde_json::Error> {
        serde_json::from_value(value.clone())
    }
    
    /// Add a transaction ID to the included list (idempotent).
    pub fn add_transaction(&mut self, tx_id: &str) {
        let tx_id = tx_id.to_string();
        if !self.transactions_included.contains(&tx_id) {
            self.transactions_included.push(tx_id);
        }
    }
    
    /// Mark failure with reason and retry info.
    pub fn record_failure(&mut self, reason: String, retryable: bool) {
        self.failure_reason = Some(reason);
        if retryable {
            self.retry_count += 1;
            self.last_retry_at = Some(chrono::Utc::now().to_rfc3339());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn metadata_json_roundtrip() {
        let mut metadata = SettlementMetadata::new(vec!["tx1".to_string(), "tx2".to_string()]);
        metadata.add_transaction("tx3");
        
        let json = metadata.to_json();
        let parsed = SettlementMetadata::from_json(&json).unwrap();
        
        assert_eq!(parsed.transactions_included.len(), 3);
        assert!(parsed.transactions_included.contains(&"tx1".to_string()));
        assert!(parsed.transactions_included.contains(&"tx3".to_string()));
    }

    #[test]
    fn idempotent_transaction_add() {
        let mut metadata = SettlementMetadata::default();
        metadata.add_transaction("tx1");
        assert_eq!(metadata.transactions_included.len(), 1);
        
        metadata.add_transaction("tx1"); // Duplicate
        assert_eq!(metadata.transactions_included.len(), 1); // Still 1
    }

    #[test]
    fn failure_tracking() {
        let mut metadata = SettlementMetadata::default();
        metadata.record_failure("Provider timeout".to_string(), true);
        
        assert_eq!(metadata.retry_count, 1);
        assert!(metadata.failure_reason.is_some());
        assert!(metadata.last_retry_at.is_some());
    }
}

