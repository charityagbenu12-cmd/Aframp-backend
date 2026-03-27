//! Masking rules — Redis-backed rule cache with immediate invalidation.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use uuid::Uuid;

use crate::masking::engine::MaskingStrategy;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaskingRule {
    pub id: String,
    pub field_name: String,
    pub category: String,
    pub strategy: MaskingStrategy,
    pub channels: Vec<String>,
    pub enabled: bool,
}

impl MaskingRule {
    pub fn new(
        field_name: impl Into<String>,
        category: impl Into<String>,
        strategy: MaskingStrategy,
        channels: Vec<String>,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            field_name: field_name.into(),
            category: category.into(),
            strategy,
            channels,
            enabled: true,
        }
    }
}

/// In-memory rule store backed by an RwLock.
/// In production this is populated from Redis on startup and invalidated on change.
#[derive(Clone, Default)]
pub struct RuleStore {
    rules: Arc<RwLock<HashMap<String, MaskingRule>>>,
}

impl RuleStore {
    pub fn new() -> Self {
        let mut store = Self::default();
        store.load_defaults();
        store
    }

    fn load_defaults(&mut self) {
        let defaults = vec![
            MaskingRule::new("password", "credentials", MaskingStrategy::FullRedaction, vec!["log".into(), "response".into(), "trace".into()]),
            MaskingRule::new("private_key", "crypto_key", MaskingStrategy::FullRedaction, vec!["log".into(), "response".into(), "trace".into()]),
            MaskingRule::new("account_number", "financial", MaskingStrategy::PartialSuffix(4), vec!["response".into(), "log".into()]),
            MaskingRule::new("phone_number", "pii", MaskingStrategy::PartialSuffix(3), vec!["response".into(), "log".into()]),
            MaskingRule::new("email", "pii", MaskingStrategy::PartialPrefix(3), vec!["response".into(), "log".into()]),
            MaskingRule::new("nin", "government_id", MaskingStrategy::FullRedaction, vec!["log".into(), "response".into(), "trace".into()]),
            MaskingRule::new("bvn", "government_id", MaskingStrategy::FullRedaction, vec!["log".into(), "response".into(), "trace".into()]),
            MaskingRule::new("token", "credentials", MaskingStrategy::FullRedaction, vec!["log".into(), "trace".into()]),
            MaskingRule::new("api_key", "credentials", MaskingStrategy::FullRedaction, vec!["log".into(), "trace".into()]),
            MaskingRule::new("card_number", "financial", MaskingStrategy::PartialSuffix(4), vec!["log".into(), "response".into()]),
        ];
        let mut map = self.rules.write().unwrap();
        for rule in defaults {
            map.insert(rule.id.clone(), rule);
        }
    }

    pub fn list(&self) -> Vec<MaskingRule> {
        self.rules.read().unwrap().values().cloned().collect()
    }

    pub fn add(&self, rule: MaskingRule) -> String {
        let id = rule.id.clone();
        self.rules.write().unwrap().insert(id.clone(), rule);
        tracing::info!(rule_id = %id, "Masking rule added");
        id
    }

    pub fn update(&self, id: &str, rule: MaskingRule) -> bool {
        let mut map = self.rules.write().unwrap();
        if map.contains_key(id) {
            map.insert(id.to_string(), rule);
            tracing::info!(rule_id = %id, "Masking rule updated");
            true
        } else {
            false
        }
    }

    pub fn remove(&self, id: &str) -> bool {
        let removed = self.rules.write().unwrap().remove(id).is_some();
        if removed {
            tracing::info!(rule_id = %id, "Masking rule removed");
        }
        removed
    }

    pub fn get(&self, id: &str) -> Option<MaskingRule> {
        self.rules.read().unwrap().get(id).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_store_defaults_loaded() {
        let store = RuleStore::new();
        assert!(!store.list().is_empty());
    }

    #[test]
    fn test_add_and_get_rule() {
        let store = RuleStore::new();
        let rule = MaskingRule::new("ssn", "government_id", MaskingStrategy::FullRedaction, vec!["log".into()]);
        let id = store.add(rule);
        assert!(store.get(&id).is_some());
    }

    #[test]
    fn test_update_rule() {
        let store = RuleStore::new();
        let rule = MaskingRule::new("test_field", "test", MaskingStrategy::FullRedaction, vec!["log".into()]);
        let id = store.add(rule);
        let updated = MaskingRule {
            id: id.clone(),
            field_name: "test_field".into(),
            category: "test".into(),
            strategy: MaskingStrategy::FormatPreserving,
            channels: vec!["log".into()],
            enabled: true,
        };
        assert!(store.update(&id, updated));
        assert_eq!(store.get(&id).unwrap().strategy, MaskingStrategy::FormatPreserving);
    }

    #[test]
    fn test_remove_rule() {
        let store = RuleStore::new();
        let rule = MaskingRule::new("temp_field", "test", MaskingStrategy::FullRedaction, vec![]);
        let id = store.add(rule);
        assert!(store.remove(&id));
        assert!(store.get(&id).is_none());
    }

    #[test]
    fn test_remove_nonexistent_rule() {
        let store = RuleStore::new();
        assert!(!store.remove("nonexistent-id"));
    }
}
