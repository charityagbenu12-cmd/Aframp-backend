//! OAuth 2.0 Scope Hierarchy Resolution
//!
//! Implements scope hierarchy logic where parent scopes include child scopes.
//! Examples:
//! - admin:* includes all admin scopes
//! - wallet:* includes all wallet scopes
//! - transactions:write includes initiate scopes

use std::collections::{HashMap, HashSet};

// ── Scope Hierarchy ─────────────────────────────────────────────────────────

pub struct ScopeHierarchy {
    /// Maps parent scopes to their child scopes
    hierarchy: HashMap<String, HashSet<String>>,
}

impl ScopeHierarchy {
    pub fn new() -> Self {
        let mut hierarchy = HashMap::new();

        // transactions:write includes onramp and offramp initiation
        hierarchy.insert(
            "transactions:write".to_string(),
            vec![
                "onramp:initiate".to_string(),
                "offramp:initiate".to_string(),
            ]
            .into_iter()
            .collect(),
        );

        // admin:* includes all admin scopes
        hierarchy.insert(
            "admin:*".to_string(),
            vec![
                "admin:transactions".to_string(),
                "admin:consumers".to_string(),
                "admin:config".to_string(),
            ]
            .into_iter()
            .collect(),
        );

        // wallet:* includes all wallet scopes
        hierarchy.insert(
            "wallet:*".to_string(),
            vec![
                "wallet:read".to_string(),
                "wallet:trustline".to_string(),
                "wallet:switch".to_string(),
            ]
            .into_iter()
            .collect(),
        );

        // onramp:* includes all onramp scopes
        hierarchy.insert(
            "onramp:*".to_string(),
            vec![
                "onramp:quote".to_string(),
                "onramp:initiate".to_string(),
                "onramp:read".to_string(),
            ]
            .into_iter()
            .collect(),
        );

        // offramp:* includes all offramp scopes
        hierarchy.insert(
            "offramp:*".to_string(),
            vec![
                "offramp:quote".to_string(),
                "offramp:initiate".to_string(),
                "offramp:read".to_string(),
            ]
            .into_iter()
            .collect(),
        );

        // bills:* includes all bills scopes
        hierarchy.insert(
            "bills:*".to_string(),
            vec!["bills:read".to_string(), "bills:pay".to_string()]
                .into_iter()
                .collect(),
        );

        // webhooks:* includes all webhooks scopes
        hierarchy.insert(
            "webhooks:*".to_string(),
            vec![
                "webhooks:read".to_string(),
                "webhooks:manage".to_string(),
            ]
            .into_iter()
            .collect(),
        );

        // batch:* includes all batch scopes
        hierarchy.insert(
            "batch:*".to_string(),
            vec![
                "batch:cngn-transfer".to_string(),
                "batch:fiat-payout".to_string(),
            ]
            .into_iter()
            .collect(),
        );

        // recurring:* includes all recurring scopes
        hierarchy.insert(
            "recurring:*".to_string(),
            vec![
                "recurring:read".to_string(),
                "recurring:manage".to_string(),
            ]
            .into_iter()
            .collect(),
        );

        Self { hierarchy }
    }

    /// Resolve all scopes including parent scopes
    /// Returns expanded set of scopes
    pub fn resolve_scopes(&self, scopes: &[&str]) -> HashSet<String> {
        let mut resolved = HashSet::new();

        for scope in scopes {
            resolved.insert(scope.to_string());

            // Add child scopes if this is a parent scope
            if let Some(children) = self.hierarchy.get(*scope) {
                for child in children {
                    resolved.insert(child.clone());
                }
            }
        }

        resolved
    }

    /// Check if a scope satisfies a required scope (considering hierarchy)
    pub fn satisfies(&self, granted_scopes: &[&str], required_scope: &str) -> bool {
        let resolved = self.resolve_scopes(granted_scopes);
        resolved.contains(required_scope)
    }

    /// Check if all required scopes are satisfied
    pub fn satisfies_all(&self, granted_scopes: &[&str], required_scopes: &[&str]) -> bool {
        let resolved = self.resolve_scopes(granted_scopes);
        required_scopes.iter().all(|scope| resolved.contains(*scope))
    }

    /// Check if any required scope is satisfied
    pub fn satisfies_any(&self, granted_scopes: &[&str], required_scopes: &[&str]) -> bool {
        let resolved = self.resolve_scopes(granted_scopes);
        required_scopes.iter().any(|scope| resolved.contains(*scope))
    }

    /// Get all child scopes for a parent scope
    pub fn get_children(&self, parent_scope: &str) -> Option<Vec<String>> {
        self.hierarchy
            .get(parent_scope)
            .map(|children| children.iter().cloned().collect())
    }
}

impl Default for ScopeHierarchy {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scope_hierarchy_single_scope() {
        let hierarchy = ScopeHierarchy::new();
        assert!(hierarchy.satisfies(&["wallet:read"], "wallet:read"));
        assert!(!hierarchy.satisfies(&["wallet:read"], "wallet:trustline"));
    }

    #[test]
    fn test_scope_hierarchy_wildcard() {
        let hierarchy = ScopeHierarchy::new();

        // admin:* should include admin:transactions
        assert!(hierarchy.satisfies(&["admin:*"], "admin:transactions"));
        assert!(hierarchy.satisfies(&["admin:*"], "admin:consumers"));
        assert!(hierarchy.satisfies(&["admin:*"], "admin:config"));

        // wallet:* should include all wallet scopes
        assert!(hierarchy.satisfies(&["wallet:*"], "wallet:read"));
        assert!(hierarchy.satisfies(&["wallet:*"], "wallet:trustline"));
        assert!(hierarchy.satisfies(&["wallet:*"], "wallet:switch"));
    }

    #[test]
    fn test_scope_hierarchy_transactions_write() {
        let hierarchy = ScopeHierarchy::new();

        // transactions:write should include onramp:initiate
        assert!(hierarchy.satisfies(&["transactions:write"], "onramp:initiate"));
        assert!(hierarchy.satisfies(&["transactions:write"], "offramp:initiate"));
    }

    #[test]
    fn test_scope_hierarchy_multi_scope() {
        let hierarchy = ScopeHierarchy::new();

        let granted = vec!["wallet:read", "onramp:quote"];
        assert!(hierarchy.satisfies_all(&granted, &["wallet:read", "onramp:quote"]));
        assert!(!hierarchy.satisfies_all(&granted, &["wallet:read", "offramp:quote"]));
    }

    #[test]
    fn test_scope_hierarchy_any() {
        let hierarchy = ScopeHierarchy::new();

        let granted = vec!["wallet:read"];
        assert!(hierarchy.satisfies_any(&granted, &["wallet:read", "offramp:quote"]));
        assert!(!hierarchy.satisfies_any(&granted, &["offramp:quote", "bills:pay"]));
    }

    #[test]
    fn test_scope_hierarchy_resolve() {
        let hierarchy = ScopeHierarchy::new();

        let resolved = hierarchy.resolve_scopes(&["admin:*"]);
        assert!(resolved.contains("admin:*"));
        assert!(resolved.contains("admin:transactions"));
        assert!(resolved.contains("admin:consumers"));
        assert!(resolved.contains("admin:config"));
    }

    #[test]
    fn test_scope_hierarchy_get_children() {
        let hierarchy = ScopeHierarchy::new();

        let children = hierarchy.get_children("wallet:*");
        assert!(children.is_some());
        let children = children.unwrap();
        assert_eq!(children.len(), 3);
    }
}
