//! Comprehensive tests for OAuth 2.0 Scope System
//!
//! Tests cover:
//! - Scope catalogue and hierarchy
//! - Scope validation
//! - Partial consent
//! - Sensitive scope enforcement

#[cfg(test)]
mod tests {
    use crate::auth::scope_catalog::{ScopeCatalog, ScopeCategory, ScopeDefinition};
    use crate::auth::scope_hierarchy::ScopeHierarchy;

    // ── Scope Catalogue Tests ────────────────────────────────────────────────

    #[test]
    fn test_scope_catalog_creation() {
        let catalog = ScopeCatalog::with_defaults();
        assert!(!catalog.all().is_empty());
    }

    #[test]
    fn test_scope_catalog_get_scope() {
        let catalog = ScopeCatalog::with_defaults();
        assert!(catalog.get("wallet:read").is_some());
        assert!(catalog.get("admin:transactions").is_some());
        assert!(catalog.get("nonexistent:scope").is_none());
    }

    #[test]
    fn test_scope_catalog_by_category() {
        let catalog = ScopeCatalog::with_defaults();

        let wallet_scopes = catalog.by_category(ScopeCategory::Wallet);
        assert!(!wallet_scopes.is_empty());
        assert!(wallet_scopes.iter().all(|s| s.category == ScopeCategory::Wallet));

        let admin_scopes = catalog.by_category(ScopeCategory::Admin);
        assert!(!admin_scopes.is_empty());
        assert!(admin_scopes.iter().all(|s| s.category == ScopeCategory::Admin));
    }

    #[test]
    fn test_scope_catalog_sensitive() {
        let catalog = ScopeCatalog::with_defaults();
        let sensitive = catalog.sensitive();

        assert!(!sensitive.is_empty());
        assert!(sensitive.iter().all(|s| s.is_sensitive));

        // Verify specific sensitive scopes
        let sensitive_names: Vec<&str> = sensitive.iter().map(|s| s.name.as_str()).collect();
        assert!(sensitive_names.contains(&"onramp:initiate"));
        assert!(sensitive_names.contains(&"admin:transactions"));
        assert!(sensitive_names.contains(&"wallet:trustline"));
    }

    #[test]
    fn test_scope_format_validation() {
        assert!(ScopeDefinition::validate_format("wallet:read").is_ok());
        assert!(ScopeDefinition::validate_format("admin:*").is_ok());
        assert!(ScopeDefinition::validate_format("onramp:quote").is_ok());

        // Invalid formats
        assert!(ScopeDefinition::validate_format("invalid").is_err());
        assert!(ScopeDefinition::validate_format("*:read").is_err());
        assert!(ScopeDefinition::validate_format(":read").is_err());
        assert!(ScopeDefinition::validate_format("wallet:").is_err());
    }

    #[test]
    fn test_scope_catalog_add() {
        let mut catalog = ScopeCatalog::new();
        let scope = ScopeDefinition::new(
            "test:read",
            "Test scope",
            ScopeCategory::Wallet,
            false,
        );

        assert!(catalog.add(scope.clone()).is_ok());
        assert!(catalog.get("test:read").is_some());

        // Duplicate should fail
        assert!(catalog.add(scope).is_err());
    }

    // ── Scope Hierarchy Tests ────────────────────────────────────────────────

    #[test]
    fn test_scope_hierarchy_single_scope() {
        let hierarchy = ScopeHierarchy::new();

        assert!(hierarchy.satisfies(&["wallet:read"], "wallet:read"));
        assert!(!hierarchy.satisfies(&["wallet:read"], "wallet:trustline"));
    }

    #[test]
    fn test_scope_hierarchy_wildcard_admin() {
        let hierarchy = ScopeHierarchy::new();

        // admin:* should include all admin scopes
        assert!(hierarchy.satisfies(&["admin:*"], "admin:transactions"));
        assert!(hierarchy.satisfies(&["admin:*"], "admin:consumers"));
        assert!(hierarchy.satisfies(&["admin:*"], "admin:config"));
    }

    #[test]
    fn test_scope_hierarchy_wildcard_wallet() {
        let hierarchy = ScopeHierarchy::new();

        // wallet:* should include all wallet scopes
        assert!(hierarchy.satisfies(&["wallet:*"], "wallet:read"));
        assert!(hierarchy.satisfies(&["wallet:*"], "wallet:trustline"));
        assert!(hierarchy.satisfies(&["wallet:*"], "wallet:switch"));
    }

    #[test]
    fn test_scope_hierarchy_wildcard_onramp() {
        let hierarchy = ScopeHierarchy::new();

        // onramp:* should include all onramp scopes
        assert!(hierarchy.satisfies(&["onramp:*"], "onramp:quote"));
        assert!(hierarchy.satisfies(&["onramp:*"], "onramp:initiate"));
        assert!(hierarchy.satisfies(&["onramp:*"], "onramp:read"));
    }

    #[test]
    fn test_scope_hierarchy_transactions_write() {
        let hierarchy = ScopeHierarchy::new();

        // transactions:write should include onramp and offramp initiation
        assert!(hierarchy.satisfies(&["transactions:write"], "onramp:initiate"));
        assert!(hierarchy.satisfies(&["transactions:write"], "offramp:initiate"));
    }

    #[test]
    fn test_scope_hierarchy_multi_scope_all() {
        let hierarchy = ScopeHierarchy::new();

        let granted = vec!["wallet:read", "onramp:quote"];
        assert!(hierarchy.satisfies_all(&granted, &["wallet:read", "onramp:quote"]));
        assert!(!hierarchy.satisfies_all(&granted, &["wallet:read", "offramp:quote"]));
    }

    #[test]
    fn test_scope_hierarchy_multi_scope_any() {
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
    fn test_scope_hierarchy_resolve_multiple() {
        let hierarchy = ScopeHierarchy::new();

        let resolved = hierarchy.resolve_scopes(&["wallet:*", "onramp:quote"]);
        assert!(resolved.contains("wallet:*"));
        assert!(resolved.contains("wallet:read"));
        assert!(resolved.contains("wallet:trustline"));
        assert!(resolved.contains("onramp:quote"));
    }

    #[test]
    fn test_scope_hierarchy_get_children() {
        let hierarchy = ScopeHierarchy::new();

        let children = hierarchy.get_children("wallet:*");
        assert!(children.is_some());
        let children = children.unwrap();
        assert_eq!(children.len(), 3);

        let children = hierarchy.get_children("admin:*");
        assert!(children.is_some());
        let children = children.unwrap();
        assert_eq!(children.len(), 3);
    }

    // ── Partial Consent Tests ────────────────────────────────────────────────

    #[test]
    fn test_partial_consent_subset() {
        let hierarchy = ScopeHierarchy::new();

        // User requested: wallet:*, onramp:*, bills:*
        // User approved: wallet:read, onramp:quote (partial consent)
        let approved = vec!["wallet:read", "onramp:quote"];

        assert!(hierarchy.satisfies(&approved, "wallet:read"));
        assert!(hierarchy.satisfies(&approved, "onramp:quote"));
        assert!(!hierarchy.satisfies(&approved, "wallet:trustline"));
        assert!(!hierarchy.satisfies(&approved, "bills:pay"));
    }

    #[test]
    fn test_partial_consent_with_hierarchy() {
        let hierarchy = ScopeHierarchy::new();

        // User approved: wallet:* (includes all wallet scopes)
        let approved = vec!["wallet:*"];

        assert!(hierarchy.satisfies(&approved, "wallet:read"));
        assert!(hierarchy.satisfies(&approved, "wallet:trustline"));
        assert!(hierarchy.satisfies(&approved, "wallet:switch"));
        assert!(!hierarchy.satisfies(&approved, "onramp:quote"));
    }

    // ── Sensitive Scope Tests ────────────────────────────────────────────────

    #[test]
    fn test_sensitive_scope_identification() {
        let catalog = ScopeCatalog::with_defaults();

        // Verify sensitive scopes
        assert!(catalog.get("onramp:initiate").unwrap().is_sensitive);
        assert!(catalog.get("admin:transactions").unwrap().is_sensitive);
        assert!(catalog.get("wallet:trustline").unwrap().is_sensitive);

        // Verify non-sensitive scopes
        assert!(!catalog.get("wallet:read").unwrap().is_sensitive);
        assert!(!catalog.get("onramp:quote").unwrap().is_sensitive);
        assert!(!catalog.get("rates:read").unwrap().is_sensitive);
    }

    #[test]
    fn test_sensitive_scope_count() {
        let catalog = ScopeCatalog::with_defaults();
        let sensitive = catalog.sensitive();

        // Should have multiple sensitive scopes
        assert!(sensitive.len() > 5);

        // All should be marked as sensitive
        assert!(sensitive.iter().all(|s| s.is_sensitive));
    }

    // ── Scope Enforcement Tests ──────────────────────────────────────────────

    #[test]
    fn test_scope_enforcement_single_scope() {
        let hierarchy = ScopeHierarchy::new();

        // Token has wallet:read
        let token_scopes = vec!["wallet:read"];

        // Endpoint requires wallet:read
        assert!(hierarchy.satisfies(&token_scopes, "wallet:read"));

        // Endpoint requires wallet:trustline (should fail)
        assert!(!hierarchy.satisfies(&token_scopes, "wallet:trustline"));
    }

    #[test]
    fn test_scope_enforcement_multi_scope() {
        let hierarchy = ScopeHierarchy::new();

        // Token has wallet:read and onramp:quote
        let token_scopes = vec!["wallet:read", "onramp:quote"];

        // Endpoint requires both
        assert!(hierarchy.satisfies_all(&token_scopes, &["wallet:read", "onramp:quote"]));

        // Endpoint requires wallet:read and offramp:quote (should fail)
        assert!(!hierarchy.satisfies_all(&token_scopes, &["wallet:read", "offramp:quote"]));
    }

    #[test]
    fn test_scope_enforcement_with_wildcard() {
        let hierarchy = ScopeHierarchy::new();

        // Token has admin:*
        let token_scopes = vec!["admin:*"];

        // Endpoint requires admin:transactions
        assert!(hierarchy.satisfies(&token_scopes, "admin:transactions"));

        // Endpoint requires wallet:read (should fail)
        assert!(!hierarchy.satisfies(&token_scopes, "wallet:read"));
    }

    #[test]
    fn test_scope_enforcement_hierarchy_chain() {
        let hierarchy = ScopeHierarchy::new();

        // Token has transactions:write
        let token_scopes = vec!["transactions:write"];

        // Should satisfy onramp:initiate (via hierarchy)
        assert!(hierarchy.satisfies(&token_scopes, "onramp:initiate"));

        // Should satisfy offramp:initiate (via hierarchy)
        assert!(hierarchy.satisfies(&token_scopes, "offramp:initiate"));

        // Should NOT satisfy wallet:read
        assert!(!hierarchy.satisfies(&token_scopes, "wallet:read"));
    }

    // ── Edge Cases ───────────────────────────────────────────────────────────

    #[test]
    fn test_empty_scopes() {
        let hierarchy = ScopeHierarchy::new();

        let empty: Vec<&str> = vec![];
        assert!(!hierarchy.satisfies(&empty, "wallet:read"));
        assert!(!hierarchy.satisfies_all(&empty, &["wallet:read"]));
        assert!(!hierarchy.satisfies_any(&empty, &["wallet:read"]));
    }

    #[test]
    fn test_duplicate_scopes() {
        let hierarchy = ScopeHierarchy::new();

        // Duplicate scopes should still work
        let scopes = vec!["wallet:read", "wallet:read"];
        assert!(hierarchy.satisfies(&scopes, "wallet:read"));
    }

    #[test]
    fn test_scope_case_sensitivity() {
        let hierarchy = ScopeHierarchy::new();

        // Scopes are case-sensitive
        let scopes = vec!["wallet:read"];
        assert!(hierarchy.satisfies(&scopes, "wallet:read"));
        assert!(!hierarchy.satisfies(&scopes, "Wallet:Read"));
    }
}
