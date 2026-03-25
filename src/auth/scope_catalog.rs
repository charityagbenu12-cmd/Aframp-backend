//! OAuth 2.0 Scope Catalogue
//!
//! Defines all available scopes with metadata and hierarchy.
//! Uses resource:action naming convention.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ── Scope Category ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[serde(rename_all = "lowercase")]
pub enum ScopeCategory {
    Onramp,
    Offramp,
    Bills,
    Wallet,
    Rates,
    Transactions,
    Webhooks,
    Batch,
    Recurring,
    Analytics,
    Admin,
    Microservice,
}

impl ScopeCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            ScopeCategory::Onramp => "onramp",
            ScopeCategory::Offramp => "offramp",
            ScopeCategory::Bills => "bills",
            ScopeCategory::Wallet => "wallet",
            ScopeCategory::Rates => "rates",
            ScopeCategory::Transactions => "transactions",
            ScopeCategory::Webhooks => "webhooks",
            ScopeCategory::Batch => "batch",
            ScopeCategory::Recurring => "recurring",
            ScopeCategory::Analytics => "analytics",
            ScopeCategory::Admin => "admin",
            ScopeCategory::Microservice => "microservice",
        }
    }
}

// ── Scope Definition ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeDefinition {
    pub name: String,
    pub description: String,
    pub category: ScopeCategory,
    pub is_sensitive: bool,
}

impl ScopeDefinition {
    pub fn new(
        name: &str,
        description: &str,
        category: ScopeCategory,
        is_sensitive: bool,
    ) -> Self {
        Self {
            name: name.to_string(),
            description: description.to_string(),
            category,
            is_sensitive,
        }
    }

    /// Validate scope name format (resource:action)
    pub fn validate_format(name: &str) -> Result<(), String> {
        let parts: Vec<&str> = name.split(':').collect();

        if parts.len() != 2 {
            return Err("Scope must be in format 'resource:action'".to_string());
        }

        if parts[0].is_empty() || parts[1].is_empty() {
            return Err("Resource and action cannot be empty".to_string());
        }

        // Allow wildcards only in action part
        if parts[0].contains('*') {
            return Err("Wildcards only allowed in action part (e.g., 'admin:*')".to_string());
        }

        Ok(())
    }
}

// ── Scope Catalogue ─────────────────────────────────────────────────────────

pub struct ScopeCatalog {
    scopes: HashMap<String, ScopeDefinition>,
}

impl ScopeCatalog {
    pub fn new() -> Self {
        Self {
            scopes: HashMap::new(),
        }
    }

    /// Initialize with all default scopes
    pub fn with_defaults() -> Self {
        let mut catalog = Self::new();
        catalog.seed_defaults();
        catalog
    }

    /// Get all scopes
    pub fn all(&self) -> Vec<ScopeDefinition> {
        self.scopes.values().cloned().collect()
    }

    /// Get scope by name
    pub fn get(&self, name: &str) -> Option<ScopeDefinition> {
        self.scopes.get(name).cloned()
    }

    /// Get scopes by category
    pub fn by_category(&self, category: ScopeCategory) -> Vec<ScopeDefinition> {
        self.scopes
            .values()
            .filter(|s| s.category == category)
            .cloned()
            .collect()
    }

    /// Get all sensitive scopes
    pub fn sensitive(&self) -> Vec<ScopeDefinition> {
        self.scopes
            .values()
            .filter(|s| s.is_sensitive)
            .cloned()
            .collect()
    }

    /// Add scope to catalogue
    pub fn add(&mut self, scope: ScopeDefinition) -> Result<(), String> {
        ScopeDefinition::validate_format(&scope.name)?;

        if self.scopes.contains_key(&scope.name) {
            return Err(format!("Scope '{}' already exists", scope.name));
        }

        self.scopes.insert(scope.name.clone(), scope);
        Ok(())
    }

    /// Update scope
    pub fn update(&mut self, name: &str, scope: ScopeDefinition) -> Result<(), String> {
        if !self.scopes.contains_key(name) {
            return Err(format!("Scope '{}' not found", name));
        }

        self.scopes.insert(name.to_string(), scope);
        Ok(())
    }

    /// Seed default scopes (idempotent)
    pub fn seed_defaults(&mut self) {
        let defaults = vec![
            // Onramp scopes
            ScopeDefinition::new(
                "onramp:quote",
                "Get onramp quotes",
                ScopeCategory::Onramp,
                false,
            ),
            ScopeDefinition::new(
                "onramp:initiate",
                "Initiate onramp transactions",
                ScopeCategory::Onramp,
                true,
            ),
            ScopeDefinition::new(
                "onramp:read",
                "Read onramp transaction history",
                ScopeCategory::Onramp,
                false,
            ),
            // Offramp scopes
            ScopeDefinition::new(
                "offramp:quote",
                "Get offramp quotes",
                ScopeCategory::Offramp,
                false,
            ),
            ScopeDefinition::new(
                "offramp:initiate",
                "Initiate offramp transactions",
                ScopeCategory::Offramp,
                true,
            ),
            ScopeDefinition::new(
                "offramp:read",
                "Read offramp transaction history",
                ScopeCategory::Offramp,
                false,
            ),
            // Bills scopes
            ScopeDefinition::new("bills:read", "Read bills", ScopeCategory::Bills, false),
            ScopeDefinition::new("bills:pay", "Pay bills", ScopeCategory::Bills, true),
            // Wallet scopes
            ScopeDefinition::new(
                "wallet:read",
                "Read wallet information",
                ScopeCategory::Wallet,
                false,
            ),
            ScopeDefinition::new(
                "wallet:trustline",
                "Manage wallet trustlines",
                ScopeCategory::Wallet,
                true,
            ),
            ScopeDefinition::new(
                "wallet:switch",
                "Switch wallet",
                ScopeCategory::Wallet,
                true,
            ),
            // Rates scopes
            ScopeDefinition::new(
                "rates:read",
                "Read exchange rates",
                ScopeCategory::Rates,
                false,
            ),
            // Transactions scopes
            ScopeDefinition::new(
                "transactions:read",
                "Read transaction history",
                ScopeCategory::Transactions,
                false,
            ),
            // Webhooks scopes
            ScopeDefinition::new(
                "webhooks:read",
                "Read webhooks",
                ScopeCategory::Webhooks,
                false,
            ),
            ScopeDefinition::new(
                "webhooks:manage",
                "Manage webhooks",
                ScopeCategory::Webhooks,
                true,
            ),
            // Batch scopes
            ScopeDefinition::new(
                "batch:cngn-transfer",
                "Batch CNGN transfers",
                ScopeCategory::Batch,
                true,
            ),
            ScopeDefinition::new(
                "batch:fiat-payout",
                "Batch fiat payouts",
                ScopeCategory::Batch,
                true,
            ),
            // Recurring scopes
            ScopeDefinition::new(
                "recurring:read",
                "Read recurring payments",
                ScopeCategory::Recurring,
                false,
            ),
            ScopeDefinition::new(
                "recurring:manage",
                "Manage recurring payments",
                ScopeCategory::Recurring,
                true,
            ),
            // Analytics scopes
            ScopeDefinition::new(
                "analytics:read",
                "Read analytics",
                ScopeCategory::Analytics,
                false,
            ),
            // Admin scopes
            ScopeDefinition::new(
                "admin:transactions",
                "Manage transactions",
                ScopeCategory::Admin,
                true,
            ),
            ScopeDefinition::new(
                "admin:consumers",
                "Manage consumers",
                ScopeCategory::Admin,
                true,
            ),
            ScopeDefinition::new(
                "admin:config",
                "Manage configuration",
                ScopeCategory::Admin,
                true,
            ),
            // Microservice scopes
            ScopeDefinition::new(
                "microservice:internal",
                "Internal microservice communication",
                ScopeCategory::Microservice,
                false,
            ),
        ];

        for scope in defaults {
            // Ignore if already exists (idempotent)
            let _ = self.add(scope);
        }
    }
}

impl Default for ScopeCatalog {
    fn default() -> Self {
        Self::with_defaults()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scope_format_validation() {
        assert!(ScopeDefinition::validate_format("wallet:read").is_ok());
        assert!(ScopeDefinition::validate_format("admin:*").is_ok());
        assert!(ScopeDefinition::validate_format("invalid").is_err());
        assert!(ScopeDefinition::validate_format("*:read").is_err());
        assert!(ScopeDefinition::validate_format(":read").is_err());
    }

    #[test]
    fn test_scope_catalog_creation() {
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
    }

    #[test]
    fn test_scope_catalog_sensitive() {
        let catalog = ScopeCatalog::with_defaults();
        let sensitive = catalog.sensitive();
        assert!(!sensitive.is_empty());
        assert!(sensitive.iter().all(|s| s.is_sensitive));
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
        assert!(catalog.add(scope).is_err()); // Duplicate
    }
}
