//! OAuth 2.0 Scope Definition and Management
//!
//! Implements:
//! - Scope catalogue with hierarchy
//! - Scope persistence and management
//! - Scope validation and enforcement
//! - Sensitive scope handling

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

// ── Scope Categories ─────────────────────────────────────────────────────────

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

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "onramp" => Some(ScopeCategory::Onramp),
            "offramp" => Some(ScopeCategory::Offramp),
            "bills" => Some(ScopeCategory::Bills),
            "wallet" => Some(ScopeCategory::Wallet),
            "rates" => Some(ScopeCategory::Rates),
            "transactions" => Some(ScopeCategory::Transactions),
            "webhooks" => Some(ScopeCategory::Webhooks),
            "batch" => Some(ScopeCategory::Batch),
            "recurring" => Some(ScopeCategory::Recurring),
            "analytics" => Some(ScopeCategory::Analytics),
            "admin" => Some(ScopeCategory::Admin),
            "microservice" => Some(ScopeCategory::Microservice),
            _ => None,
        }
    }
}

// ── OAuth Scope Definition ───────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthScope {
    pub id: String,
    pub name: String,
    pub description: String,
    pub category: ScopeCategory,
    pub is_sensitive: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl OAuthScope {
    pub fn new(
        name: String,
        description: String,
        category: ScopeCategory,
        is_sensitive: bool,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4().to_string(),
            name,
            description,
            category,
            is_sensitive,
            created_at: now,
            updated_at: now,
        }
    }

    /// Validate scope name format (resource:action)
    pub fn validate_name(name: &str) -> Result<(), ScopeError> {
        let parts: Vec<&str> = name.split(':').collect();

        if parts.len() != 2 {
            return Err(ScopeError::InvalidFormat {
                scope: name.to_string(),
                reason: "must be in format 'resource:action'".to_string(),
            });
        }

        if parts[0].is_empty() || parts[1].is_empty() {
            return Err(ScopeError::InvalidFormat {
                scope: name.to_string(),
                reason: "resource and action cannot be empty".to_string(),
            });
        }

        // Allow wildcards only in action part
        if parts[0].contains('*') {
            return Err(ScopeError::InvalidFormat {
                scope: name.to_string(),
                reason: "wildcards only allowed in action part".to_string(),
            });
        }

        Ok(())
    }
}

// ── Scope Hierarchy ──────────────────────────────────────────────────────────

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

        Self { hierarchy }
    }

    /// Resolve all scopes including parent scopes
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
}

impl Default for ScopeHierarchy {
    fn default() -> Self {
        Self::new()
    }
}

// ── Scope Catalogue ──────────────────────────────────────────────────────────

pub struct ScopeCatalogue {
    scopes: HashMap<String, OAuthScope>,
}

impl ScopeCatalogue {
    pub fn new() -> Self {
        Self {
            scopes: HashMap::new(),
        }
    }

    /// Get all scopes in the catalogue
    pub fn all(&self) -> Vec<OAuthScope> {
        self.scopes.values().cloned().collect()
    }

    /// Get scope by name
    pub fn get(&self, name: &str) -> Option<OAuthScope> {
        self.scopes.get(name).cloned()
    }

    /// Add scope to catalogue
    pub fn add(&mut self, scope: OAuthScope) -> Result<(), ScopeError> {
        OAuthScope::validate_name(&scope.name)?;

        if self.scopes.contains_key(&scope.name) {
            return Err(ScopeError::AlreadyExists {
                scope: scope.name,
            });
        }

        self.scopes.insert(scope.name.clone(), scope);
        Ok(())
    }

    /// Update scope
    pub fn update(&mut self, name: &str, scope: OAuthScope) -> Result<(), ScopeError> {
        if !self.scopes.contains_key(name) {
            return Err(ScopeError::NotFound {
                scope: name.to_string(),
            });
        }

        self.scopes.insert(name.to_string(), scope);
        Ok(())
    }

    /// Get scopes by category
    pub fn by_category(&self, category: ScopeCategory) -> Vec<OAuthScope> {
        self.scopes
            .values()
            .filter(|s| s.category == category)
            .cloned()
            .collect()
    }

    /// Get sensitive scopes
    pub fn sensitive(&self) -> Vec<OAuthScope> {
        self.scopes
            .values()
            .filter(|s| s.is_sensitive)
            .cloned()
            .collect()
    }

    /// Seed default scopes
    pub fn seed_defaults(&mut self) -> Result<(), ScopeError> {
        let default_scopes = vec![
            // Onramp scopes
            OAuthScope::new(
                "onramp:quote".to_string(),
                "Get onramp quotes".to_string(),
                ScopeCategory::Onramp,
                false,
            ),
            OAuthScope::new(
                "onramp:initiate".to_string(),
                "Initiate onramp transactions".to_string(),
                ScopeCategory::Onramp,
                true,
            ),
            OAuthScope::new(
                "onramp:read".to_string(),
                "Read onramp transaction history".to_string(),
                ScopeCategory::Onramp,
                false,
            ),
            // Offramp scopes
            OAuthScope::new(
                "offramp:quote".to_string(),
                "Get offramp quotes".to_string(),
                ScopeCategory::Offramp,
                false,
            ),
            OAuthScope::new(
                "offramp:initiate".to_string(),
                "Initiate offramp transactions".to_string(),
                ScopeCategory::Offramp,
                true,
            ),
            OAuthScope::new(
                "offramp:read".to_string(),
                "Read offramp transaction history".to_string(),
                ScopeCategory::Offramp,
                false,
            ),
            // Bills scopes
            OAuthScope::new(
                "bills:read".to_string(),
                "Read bills".to_string(),
                ScopeCategory::Bills,
                false,
            ),
            OAuthScope::new(
                "bills:pay".to_string(),
                "Pay bills".to_string(),
                ScopeCategory::Bills,
                true,
            ),
            // Wallet scopes
            OAuthScope::new(
                "wallet:read".to_string(),
                "Read wallet information".to_string(),
                ScopeCategory::Wallet,
                false,
            ),
            OAuthScope::new(
                "wallet:trustline".to_string(),
                "Manage wallet trustlines".to_string(),
                ScopeCategory::Wallet,
                true,
            ),
            OAuthScope::new(
                "wallet:switch".to_string(),
                "Switch wallet".to_string(),
                ScopeCategory::Wallet,
                true,
            ),
            // Rates scopes
            OAuthScope::new(
                "rates:read".to_string(),
                "Read exchange rates".to_string(),
                ScopeCategory::Rates,
                false,
            ),
            // Transactions scopes
            OAuthScope::new(
                "transactions:read".to_string(),
                "Read transaction history".to_string(),
                ScopeCategory::Transactions,
                false,
            ),
            // Webhooks scopes
            OAuthScope::new(
                "webhooks:read".to_string(),
                "Read webhooks".to_string(),
                ScopeCategory::Webhooks,
                false,
            ),
            OAuthScope::new(
                "webhooks:manage".to_string(),
                "Manage webhooks".to_string(),
                ScopeCategory::Webhooks,
                true,
            ),
            // Batch scopes
            OAuthScope::new(
                "batch:cngn-transfer".to_string(),
                "Batch CNGN transfers".to_string(),
                ScopeCategory::Batch,
                true,
            ),
            OAuthScope::new(
                "batch:fiat-payout".to_string(),
                "Batch fiat payouts".to_string(),
                ScopeCategory::Batch,
                true,
            ),
            // Recurring scopes
            OAuthScope::new(
                "recurring:read".to_string(),
                "Read recurring payments".to_string(),
                ScopeCategory::Recurring,
                false,
            ),
            OAuthScope::new(
                "recurring:manage".to_string(),
                "Manage recurring payments".to_string(),
                ScopeCategory::Recurring,
                true,
            ),
            // Analytics scopes
            OAuthScope::new(
                "analytics:read".to_string(),
                "Read analytics".to_string(),
                ScopeCategory::Analytics,
                false,
            ),
            // Admin scopes
            OAuthScope::new(
                "admin:transactions".to_string(),
                "Manage transactions".to_string(),
                ScopeCategory::Admin,
                true,
            ),
            OAuthScope::new(
                "admin:consumers".to_string(),
                "Manage consumers".to_string(),
                ScopeCategory::Admin,
                true,
            ),
            OAuthScope::new(
                "admin:config".to_string(),
                "Manage configuration".to_string(),
                ScopeCategory::Admin,
                true,
            ),
            // Microservice scopes
            OAuthScope::new(
                "microservice:internal".to_string(),
                "Internal microservice communication".to_string(),
                ScopeCategory::Microservice,
                false,
            ),
        ];

        for scope in default_scopes {
            // Ignore if already exists (idempotent)
            let _ = self.add(scope);
        }

        Ok(())
    }
}

impl Default for ScopeCatalogue {
    fn default() -> Self {
        Self::new()
    }
}

// ── Error Types ──────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum ScopeError {
    #[error("invalid scope format: {scope} - {reason}")]
    InvalidFormat { scope: String, reason: String },
    #[error("scope already exists: {scope}")]
    AlreadyExists { scope: String },
    #[error("scope not found: {scope}")]
    NotFound { scope: String },
    #[error("insufficient scope: required {required}, got {got}")]
    InsufficientScope { required: String, got: String },
    #[error("internal error: {0}")]
    Internal(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scope_validation() {
        assert!(OAuthScope::validate_name("wallet:read").is_ok());
        assert!(OAuthScope::validate_name("admin:*").is_ok());
        assert!(OAuthScope::validate_name("invalid").is_err());
        assert!(OAuthScope::validate_name("*:read").is_err());
    }

    #[test]
    fn test_scope_hierarchy_resolution() {
        let hierarchy = ScopeHierarchy::new();

        // transactions:write should include onramp:initiate
        assert!(hierarchy.satisfies(&["transactions:write"], "onramp:initiate"));

        // admin:* should include admin:transactions
        assert!(hierarchy.satisfies(&["admin:*"], "admin:transactions"));

        // wallet:* should include wallet:read
        assert!(hierarchy.satisfies(&["wallet:*"], "wallet:read"));
    }

    #[test]
    fn test_scope_hierarchy_multi_scope() {
        let hierarchy = ScopeHierarchy::new();

        let granted = vec!["wallet:read", "onramp:quote"];
        assert!(hierarchy.satisfies_all(&granted, &["wallet:read", "onramp:quote"]));
        assert!(!hierarchy.satisfies_all(&granted, &["wallet:read", "offramp:quote"]));
    }

    #[test]
    fn test_scope_catalogue() {
        let mut catalogue = ScopeCatalogue::new();

        let scope = OAuthScope::new(
            "test:read".to_string(),
            "Test scope".to_string(),
            ScopeCategory::Wallet,
            false,
        );

        assert!(catalogue.add(scope.clone()).is_ok());
        assert!(catalogue.get("test:read").is_some());
        assert!(catalogue.add(scope).is_err()); // Duplicate
    }

    #[test]
    fn test_scope_catalogue_seed() {
        let mut catalogue = ScopeCatalogue::new();
        assert!(catalogue.seed_defaults().is_ok());
        assert!(catalogue.get("wallet:read").is_some());
        assert!(catalogue.get("admin:transactions").is_some());
    }

    #[test]
    fn test_scope_catalogue_by_category() {
        let mut catalogue = ScopeCatalogue::new();
        let _ = catalogue.seed_defaults();

        let wallet_scopes = catalogue.by_category(ScopeCategory::Wallet);
        assert!(!wallet_scopes.is_empty());
        assert!(wallet_scopes.iter().all(|s| s.category == ScopeCategory::Wallet));
    }

    #[test]
    fn test_scope_catalogue_sensitive() {
        let mut catalogue = ScopeCatalogue::new();
        let _ = catalogue.seed_defaults();

        let sensitive = catalogue.sensitive();
        assert!(!sensitive.is_empty());
        assert!(sensitive.iter().all(|s| s.is_sensitive));
    }
}
