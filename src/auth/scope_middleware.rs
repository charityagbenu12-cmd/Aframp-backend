//! OAuth 2.0 Scope Enforcement Middleware
//!
//! Validates that requests have required scopes before allowing access.
//! Supports single scope, multi-scope (ALL), and scope hierarchy.

use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use std::sync::Arc;

use super::oauth_scope::ScopeHierarchy;
use super::oauth_token_validator::OAuthTokenClaims;

// ── Scope Requirement ────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum ScopeRequirement {
    /// Single scope required
    Single(String),
    /// All scopes required
    All(Vec<String>),
    /// Any scope required
    Any(Vec<String>),
}

impl ScopeRequirement {
    pub fn single(scope: &str) -> Self {
        ScopeRequirement::Single(scope.to_string())
    }

    pub fn all(scopes: Vec<&str>) -> Self {
        ScopeRequirement::All(scopes.iter().map(|s| s.to_string()).collect())
    }

    pub fn any(scopes: Vec<&str>) -> Self {
        ScopeRequirement::Any(scopes.iter().map(|s| s.to_string()).collect())
    }
}

// ── Scope Enforcement State ──────────────────────────────────────────────────

#[derive(Clone)]
pub struct ScopeEnforcementState {
    pub hierarchy: Arc<ScopeHierarchy>,
}

impl ScopeEnforcementState {
    pub fn new() -> Self {
        Self {
            hierarchy: Arc::new(ScopeHierarchy::new()),
        }
    }
}

impl Default for ScopeEnforcementState {
    fn default() -> Self {
        Self::new()
    }
}

// ── Scope Enforcement Error ──────────────────────────────────────────────────

#[derive(Debug)]
pub struct ScopeEnforcementError {
    pub required_scope: String,
    pub granted_scopes: String,
}

impl ScopeEnforcementError {
    pub fn response(&self) -> Response {
        (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "insufficient_scope",
                "error_description": "The request requires scopes that were not granted",
                "required_scope": self.required_scope,
                "granted_scopes": self.granted_scopes,
            })),
        )
            .into_response()
    }
}

// ── Scope Enforcement Middleware ─────────────────────────────────────────────

/// Middleware factory for scope enforcement
pub fn require_scope(requirement: ScopeRequirement) -> impl Fn(Request, Next) -> futures::future::BoxFuture<'static, Response> + Clone {
    move |mut req: Request, next: Next| {
        let requirement = requirement.clone();
        Box::pin(async move {
            // Extract claims from extensions (set by token validator)
            let claims = match req.extensions().get::<OAuthTokenClaims>() {
                Some(c) => c.clone(),
                None => {
                    return (
                        StatusCode::UNAUTHORIZED,
                        Json(json!({
                            "error": "missing_token",
                            "error_description": "No valid token found"
                        })),
                    )
                        .into_response();
                }
            };

            // Parse granted scopes
            let granted_scopes: Vec<&str> = claims.scope.split_whitespace().collect();

            // Get hierarchy from state (if available)
            let hierarchy = ScopeHierarchy::new();

            // Check scope requirement
            let has_required_scope = match &requirement {
                ScopeRequirement::Single(scope) => {
                    hierarchy.satisfies(&granted_scopes, scope)
                }
                ScopeRequirement::All(scopes) => {
                    let scope_refs: Vec<&str> = scopes.iter().map(|s| s.as_str()).collect();
                    hierarchy.satisfies_all(&granted_scopes, &scope_refs)
                }
                ScopeRequirement::Any(scopes) => {
                    let scope_refs: Vec<&str> = scopes.iter().map(|s| s.as_str()).collect();
                    hierarchy.satisfies_any(&granted_scopes, &scope_refs)
                }
            };

            if !has_required_scope {
                let required_scope = match &requirement {
                    ScopeRequirement::Single(s) => s.clone(),
                    ScopeRequirement::All(scopes) => scopes.join(" "),
                    ScopeRequirement::Any(scopes) => scopes.join(" OR "),
                };

                let error = ScopeEnforcementError {
                    required_scope,
                    granted_scopes: claims.scope.clone(),
                };

                // Log scope denial
                tracing::warn!(
                    jti = %claims.jti,
                    consumer_id = %claims.sub,
                    client_id = %claims.client_id,
                    required_scope = %error.required_scope,
                    granted_scopes = %error.granted_scopes,
                    "scope enforcement denied"
                );

                return error.response();
            }

            // Log scope approval
            tracing::debug!(
                jti = %claims.jti,
                consumer_id = %claims.sub,
                client_id = %claims.client_id,
                scopes = %claims.scope,
                "scope enforcement approved"
            );

            next.run(req).await
        })
    }
}

/// Middleware for single scope requirement
pub async fn require_single_scope(
    State(_state): State<ScopeEnforcementState>,
    scope: String,
    mut req: Request,
    next: Next,
) -> Response {
    let claims = match req.extensions().get::<OAuthTokenClaims>() {
        Some(c) => c.clone(),
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "error": "missing_token",
                    "error_description": "No valid token found"
                })),
            )
                .into_response();
        }
    };

    let granted_scopes: Vec<&str> = claims.scope.split_whitespace().collect();
    let hierarchy = ScopeHierarchy::new();

    if !hierarchy.satisfies(&granted_scopes, &scope) {
        let error = ScopeEnforcementError {
            required_scope: scope,
            granted_scopes: claims.scope.clone(),
        };

        tracing::warn!(
            jti = %claims.jti,
            consumer_id = %claims.sub,
            client_id = %claims.client_id,
            required_scope = %error.required_scope,
            granted_scopes = %error.granted_scopes,
            "scope enforcement denied"
        );

        return error.response();
    }

    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scope_requirement_single() {
        let req = ScopeRequirement::single("wallet:read");
        match req {
            ScopeRequirement::Single(s) => assert_eq!(s, "wallet:read"),
            _ => panic!("Expected Single"),
        }
    }

    #[test]
    fn test_scope_requirement_all() {
        let req = ScopeRequirement::all(vec!["wallet:read", "onramp:quote"]);
        match req {
            ScopeRequirement::All(scopes) => assert_eq!(scopes.len(), 2),
            _ => panic!("Expected All"),
        }
    }

    #[test]
    fn test_scope_requirement_any() {
        let req = ScopeRequirement::any(vec!["wallet:read", "onramp:quote"]);
        match req {
            ScopeRequirement::Any(scopes) => assert_eq!(scopes.len(), 2),
            _ => panic!("Expected Any"),
        }
    }

    #[test]
    fn test_scope_enforcement_error() {
        let error = ScopeEnforcementError {
            required_scope: "wallet:read".to_string(),
            granted_scopes: "onramp:quote".to_string(),
        };

        let response = error.response();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn test_scope_enforcement_state() {
        let state = ScopeEnforcementState::new();
        assert!(state.hierarchy.satisfies(&["wallet:*"], "wallet:read"));
    }
}
