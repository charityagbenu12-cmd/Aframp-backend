//! JWT-based authentication module for Aframp API.
//!
//! Provides:
//! - `jwt`                    – token generation, validation, Redis storage helpers
//! - `oauth_token_service`    – OAuth 2.0 access token issuance with RS256
//! - `oauth_token_validator`  – Stateless token validation with JWKS
//! - `jwks_service`           – JWKS key management and caching
//! - `token_limiter`          – Rate limiting for token issuance
//! - `middleware`             – Axum middleware (`require_auth`, `require_admin`)
//! - `handlers`               – HTTP handlers for /api/auth/{token,refresh,revoke}
//! - `routes`                 – Router builder

#[cfg(feature = "database")]
pub mod handlers;
#[cfg(feature = "database")]
pub mod jwt;
#[cfg(feature = "database")]
pub mod middleware;
#[cfg(feature = "database")]
pub mod oauth_token_service;
#[cfg(feature = "database")]
pub mod oauth_token_validator;
#[cfg(feature = "database")]
pub mod jwks_service;
#[cfg(feature = "database")]
pub mod token_limiter;
#[cfg(feature = "database")]
pub mod scope_catalog;
#[cfg(feature = "database")]
pub mod scope_hierarchy;
#[cfg(feature = "database")]
pub mod refresh_token_service;
#[cfg(feature = "database")]
pub mod refresh_token_validator;
#[cfg(test)]
pub mod oauth_tests;
#[cfg(test)]
pub mod scope_tests;
#[cfg(test)]
pub mod refresh_token_tests;

#[cfg(feature = "database")]
pub use handlers::AuthHandlerState;
#[cfg(feature = "database")]
pub use jwt::{JwtConfig, JwtError, Scope, TokenClaims, TokenType};
#[cfg(feature = "database")]
pub use middleware::AuthState;
#[cfg(feature = "database")]
pub use oauth_token_service::{
    ConsumerType, Environment, OAuthTokenClaims, OAuthTokenError, OAuthTokenService,
    TokenIssuanceRequest, TokenIssuanceResponse, TokenRegistryRecord,
};
#[cfg(feature = "database")]
pub use oauth_token_validator::{OAuthTokenValidator, TokenValidationError, ValidationContext};
#[cfg(feature = "database")]
pub use jwks_service::{JwksError, JwksKey, JwksService};
#[cfg(feature = "database")]
pub use token_limiter::{RateLimitConfig, RateLimitError, TokenRateLimiter};
#[cfg(feature = "database")]
pub use scope_catalog::{ScopeCatalog, ScopeCategory, ScopeDefinition};
#[cfg(feature = "database")]
pub use scope_hierarchy::ScopeHierarchy;
#[cfg(feature = "database")]
pub use refresh_token_service::{
    RefreshTokenError, RefreshTokenMetadata, RefreshTokenRequest, RefreshTokenResponse,
    RefreshTokenService, RefreshTokenStatus,
};
#[cfg(feature = "database")]
pub use refresh_token_validator::{
    RefreshTokenValidator, RefreshTokenValidationContext, RefreshTokenValidationResult,
};

#[cfg(feature = "database")]
use axum::{routing::post, Router};
#[cfg(feature = "database")]
use std::sync::Arc;

/// Build the auth router and mount it at `/api/auth`.
#[cfg(feature = "database")]
pub fn auth_router(state: Arc<AuthHandlerState>) -> Router {
    Router::new()
        .route("/api/auth/token", post(handlers::generate_token))
        .route("/api/auth/refresh", post(handlers::refresh_token))
        .route("/api/auth/revoke", post(handlers::revoke_token))
        .with_state(state)
}
