//! OAuth 2.0 Authorization Server for Aframp API.
//!
//! Implements:
//!   - Authorization Code + PKCE (RFC 7636)
//!   - Client Credentials
//!   - Refresh Token with rotation
//!   - RS256 JWT access tokens
//!   - JWKS endpoint for stateless verification
//!   - OpenID Connect discovery document
//!   - RFC 7662 token introspection
//!   - RFC 7009 token revocation
//!   - Admin + developer client registration

#[cfg(feature = "database")]
pub mod client_store;
#[cfg(feature = "database")]
pub mod handlers;
#[cfg(feature = "database")]
pub mod keys;
#[cfg(feature = "database")]
pub mod pkce;
#[cfg(feature = "database")]
pub mod token;
#[cfg(feature = "database")]
pub mod types;

#[cfg(all(test, feature = "database"))]
mod tests;

#[cfg(feature = "database")]
pub use handlers::OAuthState;
#[cfg(feature = "database")]
pub use keys::RsaKeyPair;
#[cfg(feature = "database")]
pub use types::OAuthError;

#[cfg(feature = "database")]
use axum::{routing::{get, post}, Router};
#[cfg(feature = "database")]
use std::sync::Arc;

/// Build and return the OAuth 2.0 router.
///
/// Mount this at the root — routes are already fully qualified.
#[cfg(feature = "database")]
pub fn oauth_router(state: Arc<OAuthState>) -> Router {
    Router::new()
        // Authorization endpoint
        .route("/oauth/authorize", get(handlers::authorize))
        // Token endpoint
        .route("/oauth/token", post(handlers::token_endpoint))
        // Introspection
        .route("/oauth/token/introspect", post(handlers::introspect_token))
        // Revocation
        .route("/oauth/token/revoke", post(handlers::revoke_token))
        // JWKS
        .route("/oauth/.well-known/jwks.json", get(handlers::jwks))
        // Discovery
        .route("/oauth/.well-known/openid-configuration", get(handlers::discovery))
        // Client registration
        .route("/api/admin/oauth/clients", post(handlers::admin_register_client))
        .route("/api/developer/oauth/clients", post(handlers::developer_register_client))
        .with_state(state)
}
