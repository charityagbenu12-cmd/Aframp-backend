# OAuth 2.0 Token System - Implementation Guide

Step-by-step guide to integrate the OAuth 2.0 access token system into the Aframp backend.

## 📋 Prerequisites

- Rust 1.70+
- PostgreSQL 12+
- Redis 6+
- RS256 key pair (private + public)

## 🔧 Step 1: Generate RS256 Key Pair

Generate a new RS256 key pair for token signing:

```bash
# Generate private key
openssl genrsa -out private_key.pem 2048

# Extract public key
openssl rsa -in private_key.pem -pubout -out public_key.pem

# Verify keys
openssl rsa -in private_key.pem -text -noout
openssl rsa -pubin -in public_key.pem -text -noout
```

Store the private key securely (e.g., AWS Secrets Manager, HashiCorp Vault).

## 🗄️ Step 2: Run Database Migration

```bash
# Apply migration
sqlx migrate run --database-url "postgresql://user:password@localhost/aframp"

# Verify table creation
psql -U user -d aframp -c "\dt token_registry"
```

The migration creates:
- `token_registry` table with JTI tracking
- Indexes for efficient queries
- Constraints for data integrity

## 🔌 Step 3: Update Configuration

Add environment variables to `.env`:

```bash
# OAuth 2.0 Configuration
OAUTH_ISSUER_URL=https://api.aframp.com
OAUTH_API_AUDIENCE=api
OAUTH_PRIVATE_KEY_PEM="-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----"
OAUTH_KEY_ID=key_id_123
OAUTH_JWKS_URL=https://auth.aframp.com/.well-known/jwks.json
OAUTH_JWKS_REFRESH_INTERVAL_SECS=3600

# Rate Limiting
OAUTH_MAX_ACTIVE_TOKENS_PER_CONSUMER=10
OAUTH_MAX_ISSUANCE_PER_CLIENT_PER_WINDOW=100
OAUTH_RATE_LIMIT_WINDOW_SECS=60
```

## 📦 Step 4: Update Dependencies

Ensure `Cargo.toml` includes required crates (already present):

```toml
[dependencies]
jsonwebtoken = "9.2.0"
chrono = { version = "0.4", features = ["serde"] }
uuid = { version = "1.6", features = ["v4", "serde"] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
tokio = { version = "1.36", features = ["full"] }
redis = { version = "1.0.2", features = ["tokio-comp", "connection-manager"] }
reqwest = { version = "0.13.1", features = ["json"] }
```

## 🏗️ Step 5: Initialize Services in Main

Update `src/main.rs` to initialize OAuth services:

```rust
use std::sync::Arc;
use aframp_backend::auth::{
    OAuthTokenService, OAuthTokenValidator, JwksService, TokenRateLimiter, RateLimitConfig,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // ... existing setup ...

    // Load configuration
    let issuer_url = std::env::var("OAUTH_ISSUER_URL")?;
    let api_audience = std::env::var("OAUTH_API_AUDIENCE")?;
    let private_key_pem = std::env::var("OAUTH_PRIVATE_KEY_PEM")?;
    let key_id = std::env::var("OAUTH_KEY_ID")?;
    let jwks_url = std::env::var("OAUTH_JWKS_URL")?;
    let jwks_refresh_interval = std::env::var("OAUTH_JWKS_REFRESH_INTERVAL_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3600);

    // Initialize OAuth services
    let token_service = Arc::new(OAuthTokenService::new(
        issuer_url.clone(),
        api_audience.clone(),
        private_key_pem,
        key_id,
        db_pool.clone(),
        redis_cache.clone(),
    ));

    let public_key_pem = std::env::var("OAUTH_PUBLIC_KEY_PEM")?;
    let token_validator = Arc::new(OAuthTokenValidator::new(
        public_key_pem,
        redis_cache.clone(),
    ));

    let jwks_service = Arc::new(JwksService::new(jwks_url, jwks_refresh_interval));
    jwks_service.clone().start_refresh_task();

    let rate_limit_config = RateLimitConfig {
        max_active_tokens_per_consumer: std::env::var("OAUTH_MAX_ACTIVE_TOKENS_PER_CONSUMER")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(10),
        max_issuance_per_client_per_window: std::env::var("OAUTH_MAX_ISSUANCE_PER_CLIENT_PER_WINDOW")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(100),
        rate_limit_window_secs: std::env::var("OAUTH_RATE_LIMIT_WINDOW_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(60),
    };

    let token_limiter = Arc::new(TokenRateLimiter::new(
        redis_cache.clone(),
        rate_limit_config,
    ));

    // Add to app state
    let app_state = AppState {
        db_pool,
        redis_cache,
        token_service,
        token_validator,
        jwks_service,
        token_limiter,
        // ... other fields ...
    };

    // ... rest of setup ...
}
```

## 🛣️ Step 6: Create API Endpoints

Create `src/api/oauth.rs` for token endpoints:

```rust
use axum::{
    extract::{State, ConnectInfo},
    http::StatusCode,
    Json,
};
use serde_json::json;
use std::net::SocketAddr;

use crate::auth::{
    OAuthTokenService, TokenIssuanceRequest, ConsumerType, Environment,
};

#[derive(serde::Deserialize)]
pub struct TokenRequest {
    pub consumer_id: String,
    pub client_id: String,
    pub consumer_type: String,
    pub scope: String,
    pub environment: String,
    pub requested_ttl_secs: Option<i64>,
}

pub async fn issue_token(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(req): Json<TokenRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    // Parse consumer type
    let consumer_type = match req.consumer_type.as_str() {
        "mobile_client" => ConsumerType::MobileClient,
        "partner" => ConsumerType::Partner,
        "microservice" => ConsumerType::Microservice,
        "admin" => ConsumerType::Admin,
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "invalid_consumer_type"
                })),
            ))
        }
    };

    // Parse environment
    let environment = match req.environment.as_str() {
        "testnet" => Environment::Testnet,
        "mainnet" => Environment::Mainnet,
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "invalid_environment"
                })),
            ))
        }
    };

    // Check rate limits
    if !state.token_limiter.check_consumer_limit(&req.consumer_id).await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "internal_error"}))))?
    {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({
                "error": "rate_limit_exceeded",
                "error_description": "Consumer token limit exceeded"
            })),
        ));
    }

    if !state.token_limiter.check_client_rate_limit(&req.client_id).await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "internal_error"}))))?
    {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({
                "error": "rate_limit_exceeded",
                "error_description": "Client rate limit exceeded"
            })),
        ));
    }

    // Issue token
    let token_request = TokenIssuanceRequest {
        consumer_id: req.consumer_id.clone(),
        client_id: req.client_id.clone(),
        consumer_type,
        scope: req.scope.clone(),
        environment,
        requested_ttl_secs: req.requested_ttl_secs,
        binding: Some(addr.ip().to_string()),
    };

    let response = state.token_service.issue_token(token_request).await
        .map_err(|e| {
            tracing::error!("token issuance failed: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "token_generation_failed"})))
        })?;

    // Increment rate limit counters
    let _ = state.token_limiter.increment_consumer_count(&req.consumer_id).await;
    let _ = state.token_limiter.increment_client_rate(&req.client_id).await;

    Ok(Json(json!({
        "access_token": response.access_token,
        "token_type": response.token_type,
        "expires_in": response.expires_in,
        "scope": response.scope,
    })))
}

#[derive(serde::Deserialize)]
pub struct RevokeRequest {
    pub jti: String,
}

pub async fn revoke_token(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RevokeRequest>,
) -> Result<StatusCode, (StatusCode, Json<serde_json::Value>)> {
    state.token_service.revoke_token(&req.jti).await
        .map_err(|e| {
            tracing::error!("token revocation failed: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "revocation_failed"})))
        })?;

    Ok(StatusCode::NO_CONTENT)
}
```

Register routes in `src/api/mod.rs`:

```rust
pub mod oauth;

// In router setup:
let app = Router::new()
    .route("/api/oauth/token", post(oauth::issue_token))
    .route("/api/oauth/revoke", post(oauth::revoke_token))
    // ... other routes ...
```

## 🔐 Step 7: Add Middleware for Token Validation

Create middleware to validate tokens on protected endpoints:

```rust
use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
};

pub async fn validate_oauth_token(
    State(state): State<Arc<AppState>>,
    mut req: Request,
    next: Next,
) -> Response {
    // Extract Bearer token
    let token = match req.headers().get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
    {
        Some(t) => t,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "missing_token"})),
            ).into_response();
        }
    };

    // Validate token
    let context = ValidationContext {
        expected_issuer: "https://api.aframp.com".to_string(),
        expected_audience: "api".to_string(),
        expected_environment: "mainnet".to_string(),
        request_ip: req.extensions().get::<SocketAddr>().map(|a| a.ip()),
        request_nonce: None,
    };

    match state.token_validator.validate(token, &context).await {
        Ok(claims) => {
            req.extensions_mut().insert(claims);
            next.run(req).await
        }
        Err(e) => {
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "error": e.error_code(),
                    "error_description": e.to_string(),
                })),
            ).into_response()
        }
    }
}
```

## 📊 Step 8: Add Metrics

Update `src/metrics/mod.rs` to add OAuth metrics:

```rust
pub mod oauth {
    use super::*;

    static TOKENS_ISSUED_TOTAL: OnceLock<CounterVec> = OnceLock::new();
    static TOKENS_VALIDATED_TOTAL: OnceLock<CounterVec> = OnceLock::new();
    static TOKEN_VALIDATION_FAILURES_TOTAL: OnceLock<CounterVec> = OnceLock::new();
    static TOKENS_REVOKED_TOTAL: OnceLock<CounterVec> = OnceLock::new();

    pub fn tokens_issued_total() -> &'static CounterVec {
        TOKENS_ISSUED_TOTAL.get().expect("metrics not initialised")
    }

    pub fn tokens_validated_total() -> &'static CounterVec {
        TOKENS_VALIDATED_TOTAL.get().expect("metrics not initialised")
    }

    pub fn token_validation_failures_total() -> &'static CounterVec {
        TOKEN_VALIDATION_FAILURES_TOTAL.get().expect("metrics not initialised")
    }

    pub fn tokens_revoked_total() -> &'static CounterVec {
        TOKENS_REVOKED_TOTAL.get().expect("metrics not initialised")
    }

    pub(super) fn register(r: &Registry) {
        TOKENS_ISSUED_TOTAL
            .set(
                register_counter_vec_with_registry!(
                    "aframp_tokens_issued_total",
                    "Total number of OAuth 2.0 access tokens issued",
                    &["consumer_type"],
                    r
                )
                .unwrap(),
            )
            .ok();

        TOKENS_VALIDATED_TOTAL
            .set(
                register_counter_vec_with_registry!(
                    "aframp_tokens_validated_total",
                    "Total number of OAuth 2.0 access tokens validated",
                    &["consumer_type"],
                    r
                )
                .unwrap(),
            )
            .ok();

        TOKEN_VALIDATION_FAILURES_TOTAL
            .set(
                register_counter_vec_with_registry!(
                    "aframp_token_validation_failures_total",
                    "Total number of OAuth 2.0 token validation failures",
                    &["reason"],
                    r
                )
                .unwrap(),
            )
            .ok();

        TOKENS_REVOKED_TOTAL
            .set(
                register_counter_vec_with_registry!(
                    "aframp_tokens_revoked_total",
                    "Total number of OAuth 2.0 access tokens revoked",
                    &[],
                    r
                )
                .unwrap(),
            )
            .ok();
    }
}
```

## 🧪 Step 9: Test the Implementation

Run tests:

```bash
# Unit tests
cargo test --lib auth::oauth_tests

# Integration tests
cargo test --test oauth_integration

# Build
cargo build --release
```

## 🚀 Step 10: Deploy

1. Generate and store RS256 keys securely
2. Set environment variables
3. Run database migrations
4. Deploy application
5. Monitor metrics and logs
6. Test token issuance and validation

## ✅ Acceptance Criteria Verification

- [ ] All tokens include required claims (iss, sub, aud, exp, iat, jti, scope, client_id, consumer_type, environment, kid)
- [ ] JTI is always unique (UUID v4)
- [ ] RS256 signature enforced
- [ ] Expired tokens rejected
- [ ] Binding enforced (IP or nonce)
- [ ] Environment mismatch rejected
- [ ] Revoked tokens blocked
- [ ] Redis cache reduces DB calls
- [ ] JWKS supports key rotation
- [ ] Rate limiting enforced
- [ ] Logs contain only JTI (no token leak)
- [ ] Metrics exposed at /metrics
- [ ] All tests pass

## 🐛 Troubleshooting

### Token validation fails with "invalid_token"
- Check RS256 key pair is correct
- Verify token was signed with private key
- Ensure public key matches private key

### "token_binding_failed" errors
- Verify request IP matches token binding
- Check if client is behind proxy (may need X-Forwarded-For)

### Rate limit exceeded
- Check rate limit configuration
- Verify Redis is working
- Monitor token count per consumer

### JWKS refresh fails
- Check JWKS URL is accessible
- Verify network connectivity
- Check auth server is running

## 📞 Support

For issues or questions, refer to:
- `OAUTH_TOKEN_SYSTEM.md` - System overview
- `src/auth/oauth_token_service.rs` - Token issuance
- `src/auth/oauth_token_validator.rs` - Token validation
- `src/auth/oauth_tests.rs` - Test examples
