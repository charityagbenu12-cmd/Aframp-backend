# OAuth 2.0 Access Token System

Complete, production-grade OAuth 2.0 access token issuance and validation system using JWT (RS256).

## 🎯 Overview

This system implements the full lifecycle of OAuth 2.0 access tokens:

- **Token Design**: RS256-signed JWT with standard + custom claims
- **Secure Issuance**: Consumer type-based TTL enforcement, token binding
- **Stateless Validation**: JWKS-based signature verification, minimal DB lookups
- **Revocation Handling**: Redis cache + database fallback
- **JWKS Management**: Key rotation support, periodic refresh
- **Rate Limiting**: Per-consumer and per-client limits
- **Observability**: Prometheus metrics, structured logging
- **Testing**: Comprehensive unit and integration tests

## 📋 Architecture

### Components

```
┌─────────────────────────────────────────────────────────────┐
│                    OAuth 2.0 Token System                   │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌──────────────────┐  ┌──────────────────┐                 │
│  │ Token Issuance   │  │ Token Validation │                 │
│  │ (RS256 signing)  │  │ (RS256 verify)   │                 │
│  └────────┬─────────┘  └────────┬─────────┘                 │
│           │                     │                            │
│           ├─────────────────────┤                            │
│           │                     │                            │
│  ┌────────▼──────────┐  ┌──────▼──────────┐                 │
│  │ Token Registry    │  │ JWKS Service    │                 │
│  │ (Database)        │  │ (Key Mgmt)      │                 │
│  └────────┬──────────┘  └──────┬──────────┘                 │
│           │                     │                            │
│  ┌────────▼──────────────────────▼──────────┐               │
│  │  Redis Cache (Revocation + JWKS)         │               │
│  └───────────────────────────────────────────┘               │
│                                                               │
│  ┌───────────────────────────────────────────┐               │
│  │  Rate Limiter (Per-consumer, Per-client)  │               │
│  └───────────────────────────────────────────┘               │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

### Token Lifetime by Consumer Type

| Consumer Type | Max TTL | Use Case |
|---|---|---|
| `mobile_client` | 1 hour | Mobile apps, web clients |
| `partner` | 30 minutes | Third-party integrations |
| `microservice` | 15 minutes | Internal service-to-service |
| `admin` | 15 minutes | Administrative operations |

## 🔐 Token Structure

### JWT Header
```json
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "key_id_123"
}
```

### JWT Payload (Claims)
```json
{
  "iss": "https://api.aframp.com",
  "sub": "consumer_id_123",
  "aud": "api",
  "exp": 1711270800,
  "iat": 1711267200,
  "jti": "jti_550e8400e29b41d4a716446655440000",
  "scope": "read write",
  "client_id": "client_123",
  "consumer_type": "mobile_client",
  "environment": "mainnet",
  "kid": "key_id_123",
  "binding": "192.168.1.1"
}
```

### Claims Reference

| Claim | Type | Description |
|---|---|---|
| `iss` | string | Issuer URL (e.g., `https://api.aframp.com`) |
| `sub` | string | Subject (consumer ID) |
| `aud` | string | Audience (API audience, e.g., `api`) |
| `exp` | number | Expiry timestamp (Unix) |
| `iat` | number | Issued-at timestamp (Unix) |
| `jti` | string | JWT ID (unique token identifier) |
| `scope` | string | Space-separated scopes |
| `client_id` | string | OAuth 2.0 client ID |
| `consumer_type` | string | Consumer type (mobile_client, partner, microservice, admin) |
| `environment` | string | Environment (testnet, mainnet) |
| `kid` | string | Key ID used for signing |
| `binding` | string | Optional token binding (IP or nonce) |

## 🚀 Usage

### 1. Token Issuance

```rust
use aframp_backend::auth::{
    OAuthTokenService, TokenIssuanceRequest, ConsumerType, Environment,
};

// Create service
let service = OAuthTokenService::new(
    "https://api.aframp.com".to_string(),
    "api".to_string(),
    private_key_pem,
    "key_id_123".to_string(),
    db,
    Some(redis_cache),
);

// Issue token
let request = TokenIssuanceRequest {
    consumer_id: "consumer_123".to_string(),
    client_id: "client_123".to_string(),
    consumer_type: ConsumerType::MobileClient,
    scope: "read write".to_string(),
    environment: Environment::Mainnet,
    requested_ttl_secs: Some(1800), // 30 minutes (capped at max)
    binding: Some("192.168.1.1".to_string()),
};

let response = service.issue_token(request).await?;
// Returns: { access_token, token_type: "Bearer", expires_in, scope }
```

### 2. Token Validation

```rust
use aframp_backend::auth::{
    OAuthTokenValidator, ValidationContext,
};

// Create validator
let validator = OAuthTokenValidator::new(
    public_key_pem,
    Some(redis_cache),
);

// Validate token
let context = ValidationContext {
    expected_issuer: "https://api.aframp.com".to_string(),
    expected_audience: "api".to_string(),
    expected_environment: "mainnet".to_string(),
    request_ip: Some("192.168.1.1".parse()?),
    request_nonce: None,
};

let claims = validator.validate(token, &context).await?;
// Returns: OAuthTokenClaims with all token data
```

### 3. Token Revocation

```rust
// Revoke single token
service.revoke_token("jti_550e8400e29b41d4a716446655440000").await?;

// Revoke all tokens for consumer
// TODO: Implement in service
```

### 4. Rate Limiting

```rust
use aframp_backend::auth::{TokenRateLimiter, RateLimitConfig};

let config = RateLimitConfig {
    max_active_tokens_per_consumer: 10,
    max_issuance_per_client_per_window: 100,
    rate_limit_window_secs: 60,
};

let limiter = TokenRateLimiter::new(redis_cache, config);

// Check limits before issuance
if !limiter.check_consumer_limit("consumer_123").await? {
    return Err("Consumer token limit exceeded");
}

if !limiter.check_client_rate_limit("client_123").await? {
    return Err("Client rate limit exceeded");
}

// Increment counters after successful issuance
limiter.increment_consumer_count("consumer_123").await?;
limiter.increment_client_rate("client_123").await?;
```

## 🔑 JWKS Key Management

### Fetching Keys

```rust
use aframp_backend::auth::JwksService;
use std::sync::Arc;

let service = Arc::new(JwksService::new(
    "https://auth.aframp.com/.well-known/jwks.json".to_string(),
    3600, // Refresh every hour
));

// Start background refresh task
service.clone().start_refresh_task();

// Get specific key
let key = service.get_key("key_id_123").await?;

// Get all keys
let keys = service.get_all_keys().await?;
```

### Key Rotation

The JWKS service automatically:
- Fetches keys from the auth server
- Caches keys in memory and Redis
- Refreshes periodically (configurable interval)
- Supports multiple keys for rotation
- Falls back to last known keys on fetch failure

## 📊 Observability

### Prometheus Metrics

```
# Token issuance
aframp_tokens_issued_total{consumer_type="mobile_client"} 1234
aframp_tokens_issued_total{consumer_type="partner"} 567

# Token validation
aframp_tokens_validated_total 5678
aframp_token_validation_failures_total{reason="expired"} 12
aframp_token_validation_failures_total{reason="revoked"} 3
aframp_token_validation_failures_total{reason="binding_failed"} 1

# Token revocation
aframp_tokens_revoked_total 45

# Rate limiting
aframp_token_rate_limit_exceeded_total{consumer_type="mobile_client"} 2
```

### Structured Logging

**Token Issuance:**
```json
{
  "timestamp": "2024-03-24T10:30:00Z",
  "level": "INFO",
  "message": "access token issued",
  "jti": "jti_550e8400e29b41d4a716446655440000",
  "consumer_id": "consumer_123",
  "client_id": "client_123",
  "scope": "read write",
  "expires_at": 1711270800,
  "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736"
}
```

**Token Validation Failure:**
```json
{
  "timestamp": "2024-03-24T10:31:00Z",
  "level": "WARN",
  "message": "token validation failed",
  "jti": "jti_550e8400e29b41d4a716446655440000",
  "reason": "token_expired",
  "endpoint": "/api/payments",
  "client_ip": "192.168.1.1",
  "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736"
}
```

**Never log full tokens** — only log JTI for security.

## 🧪 Testing

### Unit Tests

```bash
cargo test --lib auth::oauth_tests
```

Tests cover:
- Token claim correctness
- Signature verification
- Expiry enforcement
- Environment validation
- Binding validation (IP/nonce)
- Revocation cache logic
- Rate limiting

### Integration Tests

```bash
cargo test --test oauth_integration
```

Tests cover:
- Successful issuance + validation
- Expired token rejection
- Revoked token rejection
- Wrong environment rejection
- Binding mismatch rejection
- Rate limit enforcement

## 🔒 Security Best Practices

### ✅ Implemented

- RS256 signature verification (asymmetric)
- JTI uniqueness enforcement
- Token binding (IP or nonce)
- Environment validation
- Revocation checking (cache + DB)
- Rate limiting (per-consumer, per-client)
- Structured logging (no token leaks)
- TTL enforcement by consumer type
- Graceful degradation (cache failures)

### ⚠️ Important

- **Never expose private keys** — store in secure vault
- **Never log access tokens** — only log JTI
- **Always validate all claims** — fail closed
- **Always verify signature** before trusting payload
- **Rotate keys regularly** — JWKS supports rotation
- **Monitor revocation cache** — ensure Redis availability
- **Set appropriate TTLs** — shorter for sensitive operations

## 📁 File Structure

```
src/auth/
├── oauth_token_service.rs      # Token issuance (RS256)
├── oauth_token_validator.rs    # Stateless validation
├── jwks_service.rs             # JWKS key management
├── token_limiter.rs            # Rate limiting
├── oauth_tests.rs              # Comprehensive tests
├── jwt.rs                       # Existing JWT implementation
├── middleware.rs               # Axum middleware
├── handlers.rs                 # HTTP handlers
└── mod.rs                       # Module exports

src/database/
├── token_registry_repository.rs # Token persistence
└── mod.rs                       # Module exports

migrations/
└── 20240324_create_token_registry.sql # Database schema
```

## 🚀 Deployment Checklist

- [ ] Generate RS256 key pair (private + public)
- [ ] Store private key in secure vault (e.g., AWS Secrets Manager)
- [ ] Configure JWKS endpoint URL
- [ ] Set environment variables:
  - `OAUTH_ISSUER_URL`
  - `OAUTH_API_AUDIENCE`
  - `OAUTH_PRIVATE_KEY_PEM`
  - `OAUTH_KEY_ID`
  - `OAUTH_JWKS_URL`
  - `OAUTH_JWKS_REFRESH_INTERVAL_SECS`
- [ ] Run database migration
- [ ] Configure Redis for caching
- [ ] Set rate limit thresholds
- [ ] Enable Prometheus metrics
- [ ] Configure structured logging
- [ ] Test token issuance and validation
- [ ] Monitor metrics and logs
- [ ] Set up alerts for validation failures

## 📚 References

- [RFC 6749 - OAuth 2.0 Authorization Framework](https://tools.ietf.org/html/rfc6749)
- [RFC 6750 - OAuth 2.0 Bearer Token Usage](https://tools.ietf.org/html/rfc6750)
- [RFC 7519 - JSON Web Token (JWT)](https://tools.ietf.org/html/rfc7519)
- [RFC 7517 - JSON Web Key (JWK)](https://tools.ietf.org/html/rfc7517)
- [RFC 7518 - JSON Web Algorithms (JWA)](https://tools.ietf.org/html/rfc7518)

## 🤝 Contributing

When extending this system:

1. Maintain RS256 signature verification
2. Always validate all claims
3. Never log full tokens
4. Add tests for new features
5. Update documentation
6. Follow existing error handling patterns
7. Use structured logging
8. Add Prometheus metrics

## 📝 License

Part of Aframp backend system.
