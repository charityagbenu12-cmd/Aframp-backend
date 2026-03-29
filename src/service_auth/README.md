# Microservice-to-Microservice Authentication

This module implements a comprehensive authentication system for internal service-to-service communication on the Aframp platform.

## Features

- **Service Identity Registration**: Every microservice is registered as a confidential OAuth client with unique credentials
- **OAuth 2.0 Client Credentials Flow**: Services acquire short-lived JWT access tokens (15-minute TTL)
- **Proactive Token Rotation**: Tokens are automatically refreshed before expiry with exponential backoff retry
- **Service Token Injection**: HTTP client middleware automatically attaches Bearer tokens and service identity headers
- **Service Token Verification**: Middleware validates JWT signatures, claims, and service identity
- **Service Call Allowlist**: Configurable allowlist restricts which services can call which endpoints
- **mTLS Support**: Optional mutual TLS for highest sensitivity endpoints
- **Comprehensive Observability**: Prometheus metrics and structured logging for all authentication events

## Architecture

### Components

1. **ServiceRegistry** (`registration.rs`)
   - Registers services as OAuth clients
   - Manages service identities and credentials
   - Handles secret rotation with grace periods

2. **ServiceTokenManager** (`token_manager.rs`)
   - Acquires tokens via Client Credentials flow
   - Caches tokens in memory (never persisted)
   - Proactively refreshes before expiry
   - Implements exponential backoff retry

3. **ServiceHttpClient** (`client.rs`)
   - Wraps reqwest with automatic token injection
   - Adds `Authorization`, `X-Service-Name`, and `X-Request-ID` headers
   - Automatically retries 401 responses after token refresh

4. **ServiceAllowlist** (`allowlist.rs`)
   - Manages service call permissions
   - Supports exact and wildcard endpoint matching
   - Multi-level caching (memory + Redis)
   - Immediate cache invalidation on updates

5. **Service Token Verification Middleware** (`middleware.rs`)
   - Validates JWT tokens on inbound requests
   - Verifies `microservice:internal` scope
   - Prevents service impersonation
   - Enforces allowlist permissions
   - Logs all authentication events

6. **CertificateManager** (`certificate.rs`)
   - Generates per-service TLS certificates
   - Manages certificate lifecycle and rotation
   - Monitors certificate expiry
   - Supports zero-downtime rotation

## Usage

### Registering a Service

```rust
use aframp_backend::service_auth::{ServiceRegistry, ServiceRegistration};

let registry = ServiceRegistry::new(pool);

let registration = ServiceRegistration {
    service_name: "worker_service".to_string(),
    allowed_scopes: vec!["worker:execute".to_string()],
    allowed_targets: vec!["/api/settlement/*".to_string()],
};

let identity = registry.register_service(registration).await?;

// Store client_secret securely - it's only returned once
println!("Client ID: {}", identity.client_id);
println!("Client Secret: {}", identity.client_secret);
```

### Initializing Token Manager

```rust
use aframp_backend::service_auth::{ServiceTokenManager, TokenRefreshConfig};

let config = TokenRefreshConfig {
    refresh_threshold: 0.2,  // Refresh at 20% remaining lifetime
    max_retries: 3,
    initial_backoff_ms: 100,
    max_backoff_ms: 5000,
};

let manager = Arc::new(ServiceTokenManager::new(
    "worker_service".to_string(),
    "service_worker".to_string(),
    client_secret,
    "https://api.aframp.com/oauth/token".to_string(),
    config,
));

// Initialize and acquire first token
manager.initialize().await?;

// Start background refresh task
manager.clone().start_refresh_task();
```

### Making Service Calls

```rust
use aframp_backend::service_auth::ServiceHttpClient;

let client = ServiceHttpClient::new(
    "worker_service".to_string(),
    token_manager.clone(),
);

let request = reqwest::Request::new(
    reqwest::Method::POST,
    "https://api.aframp.com/api/settlement/process".parse()?,
);

let response = client.execute(request).await?;
```

### Configuring Allowlist

```rust
use aframp_backend::service_auth::ServiceAllowlist;

let allowlist = ServiceAllowlist::new(pool, cache);

// Allow worker_service to call settlement endpoints
allowlist
    .set_permission("worker_service", "/api/settlement/*", true)
    .await?;

// Deny worker_service from calling admin endpoints
allowlist
    .set_permission("worker_service", "/api/admin/*", false)
    .await?;
```

### Applying Verification Middleware

```rust
use axum::{Router, middleware};
use aframp_backend::service_auth::{service_token_verification, ServiceAuthState};

let auth_state = ServiceAuthState {
    pool: pool.clone(),
    allowlist: allowlist.clone(),
    jwt_secret: config.jwt_secret.clone(),
};

let app = Router::new()
    .route("/api/internal/settlement", post(settlement_handler))
    .layer(middleware::from_fn_with_state(
        auth_state,
        service_token_verification,
    ));
```

## Security Guarantees

1. **Short-lived Tokens**: 15-minute maximum lifetime prevents long-term credential exposure
2. **No Token Persistence**: Tokens kept exclusively in process memory
3. **Service Impersonation Prevention**: X-Service-Name header verified against JWT subject
4. **Allowlist Enforcement**: Services can only call explicitly permitted endpoints
5. **Comprehensive Auditing**: All authentication events logged to database
6. **Automatic Rotation**: Tokens refreshed before expiry, secrets rotatable with grace periods

## Metrics

All metrics are exposed at `/metrics` endpoint:

- `aframp_service_token_acquisitions_total{service_name}` - Token acquisitions per service
- `aframp_service_token_refresh_events_total{service_name}` - Token refresh events per service
- `aframp_service_token_refresh_failures_total{service_name}` - Token refresh failures per service
- `aframp_service_call_authentications_total{calling_service,endpoint,result}` - Authentication attempts
- `aframp_service_call_authorization_denials_total{calling_service,endpoint,reason}` - Authorization denials

## Admin API

### Register Service
```
POST /admin/services/register
{
  "service_name": "worker_service",
  "allowed_scopes": ["worker:execute"],
  "allowed_targets": ["/api/settlement/*"]
}
```

### List Services
```
GET /admin/services
```

### Rotate Secret
```
POST /admin/services/:service_name/rotate-secret
{
  "grace_period_secs": 300
}
```

### Manage Allowlist
```
GET /admin/services/allowlist
POST /admin/services/allowlist/add
POST /admin/services/allowlist/remove
```

## Testing

Run integration tests:
```bash
cargo test --test service_auth_test --features database -- --ignored
```

Run unit tests:
```bash
cargo test -p aframp-backend service_auth::tests
```

## Migration

Apply database migrations:
```bash
sqlx migrate run
```

The migration creates:
- `service_call_allowlist` table
- `service_secret_rotation` table
- `service_certificates` table
- `service_auth_audit` table

## Future Enhancements

- Service mesh integration (Istio/Linkerd)
- Hardware security module (HSM) integration for key storage
- Certificate transparency logging
- Automated certificate renewal
- Service-to-service rate limiting
- Request signing for additional integrity
