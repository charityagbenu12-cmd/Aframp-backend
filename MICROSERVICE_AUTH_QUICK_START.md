# Microservice Authentication Quick Start Guide

## Overview

This guide provides step-by-step instructions for implementing microservice-to-microservice authentication in your service.

## Prerequisites

- PostgreSQL database with migrations applied
- Redis instance for caching
- OAuth 2.0 token endpoint configured
- Service registered in the system

## Step 1: Register Your Service

Use the admin API to register your service:

```bash
curl -X POST https://api.aframp.com/admin/services/register \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <admin-token>" \
  -d '{
    "service_name": "my_service",
    "allowed_scopes": ["my_service:execute"],
    "allowed_targets": ["/api/internal/*"]
  }'
```

Response:
```json
{
  "service_name": "my_service",
  "client_id": "service_my_service",
  "client_secret": "svc_secret_abc123...",
  "allowed_scopes": ["microservice:internal", "my_service:execute"]
}
```

**Important**: Store the `client_secret` securely in your secrets manager. It's only shown once.

## Step 2: Configure Service Allowlist

Define which endpoints your service can call:

```bash
curl -X POST https://api.aframp.com/admin/services/allowlist/add \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <admin-token>" \
  -d '{
    "calling_service": "my_service",
    "target_endpoint": "/api/settlement/*",
    "allowed": true
  }'
```

## Step 3: Initialize Token Manager in Your Service

Add to your service's `main.rs` or initialization code:

```rust
use aframp_backend::service_auth::{ServiceTokenManager, TokenRefreshConfig};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load configuration
    let service_name = std::env::var("SERVICE_NAME")?;
    let client_id = std::env::var("SERVICE_CLIENT_ID")?;
    let client_secret = std::env::var("SERVICE_CLIENT_SECRET")?;
    let token_endpoint = std::env::var("OAUTH_TOKEN_ENDPOINT")?;

    // Create token manager
    let token_manager = Arc::new(ServiceTokenManager::new(
        service_name.clone(),
        client_id,
        client_secret,
        token_endpoint,
        TokenRefreshConfig::default(),
    ));

    // Initialize and acquire first token
    token_manager.initialize().await?;

    // Start background refresh task
    token_manager.clone().start_refresh_task();

    // Use token_manager in your HTTP client
    // ...

    Ok(())
}
```

## Step 4: Make Authenticated Service Calls

Use the `ServiceHttpClient` for all internal API calls:

```rust
use aframp_backend::service_auth::ServiceHttpClient;
use reqwest::Method;

async fn call_settlement_service(
    client: &ServiceHttpClient,
) -> Result<(), Box<dyn std::error::Error>> {
    let request = reqwest::Request::new(
        Method::POST,
        "https://api.aframp.com/api/settlement/process".parse()?,
    );

    let response = client.execute(request).await?;

    if response.status().is_success() {
        println!("Settlement processed successfully");
    }

    Ok(())
}
```

## Step 5: Protect Your Service's Endpoints

Add verification middleware to your service's internal endpoints:

```rust
use axum::{Router, routing::post, middleware};
use aframp_backend::service_auth::{service_token_verification, ServiceAuthState};
use std::sync::Arc;

async fn build_router(
    pool: Arc<sqlx::PgPool>,
    allowlist: Arc<ServiceAllowlist>,
    jwt_secret: String,
) -> Router {
    let auth_state = ServiceAuthState {
        pool,
        allowlist,
        jwt_secret,
    };

    Router::new()
        .route("/api/internal/process", post(process_handler))
        .route("/api/internal/verify", post(verify_handler))
        .layer(middleware::from_fn_with_state(
            auth_state,
            service_token_verification,
        ))
}
```

## Step 6: Environment Variables

Add these to your service's environment:

```bash
# Service identity
SERVICE_NAME=my_service
SERVICE_CLIENT_ID=service_my_service
SERVICE_CLIENT_SECRET=svc_secret_abc123...

# OAuth configuration
OAUTH_TOKEN_ENDPOINT=https://api.aframp.com/oauth/token

# JWT verification
JWT_SECRET=your-jwt-secret

# Database
DATABASE_URL=postgres://user:pass@localhost/aframp

# Redis
REDIS_URL=redis://localhost:6379
```

## Step 7: Verify Setup

Test your service authentication:

```bash
# Check service registration
curl https://api.aframp.com/admin/services/my_service \
  -H "Authorization: Bearer <admin-token>"

# Check allowlist
curl https://api.aframp.com/admin/services/allowlist/my_service \
  -H "Authorization: Bearer <admin-token>"

# Monitor metrics
curl https://api.aframp.com/metrics | grep service_token
```

## Troubleshooting

### Token Acquisition Fails

**Symptom**: Service fails to start with "Token acquisition failed"

**Solutions**:
1. Verify `SERVICE_CLIENT_ID` and `SERVICE_CLIENT_SECRET` are correct
2. Check `OAUTH_TOKEN_ENDPOINT` is accessible
3. Ensure service is registered in the database
4. Check network connectivity to OAuth server

### 401 Unauthorized on Service Calls

**Symptom**: Service calls return 401 even after token refresh

**Solutions**:
1. Verify JWT_SECRET matches between services
2. Check token hasn't expired (should auto-refresh)
3. Verify `microservice:internal` scope is present
4. Check service name in `X-Service-Name` header matches token subject

### 403 Forbidden on Service Calls

**Symptom**: Service calls return 403 with "SERVICE_NOT_AUTHORIZED"

**Solutions**:
1. Check allowlist configuration for your service
2. Verify endpoint pattern matches (wildcards must be exact)
3. Ensure allowlist entry has `allowed: true`
4. Check cache invalidation (may take up to 5 minutes)

### Service Impersonation Error

**Symptom**: Logs show "Service impersonation attempt detected"

**Solutions**:
1. Verify `X-Service-Name` header matches token subject
2. Check you're not reusing tokens from another service
3. Ensure token manager is initialized with correct service name

## Monitoring

### Key Metrics to Watch

```promql
# Token acquisition rate
rate(aframp_service_token_acquisitions_total{service_name="my_service"}[5m])

# Token refresh failures (should be 0)
aframp_service_token_refresh_failures_total{service_name="my_service"}

# Authentication success rate
rate(aframp_service_call_authentications_total{calling_service="my_service",result="success"}[5m])

# Authorization denials
rate(aframp_service_call_authorization_denials_total{calling_service="my_service"}[5m])
```

### Alerts to Configure

1. **Token Refresh Failure**
   ```yaml
   alert: ServiceTokenRefreshFailure
   expr: aframp_service_token_refresh_failures_total > 0
   for: 1m
   severity: critical
   ```

2. **High Authorization Denial Rate**
   ```yaml
   alert: HighServiceAuthDenialRate
   expr: rate(aframp_service_call_authorization_denials_total[5m]) > 0.05
   for: 5m
   severity: warning
   ```

## Best Practices

1. **Secret Management**
   - Never commit client secrets to version control
   - Use secrets manager (AWS Secrets Manager, HashiCorp Vault, etc.)
   - Rotate secrets regularly (every 90 days)

2. **Token Lifecycle**
   - Let the token manager handle all token operations
   - Don't manually refresh tokens
   - Don't cache tokens outside the token manager

3. **Error Handling**
   - Always handle token refresh failures gracefully
   - Implement circuit breakers for downstream services
   - Log all authentication failures for audit

4. **Allowlist Management**
   - Use wildcard patterns for endpoint groups
   - Review allowlist quarterly
   - Remove unused permissions promptly

5. **Monitoring**
   - Set up alerts for token refresh failures
   - Monitor authentication success rates
   - Track authorization denials

## Next Steps

- Review [MICROSERVICE_AUTH_IMPLEMENTATION.md](./MICROSERVICE_AUTH_IMPLEMENTATION.md) for detailed architecture
- Check [src/service_auth/README.md](./src/service_auth/README.md) for API documentation
- Run integration tests: `cargo test --test service_auth_test --features database -- --ignored`
- Configure mTLS for highest sensitivity endpoints

## Support

For issues or questions:
1. Check logs for detailed error messages
2. Review Prometheus metrics
3. Consult the audit log in `service_auth_audit` table
4. Contact the platform team
