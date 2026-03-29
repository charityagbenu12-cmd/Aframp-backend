# Microservice Authentication Architecture

## System Overview

The microservice-to-microservice authentication system provides a comprehensive security layer for internal service communication on the Aframp platform. It ensures that every internal API call is authenticated, authorized, and auditable.

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Service A (Caller)                          │
│                                                                     │
│  ┌──────────────────┐         ┌─────────────────────────────────┐ │
│  │ Token Manager    │         │   Service HTTP Client           │ │
│  │                  │         │                                 │ │
│  │ - Acquire token  │────────▶│ - Inject Bearer token          │ │
│  │ - Cache in memory│         │ - Add X-Service-Name header    │ │
│  │ - Proactive      │         │ - Add X-Request-ID header      │ │
│  │   refresh        │         │ - Retry on 401                 │ │
│  │ - Exponential    │         │                                 │ │
│  │   backoff        │         └─────────────┬───────────────────┘ │
│  └──────────────────┘                       │                     │
│                                             │ HTTPS + mTLS        │
└─────────────────────────────────────────────┼─────────────────────┘
                                              │
                                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│                      OAuth 2.0 Token Endpoint                       │
│                                                                     │
│  ┌──────────────────────────────────────────────────────────────┐ │
│  │ Client Credentials Flow                                      │ │
│  │                                                              │ │
│  │ POST /oauth/token                                            │ │
│  │ grant_type=client_credentials                                │ │
│  │ client_id=service_worker                                     │ │
│  │ client_secret=svc_secret_***                                 │ │
│  │ scope=microservice:internal                                  │ │
│  │                                                              │ │
│  │ Response: { access_token, expires_in: 900 }                  │ │
│  └──────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
                                              │
                                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         Service B (Target)                          │
│                                                                     │
│  ┌──────────────────────────────────────────────────────────────┐ │
│  │ Service Token Verification Middleware                        │ │
│  │                                                              │ │
│  │ 1. Extract Authorization header                              │ │
│  │ 2. Extract X-Service-Name header                             │ │
│  │ 3. Validate JWT signature & claims                           │ │
│  │ 4. Verify microservice:internal scope                        │ │
│  │ 5. Verify service name matches token subject                 │ │
│  │ 6. Check service call allowlist                              │ │
│  │ 7. Log authentication event                                  │ │
│  │ 8. Inject AuthenticatedService into extensions               │ │
│  └──────────────────────────────────────────────────────────────┘ │
│                              │                                      │
│                              ▼                                      │
│  ┌──────────────────────────────────────────────────────────────┐ │
│  │ Protected Endpoint Handler                                   │ │
│  │                                                              │ │
│  │ - Access AuthenticatedService from extensions                │ │
│  │ - Process request with service context                       │ │
│  │ - Return response                                            │ │
│  └──────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
                                              │
                                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│                      Supporting Infrastructure                      │
│                                                                     │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐ │
│  │ PostgreSQL   │  │ Redis Cache  │  │ Prometheus Metrics       │ │
│  │              │  │              │  │                          │ │
│  │ - Service    │  │ - Allowlist  │  │ - Token acquisitions     │ │
│  │   registry   │  │   cache      │  │ - Refresh events         │ │
│  │ - Allowlist  │  │ - 5min TTL   │  │ - Refresh failures       │ │
│  │ - Audit log  │  │              │  │ - Authentication results │ │
│  │ - Certs      │  │              │  │ - Authorization denials  │ │
│  └──────────────┘  └──────────────┘  └──────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
```

## Component Details

### 1. Service Registry

**Purpose**: Manages service identities and credentials

**Key Features**:
- Registers services as confidential OAuth clients
- Generates unique client ID and secret per service
- Stores credentials in PostgreSQL
- Supports secret rotation with grace periods

**Database Schema**:
```sql
oauth_clients (
    id UUID PRIMARY KEY,
    client_id VARCHAR(128) UNIQUE,
    client_secret_hash VARCHAR(256),
    client_name VARCHAR(255),
    client_type VARCHAR(32),  -- 'confidential'
    allowed_grant_types TEXT[],  -- ['client_credentials']
    allowed_scopes TEXT[],  -- ['microservice:internal', ...]
    status VARCHAR(32)  -- 'active', 'suspended', 'revoked'
)
```

### 2. Token Manager

**Purpose**: Acquires and manages service access tokens

**Token Lifecycle**:
```
┌─────────────┐
│   Startup   │
└──────┬──────┘
       │
       ▼
┌─────────────────────┐
│ Acquire Initial     │
│ Token via Client    │
│ Credentials Flow    │
└──────┬──────────────┘
       │
       ▼
┌─────────────────────┐
│ Cache Token in      │
│ Memory (15min TTL)  │
└──────┬──────────────┘
       │
       ▼
┌─────────────────────┐
│ Background Task     │
│ Checks Every 30s    │
└──────┬──────────────┘
       │
       ▼
┌─────────────────────┐
│ Remaining Lifetime  │
│ < 20% of Total?     │
└──────┬──────────────┘
       │
       ├─ No ──▶ Continue monitoring
       │
       └─ Yes ─▶ Refresh token
                 │
                 ▼
          ┌─────────────────┐
          │ Retry with      │
          │ Exponential     │
          │ Backoff (3x)    │
          └─────────────────┘
```

**Configuration**:
- Refresh threshold: 20% remaining lifetime (configurable)
- Max retries: 3 (configurable)
- Initial backoff: 100ms (configurable)
- Max backoff: 5s (configurable)

### 3. Service HTTP Client

**Purpose**: Wraps HTTP requests with automatic authentication

**Request Flow**:
```
1. Create request
2. Get current token from token manager
3. Inject headers:
   - Authorization: Bearer <token>
   - X-Service-Name: <service_name>
   - X-Request-ID: <uuid>
4. Execute request
5. If 401:
   a. Force token refresh
   b. Retry request once
6. Return response
```

### 4. Service Allowlist

**Purpose**: Controls which services can call which endpoints

**Matching Algorithm**:
```rust
fn is_allowed(service: &str, endpoint: &str) -> bool {
    // 1. Check memory cache
    if let Some(cached) = memory_cache.get(service) {
        if let Some(result) = match_endpoint(cached, endpoint) {
            return result;
        }
    }
    
    // 2. Check Redis cache (5min TTL)
    if let Some(cached) = redis_cache.get(service) {
        memory_cache.insert(service, cached);
        return match_endpoint(cached, endpoint);
    }
    
    // 3. Load from database
    let rules = database.load_rules(service);
    redis_cache.set(service, rules, 300);
    memory_cache.insert(service, rules);
    
    match_endpoint(rules, endpoint)
}

fn match_endpoint(rules: &HashMap<String, bool>, endpoint: &str) -> Option<bool> {
    // Exact match
    if let Some(&allowed) = rules.get(endpoint) {
        return Some(allowed);
    }
    
    // Wildcard match
    for (pattern, &allowed) in rules {
        if pattern.ends_with("/*") {
            let prefix = &pattern[..pattern.len() - 2];
            if endpoint.starts_with(prefix) {
                return Some(allowed);
            }
        }
    }
    
    None  // Not in allowlist = deny
}
```

### 5. Verification Middleware

**Purpose**: Validates service tokens on inbound requests

**Verification Steps**:
```
1. Extract Authorization header
   ├─ Missing? → 401 MISSING_SERVICE_TOKEN
   └─ Present → Continue

2. Extract X-Service-Name header
   ├─ Missing? → 401 MISSING_SERVICE_NAME
   └─ Present → Continue

3. Validate JWT token
   ├─ Invalid signature? → 401 INVALID_SERVICE_TOKEN
   ├─ Expired? → 401 TOKEN_EXPIRED
   └─ Valid → Continue

4. Verify microservice:internal scope
   ├─ Missing? → 401 INSUFFICIENT_SCOPE
   └─ Present → Continue

5. Verify service name matches token subject
   ├─ Mismatch? → 403 SERVICE_IMPERSONATION
   └─ Match → Continue

6. Check service call allowlist
   ├─ Not allowed? → 403 SERVICE_NOT_AUTHORIZED
   ├─ Explicitly denied? → 403 SERVICE_NOT_AUTHORIZED
   └─ Allowed → Continue

7. Log authentication event to database

8. Inject AuthenticatedService into request extensions

9. Call next middleware/handler
```

### 6. Certificate Manager

**Purpose**: Manages mTLS certificates for service-to-service communication

**Certificate Lifecycle**:
```
┌─────────────────────┐
│ Generate RSA        │
│ Key Pair (2048-bit) │
└──────┬──────────────┘
       │
       ▼
┌─────────────────────┐
│ Create Certificate  │
│ Signing Request     │
│ (CSR)               │
└──────┬──────────────┘
       │
       ▼
┌─────────────────────┐
│ Sign with CA        │
│ Private Key         │
│ (1 year validity)   │
└──────┬──────────────┘
       │
       ▼
┌─────────────────────┐
│ Store Certificate   │
│ in Database         │
└──────┬──────────────┘
       │
       ▼
┌─────────────────────┐
│ Store Private Key   │
│ in Secrets Manager  │
└──────┬──────────────┘
       │
       ▼
┌─────────────────────┐
│ Monitor Expiry      │
│ (Alert at 30 days)  │
└──────┬──────────────┘
       │
       ▼
┌─────────────────────┐
│ Rotate Certificate  │
│ (Grace Period)      │
└─────────────────────┘
```

## Security Guarantees

### 1. Authentication
- ✅ Every service has unique credentials
- ✅ Tokens are short-lived (15 minutes)
- ✅ Tokens never persisted to disk or Redis
- ✅ Automatic token rotation before expiry
- ✅ Exponential backoff on failures

### 2. Authorization
- ✅ Service call allowlist enforcement
- ✅ Wildcard pattern support
- ✅ Explicit deny rules
- ✅ Default deny (not in allowlist = denied)

### 3. Identity Verification
- ✅ JWT signature validation
- ✅ Service name vs. token subject verification
- ✅ Impersonation attempt detection
- ✅ Scope enforcement

### 4. Auditability
- ✅ All authentication events logged
- ✅ Success and failure tracking
- ✅ Impersonation attempts flagged
- ✅ Request ID correlation

### 5. Operational Security
- ✅ Secret rotation with grace periods
- ✅ Certificate expiry monitoring
- ✅ Zero-downtime rotation
- ✅ Comprehensive metrics

## Performance Characteristics

### Token Manager
- Token acquisition: ~100ms (network call)
- Token cache hit: <1μs (memory lookup)
- Background refresh: Non-blocking
- Retry overhead: 100ms - 5s (exponential backoff)

### Allowlist
- Memory cache hit: <1μs
- Redis cache hit: ~1ms
- Database lookup: ~10ms
- Cache invalidation: Immediate (Redis pub/sub)

### Verification Middleware
- JWT validation: ~100μs
- Allowlist check: <1μs (cached)
- Audit logging: Async (non-blocking)
- Total overhead: ~200μs per request

### Scalability
- Token manager: One per service instance
- Allowlist cache: Shared across instances
- Database: Connection pooling
- Metrics: Aggregated by Prometheus

## Failure Modes & Recovery

### Token Acquisition Failure
**Symptom**: Service cannot acquire initial token

**Recovery**:
1. Retry with exponential backoff (3 attempts)
2. If all retries fail, service fails to start
3. Alert fires immediately
4. Manual intervention required

### Token Refresh Failure
**Symptom**: Background refresh fails

**Recovery**:
1. Retry with exponential backoff (3 attempts)
2. If all retries fail, alert fires
3. Service continues with cached token until expiry
4. On expiry, requests will fail with 401
5. Manual intervention required

### Allowlist Cache Miss
**Symptom**: Cache unavailable (Redis down)

**Recovery**:
1. Fall back to database lookup
2. Performance degradation (~10ms per request)
3. Service continues operating
4. Alert fires for Redis unavailability

### Database Unavailability
**Symptom**: Cannot load allowlist or audit logs

**Recovery**:
1. Allowlist: Use cached data (memory + Redis)
2. Audit logs: Queue in memory, flush when DB recovers
3. Service continues operating with cached data
4. Alert fires for database unavailability

### Certificate Expiry
**Symptom**: mTLS certificate expired

**Recovery**:
1. Alert fires 30 days before expiry
2. Rotate certificate with grace period
3. Both old and new certificates valid during grace period
4. Zero downtime

## Monitoring & Alerting

### Critical Alerts
1. **Token Refresh Failure**: Any failure after all retries
2. **Certificate Expiry**: <30 days remaining
3. **Service Impersonation**: Any impersonation attempt
4. **High Denial Rate**: >5% of requests denied

### Warning Alerts
1. **Token Acquisition Slow**: >500ms
2. **Allowlist Cache Miss Rate**: >10%
3. **Database Slow Queries**: >100ms
4. **Certificate Rotation Needed**: <60 days remaining

### Dashboards
1. **Token Lifecycle**: Acquisitions, refreshes, failures
2. **Authentication**: Success rate, denial rate, impersonation attempts
3. **Allowlist**: Cache hit rate, update frequency
4. **Certificates**: Expiry timeline, rotation events

## Future Enhancements

### Phase 2
- [ ] Service mesh integration (Istio/Linkerd)
- [ ] Hardware security module (HSM) integration
- [ ] Certificate transparency logging
- [ ] Automated certificate renewal

### Phase 3
- [ ] Service-to-service rate limiting
- [ ] Request signing for integrity
- [ ] Dynamic allowlist via control plane
- [ ] Multi-region certificate distribution

### Phase 4
- [ ] Service dependency graph visualization
- [ ] Anomaly detection for service calls
- [ ] Automated security policy generation
- [ ] Zero-trust network architecture
