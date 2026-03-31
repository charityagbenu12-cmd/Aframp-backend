# Microservice Authentication - Deployment Checklist

## Pre-Deployment

### 1. Code Review
- [ ] Review all service authentication code
- [ ] Verify security best practices followed
- [ ] Check for hardcoded secrets (should be none)
- [ ] Review error handling and logging
- [ ] Verify metrics are properly instrumented

### 2. Testing
- [ ] Run unit tests: `cargo test service_auth::tests`
- [ ] Run integration tests: `cargo test --test service_auth_test --features database -- --ignored`
- [ ] Test service registration flow
- [ ] Test token acquisition and refresh
- [ ] Test allowlist enforcement
- [ ] Test certificate generation
- [ ] Test secret rotation
- [ ] Verify metrics are collected

### 3. Database Preparation
- [ ] Review migration file: `migrations/20260326000001_service_identity.sql`
- [ ] Test migration on staging database
- [ ] Verify indexes are created
- [ ] Check foreign key constraints
- [ ] Backup production database before migration

### 4. Configuration
- [ ] Set up secrets manager (AWS Secrets Manager, Vault, etc.)
- [ ] Generate CA certificate for mTLS
- [ ] Store CA private key securely
- [ ] Configure OAuth token endpoint URL
- [ ] Set JWT secret for token verification
- [ ] Configure Redis for caching

## Deployment Steps

### Phase 1: Infrastructure Setup

#### 1.1 Apply Database Migrations
```bash
# Staging
sqlx migrate run --database-url $STAGING_DATABASE_URL

# Production (after staging verification)
sqlx migrate run --database-url $PRODUCTION_DATABASE_URL
```
- [ ] Migrations applied to staging
- [ ] Migrations verified on staging
- [ ] Migrations applied to production
- [ ] Tables created successfully
- [ ] Indexes created successfully

#### 1.2 Deploy Prometheus Alerting Rules
```bash
kubectl apply -f docs/SERVICE_AUTH_ALERTS.yaml
```
- [ ] Alerting rules deployed
- [ ] Alerts visible in Prometheus
- [ ] Alert routing configured in Alertmanager
- [ ] Test alerts fire correctly

#### 1.3 Configure Secrets Manager
```bash
# Example for AWS Secrets Manager
aws secretsmanager create-secret \
  --name service-auth/ca-certificate \
  --secret-string file://ca-cert.pem

aws secretsmanager create-secret \
  --name service-auth/ca-private-key \
  --secret-string file://ca-key.pem
```
- [ ] CA certificate stored
- [ ] CA private key stored
- [ ] Access policies configured
- [ ] Service accounts have read access

### Phase 2: Service Registration

#### 2.1 Register Core Services
For each service (worker, settlement, analytics, admin):

```bash
curl -X POST https://api.aframp.com/admin/services/register \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{
    "service_name": "worker_service",
    "allowed_scopes": ["worker:execute"],
    "allowed_targets": ["/api/settlement/*", "/api/analytics/*"]
  }'
```

Services to register:
- [ ] worker_service
- [ ] settlement_service
- [ ] analytics_service
- [ ] admin_service
- [ ] (add other services as needed)

For each service:
- [ ] Service registered successfully
- [ ] Client ID received
- [ ] Client secret received and stored in secrets manager
- [ ] Allowed scopes configured
- [ ] Allowed targets documented

#### 2.2 Configure Service Allowlists
For each service, configure which endpoints it can call:

```bash
# Worker service can call settlement endpoints
curl -X POST https://api.aframp.com/admin/services/allowlist/add \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{
    "calling_service": "worker_service",
    "target_endpoint": "/api/settlement/*",
    "allowed": true
  }'
```

Allowlist configurations:
- [ ] worker_service → settlement endpoints
- [ ] worker_service → analytics endpoints
- [ ] settlement_service → blockchain endpoints
- [ ] analytics_service → data endpoints
- [ ] admin_service → all internal endpoints
- [ ] (add other rules as needed)

For each rule:
- [ ] Rule added successfully
- [ ] Rule visible in allowlist
- [ ] Cache invalidated

### Phase 3: Service Updates

#### 3.1 Update Service Configuration
For each service, add environment variables:

```bash
# Service identity
SERVICE_NAME=worker_service
SERVICE_CLIENT_ID=service_worker_service
SERVICE_CLIENT_SECRET=<from-secrets-manager>

# OAuth configuration
OAUTH_TOKEN_ENDPOINT=https://api.aframp.com/oauth/token

# JWT verification
JWT_SECRET=<from-secrets-manager>

# Token refresh configuration (optional, uses defaults if not set)
SERVICE_TOKEN_REFRESH_THRESHOLD=0.2
SERVICE_TOKEN_MAX_RETRIES=3
SERVICE_TOKEN_INITIAL_BACKOFF_MS=100
SERVICE_TOKEN_MAX_BACKOFF_MS=5000
```

Services configured:
- [ ] worker_service
- [ ] settlement_service
- [ ] analytics_service
- [ ] admin_service
- [ ] (add other services)

#### 3.2 Update Service Code
For each service:

1. Initialize token manager at startup:
```rust
let token_manager = Arc::new(ServiceTokenManager::new(
    env::var("SERVICE_NAME")?,
    env::var("SERVICE_CLIENT_ID")?,
    env::var("SERVICE_CLIENT_SECRET")?,
    env::var("OAUTH_TOKEN_ENDPOINT")?,
    TokenRefreshConfig::default(),
));

token_manager.initialize().await?;
token_manager.clone().start_refresh_task();
```

2. Use ServiceHttpClient for outbound calls:
```rust
let client = ServiceHttpClient::new(
    service_name,
    token_manager.clone(),
);
```

3. Apply verification middleware to internal endpoints:
```rust
let auth_state = ServiceAuthState {
    pool: pool.clone(),
    allowlist: allowlist.clone(),
    jwt_secret: config.jwt_secret.clone(),
};

let app = Router::new()
    .route("/api/internal/*", ...)
    .layer(middleware::from_fn_with_state(
        auth_state,
        service_token_verification,
    ));
```

Code updates:
- [ ] worker_service updated
- [ ] settlement_service updated
- [ ] analytics_service updated
- [ ] admin_service updated
- [ ] (add other services)

#### 3.3 Deploy Updated Services
Deploy services one at a time with monitoring:

```bash
# Deploy to staging first
kubectl apply -f k8s/staging/worker-service.yaml

# Monitor for issues
kubectl logs -f deployment/worker-service -n staging

# Check metrics
curl https://staging.api.aframp.com/metrics | grep service_token

# If successful, deploy to production
kubectl apply -f k8s/production/worker-service.yaml
```

Deployments:
- [ ] worker_service deployed to staging
- [ ] worker_service verified on staging
- [ ] worker_service deployed to production
- [ ] settlement_service deployed to staging
- [ ] settlement_service verified on staging
- [ ] settlement_service deployed to production
- [ ] analytics_service deployed to staging
- [ ] analytics_service verified on staging
- [ ] analytics_service deployed to production
- [ ] admin_service deployed to staging
- [ ] admin_service verified on staging
- [ ] admin_service deployed to production

### Phase 4: Verification

#### 4.1 Verify Service Registration
```bash
# List all registered services
curl https://api.aframp.com/admin/services \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```
- [ ] All services listed
- [ ] Client IDs correct
- [ ] Allowed scopes correct
- [ ] Status is 'active'

#### 4.2 Verify Allowlist Configuration
```bash
# List all allowlist entries
curl https://api.aframp.com/admin/services/allowlist \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```
- [ ] All rules present
- [ ] Rules are correct
- [ ] No unexpected rules

#### 4.3 Verify Token Acquisition
Check service logs for successful token acquisition:
```bash
kubectl logs deployment/worker-service | grep "Service token acquired"
```
- [ ] worker_service acquiring tokens
- [ ] settlement_service acquiring tokens
- [ ] analytics_service acquiring tokens
- [ ] admin_service acquiring tokens
- [ ] No token acquisition failures

#### 4.4 Verify Service-to-Service Calls
Check logs for successful authenticated calls:
```bash
kubectl logs deployment/worker-service | grep "Service authentication successful"
```
- [ ] worker_service → settlement_service working
- [ ] worker_service → analytics_service working
- [ ] settlement_service → blockchain_service working
- [ ] analytics_service → data_service working
- [ ] No authentication failures

#### 4.5 Verify Metrics
```bash
curl https://api.aframp.com/metrics | grep aframp_service
```

Check for:
- [ ] `aframp_service_token_acquisitions_total` > 0
- [ ] `aframp_service_token_refresh_events_total` > 0
- [ ] `aframp_service_token_refresh_failures_total` == 0
- [ ] `aframp_service_call_authentications_total{result="success"}` > 0
- [ ] `aframp_service_call_authorization_denials_total` == 0 (or expected)

#### 4.6 Verify Audit Logging
```sql
-- Check recent authentication events
SELECT 
    calling_service,
    target_endpoint,
    auth_result,
    COUNT(*) as count
FROM service_auth_audit
WHERE created_at > NOW() - INTERVAL '1 hour'
GROUP BY calling_service, target_endpoint, auth_result
ORDER BY count DESC;
```
- [ ] Authentication events being logged
- [ ] Success events present
- [ ] No unexpected failures
- [ ] No impersonation attempts

#### 4.7 Test Negative Cases
Test that security controls work:

1. Test invalid token:
```bash
curl https://api.aframp.com/api/internal/settlement \
  -H "Authorization: Bearer invalid-token"
# Expected: 401 INVALID_SERVICE_TOKEN
```
- [ ] Invalid token rejected

2. Test missing service name:
```bash
curl https://api.aframp.com/api/internal/settlement \
  -H "Authorization: Bearer $VALID_TOKEN"
# Expected: 401 MISSING_SERVICE_NAME
```
- [ ] Missing service name rejected

3. Test service impersonation:
```bash
curl https://api.aframp.com/api/internal/settlement \
  -H "Authorization: Bearer $WORKER_TOKEN" \
  -H "X-Service-Name: admin_service"
# Expected: 403 SERVICE_IMPERSONATION
```
- [ ] Impersonation attempt rejected
- [ ] Impersonation logged to audit table

4. Test unauthorized endpoint:
```bash
# Worker calling admin endpoint (not in allowlist)
curl https://api.aframp.com/api/admin/users \
  -H "Authorization: Bearer $WORKER_TOKEN" \
  -H "X-Service-Name: worker_service"
# Expected: 403 SERVICE_NOT_AUTHORIZED
```
- [ ] Unauthorized call rejected
- [ ] Denial logged to metrics

### Phase 5: Monitoring Setup

#### 5.1 Configure Dashboards
Create Grafana dashboards for:
- [ ] Token lifecycle (acquisitions, refreshes, failures)
- [ ] Authentication success rate
- [ ] Authorization denial rate
- [ ] Service call patterns
- [ ] Certificate expiry timeline

#### 5.2 Verify Alerts
Test that alerts fire correctly:
- [ ] Token refresh failure alert
- [ ] Certificate expiry alert
- [ ] Service impersonation alert
- [ ] High denial rate alert
- [ ] SLO breach alerts

#### 5.3 Set Up On-Call Runbooks
- [ ] Token refresh failure runbook
- [ ] Certificate rotation runbook
- [ ] Service impersonation runbook
- [ ] High denial rate runbook
- [ ] SLO breach runbook

## Post-Deployment

### 1. Documentation
- [ ] Update internal wiki with service auth documentation
- [ ] Share quick start guide with development teams
- [ ] Document service registration process
- [ ] Document allowlist management process
- [ ] Document secret rotation process

### 2. Training
- [ ] Train development teams on service auth
- [ ] Train operations teams on monitoring and alerting
- [ ] Train security teams on audit log analysis
- [ ] Conduct incident response drill

### 3. Ongoing Maintenance
- [ ] Schedule quarterly allowlist review
- [ ] Schedule quarterly secret rotation
- [ ] Schedule annual certificate rotation
- [ ] Monitor metrics weekly
- [ ] Review audit logs monthly

## Rollback Plan

If issues are encountered:

### 1. Immediate Rollback
```bash
# Revert service deployments
kubectl rollout undo deployment/worker-service
kubectl rollout undo deployment/settlement-service
# ... for each service
```
- [ ] Services reverted to previous version
- [ ] Service-to-service calls working without auth
- [ ] No authentication errors

### 2. Database Rollback
```bash
# Rollback migration (if needed)
sqlx migrate revert --database-url $DATABASE_URL
```
- [ ] Migration reverted
- [ ] Tables dropped
- [ ] No data loss

### 3. Configuration Cleanup
- [ ] Remove service registrations
- [ ] Clear allowlist entries
- [ ] Remove secrets from secrets manager
- [ ] Remove alerting rules

## Sign-Off

### Development Team
- [ ] Code reviewed and approved
- [ ] Tests passing
- [ ] Documentation complete

**Signed**: _________________ Date: _________

### Operations Team
- [ ] Infrastructure ready
- [ ] Monitoring configured
- [ ] Runbooks prepared

**Signed**: _________________ Date: _________

### Security Team
- [ ] Security review complete
- [ ] Audit logging verified
- [ ] Compliance requirements met

**Signed**: _________________ Date: _________

### Product Owner
- [ ] Acceptance criteria met
- [ ] Ready for production

**Signed**: _________________ Date: _________
