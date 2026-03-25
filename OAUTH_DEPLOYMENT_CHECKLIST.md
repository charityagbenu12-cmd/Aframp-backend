# OAuth 2.0 Token System - Deployment Checklist

Complete checklist for deploying the OAuth 2.0 access token system to production.

## 🔐 Pre-Deployment Security

- [ ] Generate RS256 key pair
  ```bash
  openssl genrsa -out private_key.pem 2048
  openssl rsa -in private_key.pem -pubout -out public_key.pem
  ```

- [ ] Store private key in secure vault (AWS Secrets Manager, HashiCorp Vault, etc.)
- [ ] Verify public key matches private key
- [ ] Rotate keys according to security policy
- [ ] Document key rotation schedule
- [ ] Set up key versioning/management

## 🗄️ Database Setup

- [ ] PostgreSQL 12+ installed and running
- [ ] Database created: `aframp`
- [ ] Database user created with appropriate permissions
- [ ] Connection string verified: `postgresql://user:password@host:5432/aframp`
- [ ] Run migration:
  ```bash
  sqlx migrate run --database-url "postgresql://user:password@host:5432/aframp"
  ```
- [ ] Verify table created:
  ```bash
  psql -U user -d aframp -c "\dt token_registry"
  ```
- [ ] Verify indexes created:
  ```bash
  psql -U user -d aframp -c "\di token_registry*"
  ```
- [ ] Test database connection from application
- [ ] Set up database backups
- [ ] Set up database monitoring

## 🔴 Redis Setup

- [ ] Redis 6+ installed and running
- [ ] Redis connection string verified: `redis://host:6379`
- [ ] Redis persistence enabled (RDB or AOF)
- [ ] Redis memory limits configured
- [ ] Test Redis connection from application
- [ ] Set up Redis monitoring
- [ ] Set up Redis backups
- [ ] Configure Redis eviction policy

## ⚙️ Environment Configuration

- [ ] Create `.env` file with all required variables:
  ```bash
  OAUTH_ISSUER_URL=https://api.aframp.com
  OAUTH_API_AUDIENCE=api
  OAUTH_PRIVATE_KEY_PEM="-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----"
  OAUTH_KEY_ID=key_id_123
  OAUTH_JWKS_URL=https://auth.aframp.com/.well-known/jwks.json
  OAUTH_JWKS_REFRESH_INTERVAL_SECS=3600
  OAUTH_MAX_ACTIVE_TOKENS_PER_CONSUMER=10
  OAUTH_MAX_ISSUANCE_PER_CLIENT_PER_WINDOW=100
  OAUTH_RATE_LIMIT_WINDOW_SECS=60
  ```

- [ ] Verify all environment variables are set
- [ ] Test environment variable loading
- [ ] Document all configuration options
- [ ] Set up configuration management (e.g., AWS Parameter Store)

## 🏗️ Application Build

- [ ] Run tests:
  ```bash
  cargo test --lib auth::oauth_tests
  ```
- [ ] Run clippy:
  ```bash
  cargo clippy --all-targets --all-features
  ```
- [ ] Check formatting:
  ```bash
  cargo fmt --check
  ```
- [ ] Build release binary:
  ```bash
  cargo build --release
  ```
- [ ] Verify binary size is reasonable
- [ ] Test binary runs locally
- [ ] Create Docker image (if applicable)

## 📊 Observability Setup

### Prometheus Metrics
- [ ] Prometheus server running
- [ ] Scrape config includes `/metrics` endpoint
- [ ] Verify metrics are being collected:
  ```bash
  curl http://localhost:8000/metrics | grep aframp_tokens
  ```
- [ ] Set up Prometheus retention policy
- [ ] Set up Prometheus backup

### Structured Logging
- [ ] Logging configured (JSON format)
- [ ] Log level set appropriately (INFO for production)
- [ ] Logs being written to file or stdout
- [ ] Log rotation configured (if file-based)
- [ ] Logs being shipped to centralized logging (e.g., ELK, Datadog)
- [ ] Verify logs don't contain full tokens (only JTI)

### Alerting
- [ ] Set up alerts for validation failures:
  ```
  aframp_token_validation_failures_total > 100 in 5m
  ```
- [ ] Set up alerts for rate limit exceeded:
  ```
  aframp_token_rate_limit_exceeded_total > 10 in 5m
  ```
- [ ] Set up alerts for Redis connection failures
- [ ] Set up alerts for database connection failures
- [ ] Set up alerts for JWKS refresh failures
- [ ] Configure alert recipients (email, Slack, PagerDuty)

## 🧪 Testing

### Unit Tests
- [ ] All OAuth tests pass:
  ```bash
  cargo test --lib auth::oauth_tests
  ```
- [ ] All database tests pass:
  ```bash
  cargo test --lib database::token_registry_repository
  ```

### Integration Tests
- [ ] Token issuance works end-to-end
- [ ] Token validation works end-to-end
- [ ] Token revocation works
- [ ] Rate limiting works
- [ ] JWKS refresh works
- [ ] Redis caching works
- [ ] Database persistence works

### Manual Testing
- [ ] Issue token via API:
  ```bash
  curl -X POST http://localhost:8000/api/oauth/token \
    -H "Content-Type: application/json" \
    -d '{"consumer_id":"test","client_id":"test","consumer_type":"mobile_client","scope":"read","environment":"mainnet"}'
  ```
- [ ] Validate token via API
- [ ] Revoke token via API
- [ ] Verify token binding works
- [ ] Verify rate limiting works
- [ ] Verify expired tokens are rejected
- [ ] Verify revoked tokens are rejected

### Load Testing
- [ ] Load test token issuance (1000 req/s)
- [ ] Load test token validation (5000 req/s)
- [ ] Monitor CPU, memory, disk usage
- [ ] Monitor database connection pool
- [ ] Monitor Redis memory usage
- [ ] Verify no memory leaks

## 🔒 Security Testing

- [ ] Verify RS256 signature verification works
- [ ] Verify invalid signatures are rejected
- [ ] Verify token tampering is detected
- [ ] Verify expired tokens are rejected
- [ ] Verify binding validation works
- [ ] Verify environment validation works
- [ ] Verify rate limiting prevents abuse
- [ ] Verify no tokens logged in full
- [ ] Verify private key is not exposed
- [ ] Verify JWKS endpoint is accessible

## 📈 Performance Validation

- [ ] Token issuance latency < 100ms (p99)
- [ ] Token validation latency < 50ms (p99)
- [ ] Redis cache hit rate > 95%
- [ ] Database query latency < 10ms (p99)
- [ ] Memory usage stable over time
- [ ] CPU usage reasonable under load
- [ ] No connection pool exhaustion

## 🚀 Deployment

### Staging Deployment
- [ ] Deploy to staging environment
- [ ] Run smoke tests
- [ ] Monitor metrics and logs
- [ ] Verify all endpoints work
- [ ] Run load tests
- [ ] Verify alerting works
- [ ] Get approval from security team

### Production Deployment
- [ ] Create deployment plan
- [ ] Schedule maintenance window (if needed)
- [ ] Backup database
- [ ] Backup Redis
- [ ] Deploy application
- [ ] Verify application started
- [ ] Run smoke tests
- [ ] Monitor metrics and logs
- [ ] Verify alerting works
- [ ] Document deployment

### Post-Deployment
- [ ] Monitor metrics for 24 hours
- [ ] Monitor logs for errors
- [ ] Verify no performance degradation
- [ ] Verify no security issues
- [ ] Collect feedback from team
- [ ] Document lessons learned

## 📋 Documentation

- [ ] OAUTH_TOKEN_SYSTEM.md reviewed
- [ ] OAUTH_IMPLEMENTATION_GUIDE.md reviewed
- [ ] OAUTH_QUICK_REFERENCE.md reviewed
- [ ] OAUTH_GIT_WORKFLOW.md reviewed
- [ ] Runbook created for common tasks
- [ ] Troubleshooting guide created
- [ ] API documentation updated
- [ ] Architecture diagram created
- [ ] Security documentation created

## 🔄 Operational Procedures

### Daily Operations
- [ ] Monitor metrics dashboard
- [ ] Check logs for errors
- [ ] Verify no rate limit issues
- [ ] Verify no validation failures

### Weekly Operations
- [ ] Review metrics trends
- [ ] Review logs for patterns
- [ ] Check Redis memory usage
- [ ] Check database size

### Monthly Operations
- [ ] Review security logs
- [ ] Verify key rotation schedule
- [ ] Review performance metrics
- [ ] Plan capacity upgrades

### Quarterly Operations
- [ ] Security audit
- [ ] Performance review
- [ ] Disaster recovery drill
- [ ] Documentation review

## 🆘 Incident Response

- [ ] Incident response plan created
- [ ] On-call rotation established
- [ ] Escalation procedures documented
- [ ] Rollback procedures documented
- [ ] Communication plan established
- [ ] Post-incident review process established

## 📞 Support

- [ ] Support team trained on OAuth system
- [ ] Support documentation created
- [ ] FAQ created
- [ ] Common issues documented
- [ ] Troubleshooting guide created
- [ ] Support contact information documented

## ✅ Final Verification

- [ ] All checklist items completed
- [ ] All tests passing
- [ ] All metrics healthy
- [ ] All logs clean
- [ ] All documentation complete
- [ ] All team members trained
- [ ] All stakeholders notified
- [ ] Ready for production

## 🎯 Sign-Off

- [ ] Development team sign-off
- [ ] QA team sign-off
- [ ] Security team sign-off
- [ ] Operations team sign-off
- [ ] Product team sign-off

**Deployment Date**: _______________

**Deployed By**: _______________

**Approved By**: _______________

## 📝 Notes

```
[Space for deployment notes]
```

## 🔗 Related Documents

- OAUTH_TOKEN_SYSTEM.md - System overview
- OAUTH_IMPLEMENTATION_GUIDE.md - Implementation steps
- OAUTH_QUICK_REFERENCE.md - Quick reference
- OAUTH_GIT_WORKFLOW.md - Git workflow
- OAUTH_IMPLEMENTATION_SUMMARY.md - Summary

## 📞 Emergency Contacts

| Role | Name | Phone | Email |
|---|---|---|---|
| On-Call Engineer | | | |
| Security Lead | | | |
| Database Admin | | | |
| DevOps Lead | | | |

---

**Last Updated**: 2024-03-24
**Version**: 1.0
