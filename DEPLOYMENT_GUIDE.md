# Abuse Detection System - Deployment Guide

## Pre-Deployment Checklist

### 1. Environment Preparation
- [ ] PostgreSQL database accessible
- [ ] Redis instance running and accessible
- [ ] Prometheus configured for metrics scraping
- [ ] Admin accounts created with appropriate permissions
- [ ] Backup of current database taken

### 2. Configuration Review
- [ ] Review thresholds in `AbuseDetectionConfig`
- [ ] Adjust detection windows if needed
- [ ] Set confidence thresholds for response tiers
- [ ] Configure response durations
- [ ] Review and adjust all detection signal thresholds

### 3. Infrastructure
- [ ] Ensure Redis has sufficient memory (recommend 2GB+)
- [ ] Database has capacity for new tables
- [ ] Monitoring system ready for new metrics
- [ ] Alert manager configured for critical alerts

## Deployment Steps

### Step 1: Database Migration

```bash
# Connect to your database
psql -U postgres -d aframp

# Apply the migration
\i db/migrations/abuse_detection_schema.sql

# Verify tables created
\dt abuse_*

# Verify indexes
\di abuse_*

# Verify functions
\df has_active_abuse_response
\df get_active_rate_limit
\df is_signal_whitelisted
\df cleanup_expired_abuse_responses
```

Expected output:
```
abuse_cases
abuse_response_actions
abuse_signal_whitelist
abuse_detection_audit_log
rate_limit_adjustments
credential_suspensions
```

### Step 2: Configuration

Create or update your configuration file:

```rust
// config/production.toml or environment variables

[abuse_detection]
# Authentication abuse thresholds
credential_stuffing_threshold = 50
credential_stuffing_window_secs = 60
brute_force_threshold = 10
brute_force_window_secs = 60
token_harvesting_threshold = 100
token_harvesting_window_secs = 300

# Endpoint abuse thresholds
scraping_distinct_resources_threshold = 100
scraping_window_secs = 60
quote_farming_threshold = 50
quote_farming_window_secs = 300

# Transaction abuse thresholds
structuring_threshold = 5
structuring_window_secs = 3600
velocity_multiplier_threshold = 5.0
velocity_window_secs = 3600

# Confidence thresholds
monitor_confidence_threshold = 0.30
soft_response_confidence_threshold = 0.60
hard_response_confidence_threshold = 0.80
critical_response_confidence_threshold = 0.95

# Response durations
soft_response_duration_mins = 15
hard_response_duration_hours = 24
critical_response_permanent = true
```

### Step 3: Code Integration

Add to your main application:

```rust
use aframp::abuse_detection::{
    AbuseDetectionConfig,
    AbuseDetector,
    repository::AbuseDetectionRepository,
    middleware::abuse_check_middleware,
};

// Initialize detector
let abuse_config = Arc::new(AbuseDetectionConfig::from_env());
let abuse_detector = Arc::new(AbuseDetector::new(
    abuse_config.clone(),
    redis_cache.clone(),
));
let abuse_repo = Arc::new(AbuseDetectionRepository::new(db_pool.clone()));

// Add middleware to your router
let app = Router::new()
    .route("/api/...", ...)
    .layer(middleware::from_fn_with_state(
        AbuseDetectionState {
            detector: abuse_detector.clone(),
            repo: abuse_repo.clone(),
        },
        abuse_check_middleware,
    ))
    // ... other middleware
```

### Step 4: Metrics Configuration

Add to your Prometheus configuration:

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'aframp-abuse-detection'
    static_configs:
      - targets: ['localhost:9090']
    metrics_path: '/metrics'
    scrape_interval: 15s
```

### Step 5: Alerting Rules

Create alerting rules:

```yaml
# alerts/abuse_detection.yml
groups:
  - name: abuse_detection
    interval: 30s
    rules:
      - alert: CriticalAbuseResponseTriggered
        expr: increase(aframp_abuse_response_actions_total{tier="critical"}[5m]) > 0
        for: 0m
        labels:
          severity: critical
        annotations:
          summary: "Critical abuse response triggered"
          description: "A critical abuse response has been triggered. Immediate investigation required."

      - alert: HighFalsePositiveRate
        expr: rate(aframp_abuse_false_positives_total[1h]) > 0.1
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High false positive rate detected"
          description: "False positive rate exceeds 10%. Review detection thresholds."

      - alert: CoordinatedAttackDetected
        expr: increase(aframp_abuse_coordinated_attacks_total[5m]) > 0
        for: 0m
        labels:
          severity: critical
        annotations:
          summary: "Coordinated attack detected"
          description: "Multiple consumers showing correlated abuse patterns."
```

### Step 6: Testing in Staging

```bash
# Run unit tests
cargo test --lib abuse_detection

# Run example
cargo run --example abuse_detection_demo

# Test API endpoints
curl -X GET http://localhost:8080/api/admin/abuse/cases \
  -H "Authorization: Bearer $ADMIN_TOKEN"

# Trigger test signals (in staging only!)
# Credential stuffing test
for i in {1..60}; do
  curl -X POST http://localhost:8080/api/auth/login \
    -d "username=test$i&password=wrong"
done

# Check if signal detected
curl -X GET http://localhost:8080/api/admin/abuse/cases \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

### Step 7: Gradual Rollout

#### Phase 1: Monitor Mode (Week 1)
```rust
// Set all responses to monitor only
let config = AbuseDetectionConfig {
    soft_response_confidence_threshold: Decimal::new(100, 2), // 1.00 (never trigger)
    hard_response_confidence_threshold: Decimal::new(100, 2),
    critical_response_confidence_threshold: Decimal::new(100, 2),
    ..Default::default()
};
```

**Monitor:**
- Detection signal counts
- Confidence score distributions
- False positive rate
- Detection latency

#### Phase 2: Soft Responses (Week 2)
```rust
// Enable soft responses only
let config = AbuseDetectionConfig {
    soft_response_confidence_threshold: Decimal::new(60, 2), // 0.60
    hard_response_confidence_threshold: Decimal::new(100, 2), // Disabled
    critical_response_confidence_threshold: Decimal::new(100, 2), // Disabled
    ..Default::default()
};
```

**Monitor:**
- Rate limit adjustment effectiveness
- Consumer complaints
- False positive dismissals

#### Phase 3: Hard Responses (Week 3)
```rust
// Enable hard responses
let config = AbuseDetectionConfig {
    soft_response_confidence_threshold: Decimal::new(60, 2),
    hard_response_confidence_threshold: Decimal::new(80, 2), // 0.80
    critical_response_confidence_threshold: Decimal::new(100, 2), // Disabled
    ..Default::default()
};
```

**Monitor:**
- Suspension accuracy
- Appeal rate
- Attack mitigation effectiveness

#### Phase 4: Full Production (Week 4)
```rust
// Enable all response tiers
let config = AbuseDetectionConfig::default();
```

**Monitor:**
- All metrics
- Security incident reduction
- System performance

## Post-Deployment

### Monitoring Dashboard

Create Grafana dashboard with:

1. **Detection Overview**
   - Signals detected per hour
   - Confidence score distribution
   - Detection latency

2. **Response Actions**
   - Actions by tier (stacked area chart)
   - Active responses gauge
   - Response duration histogram

3. **Case Management**
   - Open cases by tier
   - Resolution time
   - False positive rate

4. **Performance**
   - Detection latency (p50, p95, p99)
   - Redis operation latency
   - Database query performance

### Daily Operations

#### Morning Checks (5 minutes)
```bash
# Check open cases
curl -X GET http://localhost:8080/api/admin/abuse/cases?status=open

# Check critical responses in last 24h
curl -X GET http://localhost:8080/api/admin/abuse/cases?tier=critical

# Review false positives
curl -X GET http://localhost:8080/api/admin/abuse/cases?status=dismissed
```

#### Weekly Review (30 minutes)
- Review false positive rate by signal type
- Adjust thresholds if needed
- Review coordinated attack patterns
- Update whitelist for legitimate high-volume users

#### Monthly Audit (2 hours)
- Full case review
- Threshold optimization
- Performance analysis
- Security incident correlation

### Maintenance Tasks

#### Daily
```sql
-- Check for expired responses (automatic cleanup)
SELECT cleanup_expired_abuse_responses();
```

#### Weekly
```sql
-- Review case statistics
SELECT
    status,
    response_tier,
    COUNT(*) as count,
    AVG(composite_confidence) as avg_confidence
FROM abuse_cases
WHERE created_at > NOW() - INTERVAL '7 days'
GROUP BY status, response_tier;
```

#### Monthly
```sql
-- Archive old resolved cases (optional)
INSERT INTO abuse_cases_archive
SELECT * FROM abuse_cases
WHERE status IN ('resolved', 'dismissed')
  AND resolved_at < NOW() - INTERVAL '90 days';

DELETE FROM abuse_cases
WHERE status IN ('resolved', 'dismissed')
  AND resolved_at < NOW() - INTERVAL '90 days';
```

## Rollback Plan

If issues arise:

### Step 1: Disable Automated Responses
```rust
// Set all thresholds to 1.0 (never trigger)
let config = AbuseDetectionConfig {
    soft_response_confidence_threshold: Decimal::new(100, 2),
    hard_response_confidence_threshold: Decimal::new(100, 2),
    critical_response_confidence_threshold: Decimal::new(100, 2),
    ..Default::default()
};
```

### Step 2: Remove Middleware
```rust
// Comment out abuse_check_middleware
// .layer(middleware::from_fn_with_state(...))
```

### Step 3: Clear Active Responses (if needed)
```sql
-- Remove all active soft responses
DELETE FROM rate_limit_adjustments
WHERE expires_at > NOW();

-- Remove all active suspensions (CAREFUL!)
-- Only do this if absolutely necessary
-- DELETE FROM credential_suspensions
-- WHERE expires_at > NOW();
```

### Step 4: Revert Database (last resort)
```sql
-- Drop all abuse detection tables
DROP TABLE IF EXISTS credential_suspensions CASCADE;
DROP TABLE IF EXISTS rate_limit_adjustments CASCADE;
DROP TABLE IF EXISTS abuse_detection_audit_log CASCADE;
DROP TABLE IF EXISTS abuse_signal_whitelist CASCADE;
DROP TABLE IF EXISTS abuse_response_actions CASCADE;
DROP TABLE IF EXISTS abuse_cases CASCADE;
DROP TYPE IF EXISTS abuse_case_status CASCADE;
```

## Troubleshooting

### High False Positive Rate

**Symptoms:** Many legitimate users flagged

**Solutions:**
1. Review and increase thresholds
2. Add legitimate high-volume users to whitelist
3. Adjust confidence scoring weights
4. Review detection windows

### Low Detection Rate

**Symptoms:** Known abuse not detected

**Solutions:**
1. Review and decrease thresholds
2. Check Redis connectivity
3. Verify signal recording is working
4. Review detection window configuration

### Performance Issues

**Symptoms:** High latency, slow responses

**Solutions:**
1. Check Redis performance
2. Review database query performance
3. Add more Redis memory
4. Optimize detection queries
5. Consider Redis cluster for scale

### Database Issues

**Symptoms:** Errors writing cases or responses

**Solutions:**
1. Check database connection pool
2. Verify table indexes exist
3. Check disk space
4. Review constraint violations in logs

## Support

For issues or questions:
1. Check logs: `grep "abuse_detection" /var/log/aframp.log`
2. Review metrics: `http://localhost:9090/metrics`
3. Check Redis: `redis-cli INFO`
4. Review database: `psql -d aframp -c "SELECT * FROM abuse_cases ORDER BY created_at DESC LIMIT 10"`

## Success Metrics

Track these KPIs:

- **Detection Accuracy**: > 95%
- **False Positive Rate**: < 5%
- **Detection Latency**: < 10ms p99
- **Response Time**: < 15ms total
- **Case Resolution Time**: < 24 hours average
- **Attack Mitigation**: > 90% of attacks blocked

---

**Deployment Complete! 🚀**

The abuse detection system is now protecting your platform from malicious API usage.
