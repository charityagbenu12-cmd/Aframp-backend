# Consumer Analytics Quick Start

Get started with the consumer usage analytics and reporting system in 5 minutes.

## Prerequisites

- Database migrations applied
- Audit logging enabled and collecting data
- Redis cache configured (for endpoint caching)

## 1. Run Database Migration

```bash
sqlx migrate run
```

This creates:
- `consumer_usage_snapshots` - Time-series usage aggregates
- `consumer_endpoint_usage` - Per-endpoint breakdown
- `consumer_feature_adoption` - Feature usage tracking
- `consumer_health_scores` - Integration health metrics
- `consumer_revenue_attribution` - Revenue tracking
- `consumer_usage_anomalies` - Anomaly detection results
- `platform_usage_reports` - Platform-wide reports
- `health_score_config` - Health scoring configuration

## 2. Start the Server

The analytics worker starts automatically with the application:

```bash
cargo run --features database
```

You should see:
```
✅ Analytics worker started
```

## 3. Test Consumer Endpoints

### Get Usage Summary
```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
  "http://localhost:8000/api/developer/usage/summary?period=today"
```

### Get Endpoint Usage
```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
  http://localhost:8000/api/developer/usage/endpoints
```

### Get Feature Adoption
```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
  http://localhost:8000/api/developer/usage/features
```

## 4. Test Admin Endpoints

### Get Consumer Overview
```bash
curl -H "Authorization: Bearer ADMIN_TOKEN" \
  http://localhost:8000/api/admin/analytics/consumers/overview
```

### Get At-Risk Consumers
```bash
curl -H "Authorization: Bearer ADMIN_TOKEN" \
  http://localhost:8000/api/admin/analytics/consumers/health
```

### Get Consumer Detail
```bash
curl -H "Authorization: Bearer ADMIN_TOKEN" \
  http://localhost:8000/api/admin/analytics/consumers/consumer_123/detail
```

### Get Platform Reports
```bash
curl -H "Authorization: Bearer ADMIN_TOKEN" \
  http://localhost:8000/api/admin/analytics/reports
```

## 5. Monitor Metrics

View analytics metrics at:
```
http://localhost:8000/metrics
```

Key metrics:
- `aframp_analytics_snapshots_generated_total` - Snapshot generation count
- `aframp_analytics_consumer_health_score` - Per-consumer health scores
- `aframp_analytics_at_risk_consumers_total` - At-risk consumer count
- `aframp_analytics_anomalies_detected_total` - Anomaly detection count

## 6. Run Example

```bash
cargo run --example analytics_usage --features database
```

This demonstrates:
- Snapshot generation
- Health score calculation
- Anomaly detection
- Report generation

## Configuration

### Worker Schedule
Edit `src/analytics/worker.rs` or set environment variables:

```bash
ANALYTICS_HOURLY_SNAPSHOTS=true
ANALYTICS_DAILY_SNAPSHOTS=true
ANALYTICS_HEALTH_SCORING=true
ANALYTICS_ANOMALY_DETECTION=true
ANALYTICS_CHECK_INTERVAL_SECS=300
```

### Health Score Weights
Update via SQL:

```sql
UPDATE health_score_config
SET error_rate_weight = 0.35,
    rate_limit_weight = 0.25,
    at_risk_threshold = 65
WHERE config_name = 'default';
```

### Anomaly Thresholds
Edit `AnomalyDetectionConfig` in code or add environment variables:

```bash
ANALYTICS_VOLUME_DROP_THRESHOLD=50.0
ANALYTICS_ERROR_SPIKE_THRESHOLD=200.0
ANALYTICS_INACTIVITY_WINDOW_HOURS=72
```

## Troubleshooting

### No snapshots generated
- Check audit logs contain data: `SELECT COUNT(*) FROM api_audit_logs;`
- Verify worker is running: Check logs for "Analytics worker started"
- Check snapshot generation log: `SELECT * FROM snapshot_generation_log ORDER BY started_at DESC LIMIT 5;`

### Health scores not updating
- Ensure daily snapshots are enabled
- Check health score config is active: `SELECT * FROM health_score_config WHERE is_active = true;`
- Verify consumers have recent activity

### Anomalies not detected
- Ensure sufficient historical data (7+ days)
- Check anomaly detection is enabled in worker config
- Review detection thresholds in `AnomalyDetectionConfig`

## Next Steps

- Review full documentation: `docs/CONSUMER_ANALYTICS.md`
- Configure Prometheus alerts: `monitoring/prometheus/rules/analytics_alerts.yml`
- Customize health score weights for your use case
- Set up report delivery automation
- Integrate with notification system for anomaly alerts
