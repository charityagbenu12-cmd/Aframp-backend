# Consumer Usage Analytics & Reporting System

Comprehensive business-level analytics for API consumer adoption, health monitoring, feature utilization, and revenue attribution.

## Overview

The analytics system provides deep visibility into API usage patterns for both individual consumers and platform administrators. It operates independently from transactional systems by computing analytics from audit logs, ensuring zero impact on primary database performance.

## Architecture

### Data Flow
```
API Requests → Audit Logs (Partitioned) → Analytics Worker → Usage Snapshots
                                                           → Health Scores
                                                           → Anomaly Detection
                                                           → Reports
```

### Components

1. **Snapshot Generator**: Computes time-series usage aggregates (hourly, daily, weekly, monthly)
2. **Health Score Calculator**: Evaluates consumer integration health using weighted factors
3. **Anomaly Detector**: Identifies volume drops, error spikes, and inactivity patterns
4. **Report Generator**: Creates platform-wide and per-consumer usage reports
5. **Analytics Worker**: Background job orchestrating all analytics operations

## Consumer-Facing Endpoints

### GET /api/developer/usage/summary
Usage summary for the authenticated consumer.

**Query Parameters:**
- `period`: `current_hour`, `today`, `this_week`, `this_month` (default)

**Response:**
```json
{
  "period": "this_month",
  "period_start": "2026-03-01T00:00:00Z",
  "period_end": "2026-03-27T12:00:00Z",
  "total_requests": 15420,
  "error_rate": 0.0234,
  "rate_limit_utilization": 0.67,
  "active_features": ["onramp", "offramp", "bills"],
  "health_score": 87
}
```

### GET /api/developer/usage/endpoints
Per-endpoint usage breakdown with performance metrics.

**Response:**
```json
[
  {
    "endpoint_path": "/api/onramp/quote",
    "http_method": "POST",
    "request_count": 8420,
    "error_rate": 0.0156,
    "avg_latency_ms": 245
  }
]
```

### GET /api/developer/usage/features
Feature adoption summary showing platform feature usage.

**Response:**
```json
[
  {
    "feature_name": "onramp",
    "first_used_at": "2026-01-15T10:30:00Z",
    "last_used_at": "2026-03-27T11:45:00Z",
    "total_usage_count": 8420,
    "is_active": true
  }
]
```

## Admin Analytics Endpoints

### GET /api/admin/analytics/consumers/overview
Platform-wide consumer adoption overview.

**Response:**
```json
{
  "total_registered_consumers": 245,
  "active_consumers_by_tier": {
    "free": 180,
    "starter": 45,
    "professional": 15,
    "enterprise": 5
  },
  "new_consumers_this_period": 12,
  "consumer_growth_trend": [
    {"period": "2026-03", "count": 12},
    {"period": "2026-02", "count": 18}
  ]
}
```

### GET /api/admin/analytics/consumers/health
Consumer health score distribution and at-risk consumers.

**Response:**
```json
[
  {
    "consumer_id": "consumer_abc123",
    "health_score": 45,
    "risk_factors": ["high_error_rate", "low_activity"],
    "last_activity": "2026-03-25T14:30:00Z"
  }
]
```

### GET /api/admin/analytics/consumers/:consumer_id/detail
Full analytics detail for a specific consumer.

**Response:**
```json
{
  "consumer_id": "consumer_abc123",
  "snapshots": [...],
  "health_score": {...},
  "features": [...]
}
```

### GET /api/admin/analytics/reports
List of generated platform usage reports.

**Response:**
```json
[
  {
    "id": "uuid",
    "report_type": "weekly",
    "report_period_start": "2026-03-20T00:00:00Z",
    "report_period_end": "2026-03-27T00:00:00Z",
    "total_api_requests": 125000,
    "platform_error_rate": 0.0189,
    "active_consumers": 198,
    "at_risk_consumers": 8,
    "generated_at": "2026-03-27T00:00:00Z"
  }
]
```

## Health Score Model

Health scores range from 0-100 and are calculated using weighted contributing factors:

| Factor | Weight | Description |
|--------|--------|-------------|
| Error Rate | 30% | Request failure rate over lookback period |
| Rate Limiting | 20% | Frequency of rate limit breaches |
| Auth Failures | 15% | Authentication failure rate |
| Webhook Delivery | 20% | Webhook delivery success rate |
| Activity Recency | 15% | Time since last API request |

### Health Score Bands
- **90-100**: Excellent - Integration performing optimally
- **70-89**: Good - Minor issues, monitoring recommended
- **50-69**: Fair - Attention needed, review integration
- **0-49**: Poor - Critical issues, immediate action required

### Trend Classification
- **Improving**: Score increased >5 points vs rolling average
- **Stable**: Score within ±5 points of rolling average
- **Declining**: Score decreased >5 points vs rolling average

## Anomaly Detection

### Volume Drop
Triggered when request volume drops by >50% compared to rolling 7-day average.

**Severity Levels:**
- Critical: >80% drop
- High: 60-80% drop
- Medium: 50-60% drop

### Error Spike
Triggered when error rate increases by >200% compared to rolling average.

**Severity Levels:**
- Critical: Error rate >20%
- High: Error rate 10-20%
- Medium: Error rate 5-10%

### Inactivity
Triggered when no requests received within 72-hour window.

**Severity Levels:**
- High: Inactive >7 days
- Medium: Inactive 3-7 days

## Snapshot Generation

### Incremental Computation
Snapshots use UPSERT logic to recompute only the current incomplete period, avoiding reprocessing of historical data.

### Schedule
- **Hourly**: Top of each hour (minute 0)
- **Daily**: Midnight UTC
- **Weekly**: Monday midnight UTC
- **Monthly**: 1st of month midnight UTC

### Performance
- Queries run against partitioned `api_audit_logs` tables
- No load on transactional database
- Typical daily snapshot: <30s for 200 consumers
- Metrics tracked: duration, success rate, consumer count

## Caching Strategy

All analytics endpoints are cached in Redis with appropriate TTLs:

| Endpoint | TTL | Rationale |
|----------|-----|-----------|
| Usage Summary | 5 min | Frequently updated |
| Endpoint Usage | 10 min | Moderate volatility |
| Feature Adoption | 1 hour | Low volatility |
| Health Scores | 15 min | Daily updates |
| Consumer Overview | 5 min | Platform stats |
| Reports List | 1 hour | Historical data |

## Monitoring & Alerts

### Prometheus Metrics
- `aframp_analytics_snapshots_generated_total{period, status}`
- `aframp_analytics_snapshot_generation_duration_seconds{period}`
- `aframp_analytics_consumer_health_score{consumer_id}`
- `aframp_analytics_at_risk_consumers_total`
- `aframp_analytics_anomalies_detected_total{anomaly_type, severity}`
- `aframp_analytics_active_consumers_by_tier{tier}`

### Alert Rules
- **AnalyticsSnapshotGenerationFailed**: Snapshot generation failures
- **AnalyticsSnapshotGenerationSlow**: Generation time >120s
- **HighAtRiskConsumerCount**: >10 at-risk consumers
- **CriticalAtRiskConsumerCount**: >25 at-risk consumers (platform issue)
- **HighUsageAnomalyRate**: Anomaly detection rate spike
- **AnalyticsSnapshotGenerationStalled**: No snapshots in 2 hours

## Configuration

### Environment Variables
```bash
# Worker configuration
ANALYTICS_HOURLY_SNAPSHOTS=true
ANALYTICS_DAILY_SNAPSHOTS=true
ANALYTICS_HEALTH_SCORING=true
ANALYTICS_ANOMALY_DETECTION=true
ANALYTICS_CHECK_INTERVAL_SECS=300

# Anomaly detection thresholds
ANALYTICS_VOLUME_DROP_THRESHOLD=50.0
ANALYTICS_ERROR_SPIKE_THRESHOLD=200.0
ANALYTICS_INACTIVITY_WINDOW_HOURS=72
```

### Health Score Configuration
Stored in `health_score_config` table. Update via admin API or direct SQL:

```sql
UPDATE health_score_config
SET error_rate_weight = 0.35,
    at_risk_threshold = 65
WHERE config_name = 'default';
```

## Usage Example

```rust
use Bitmesh_backend::analytics::*;

// Initialize analytics system
let pool = Arc::new(PgPool::connect(&database_url).await?);
let worker = AnalyticsWorker::new(pool, AnalyticsWorkerConfig::default());

// Start background worker
let (shutdown_tx, shutdown_rx) = watch::channel(false);
tokio::spawn(async move {
    worker.run(shutdown_rx).await;
});

// Query consumer usage
let repo = AnalyticsRepository::new(pool.as_ref().clone());
let snapshots = repo
    .get_consumer_snapshots("consumer_123", SnapshotPeriod::Daily, 30)
    .await?;

// Calculate health score
let calculator = HealthScoreCalculator::new(pool.clone(), Arc::new(repo));
let health = calculator.calculate_health_score("consumer_123").await?;
```

## Testing

Run integration tests:
```bash
cargo test --test analytics_integration --features database
```

Run example:
```bash
cargo run --example analytics_usage --features database
```

## Performance Considerations

1. **Query Optimization**: All analytics queries use indexes on partitioned audit log tables
2. **Incremental Processing**: Only current incomplete periods are recomputed
3. **Batch Processing**: Consumers processed in batches to manage memory
4. **Cache-First**: All read endpoints check Redis before hitting database
5. **Async Processing**: Snapshot generation runs in background without blocking API

## Future Enhancements

- Real-time streaming analytics via Redis pub/sub
- Machine learning-based anomaly detection
- Predictive churn modeling
- Custom dashboard builder for consumers
- Automated integration health recommendations
- Revenue forecasting per consumer tier
