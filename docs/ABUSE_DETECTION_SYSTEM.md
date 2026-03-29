# Abuse Detection and Automated Response System

## Overview

The Abuse Detection System is a comprehensive, multi-layered framework that identifies and neutralizes malicious or negligent API usage patterns in real time. It operates independently of rate limiting, focusing on the quality and intent of API usage rather than just volume.

## Architecture

### Detection Categories

#### 1. Authentication Abuse
- **Credential Stuffing**: High volumes of authentication attempts with varying credentials
- **Brute Force**: Excessive failed authentication attempts against a single account
- **Token Harvesting**: Unusually high token issuance rates relative to usage
- **API Key Enumeration**: Systematic attempts to discover valid API key prefixes

#### 2. Endpoint Abuse
- **Scraping**: Sequential requests across large numbers of distinct resource identifiers
- **Quote Farming**: High volumes of quote generation without transaction initiation
- **Status Polling Abuse**: Excessive polling frequency beyond legitimate monitoring needs
- **Error Farming**: High volumes of requests resulting in 4xx errors (probing for valid inputs)

#### 3. Transaction Abuse
- **Structuring**: Multiple transactions just below reporting thresholds
- **Velocity Abuse**: Transaction rates significantly exceeding historical patterns
- **Round-Trip Detection**: Onramp transactions immediately followed by offramp for same amount
- **New Consumer High Value**: High-value transactions before establishing normal history

#### 4. Coordinated Abuse
- **Multi-Consumer Coordination**: Correlated abuse signals across multiple consumers
- **Distributed Credential Stuffing**: Attacks spread across multiple accounts and IPs
- **Sybil Detection**: Multiple accounts with similar characteristics to multiply rate limits

### Detection Windows

- **Short Window (1 minute)**: Fast-moving attacks requiring immediate response
- **Medium Window (1 hour)**: Sustained abuse patterns
- **Long Window (24 hours)**: Slow and low abuse strategies

### Confidence Scoring

Each detection signal contributes a confidence score (0.0 - 1.0) based on:
- Severity of the violation
- Ratio of observed behavior to threshold
- Historical patterns for the consumer

Multiple signals are combined using weighted averaging with diminishing returns:
- First signal: 100% weight
- Second signal: 70% weight
- Third signal: 50% weight
- Fourth signal: 30% weight
- Additional signals: 20% weight each

### Response Tiers

#### Monitor (Confidence: 0.30 - 0.60)
- **Actions**: Log event, send alert
- **Consumer Impact**: None
- **Use Case**: Low-confidence signals requiring human review

#### Soft (Confidence: 0.60 - 0.80)
- **Actions**: Apply rate limit tightening (typically 50% reduction)
- **Duration**: 15 minutes (configurable)
- **Consumer Impact**: Reduced request capacity
- **Use Case**: Suspicious patterns that may be legitimate high-volume usage

#### Hard (Confidence: 0.80 - 0.95)
- **Actions**: Suspend all API keys and tokens, notify consumer with appeal process
- **Duration**: 24 hours (configurable)
- **Consumer Impact**: Complete API access suspension
- **Use Case**: Clear abuse patterns requiring temporary lockout

#### Critical (Confidence: 0.95+)
- **Actions**: Revoke all credentials, flag account, notify security team
- **Duration**: Permanent (configurable)
- **Consumer Impact**: Account termination
- **Use Case**: Severe violations or coordinated attacks

## Implementation

### Database Schema

```sql
-- Core tables
- abuse_cases: Tracks all detected abuse incidents
- abuse_response_actions: Records automated responses
- abuse_signal_whitelist: Consumer-specific signal exemptions
- abuse_detection_audit_log: Complete audit trail
- rate_limit_adjustments: Active rate limit modifications
- credential_suspensions: Suspended keys and tokens
```

### API Endpoints

#### Admin Case Management

```
GET    /api/admin/abuse/cases
GET    /api/admin/abuse/cases/:case_id
POST   /api/admin/abuse/cases/:case_id/escalate
POST   /api/admin/abuse/cases/:case_id/dismiss
POST   /api/admin/abuse/cases/:case_id/resolve
```

### Metrics

All metrics are exposed at `/metrics` in Prometheus format:

```
aframp_abuse_signals_detected_total{signal_type, category}
aframp_abuse_confidence_score{consumer_type}
aframp_abuse_response_actions_total{tier}
aframp_abuse_false_positives_total{signal_type}
aframp_abuse_cases_open{tier}
aframp_abuse_cases_resolved_total{tier, outcome}
aframp_abuse_coordinated_attacks_total{attack_type}
aframp_abuse_detection_duration_seconds{check_type}
```

### Integration Points

#### 1. Authentication Middleware
```rust
// Record authentication failures
detector.record_auth_failure(consumer_id, ip_address).await?;

// Check for credential stuffing
if let Some(signal) = detector.check_credential_stuffing(consumer_id, ip_address).await? {
    // Process signal
}
```

#### 2. API Key Middleware
```rust
// Record invalid key attempts
detector.record_invalid_key(ip_address, key_prefix).await?;

// Check for key enumeration
if let Some(signal) = detector.check_key_enumeration(ip_address).await? {
    // Process signal
}
```

#### 3. Transaction Processing
```rust
// Record quote generation
detector.record_quote(consumer_id).await?;

// Record transaction initiation
detector.record_initiation(consumer_id).await?;

// Check for quote farming
if let Some(signal) = detector.check_quote_farming(consumer_id).await? {
    // Process signal
}
```

#### 4. Request Middleware
```rust
// Check for active abuse responses
let responses = repo.get_active_responses(consumer_id).await?;
for response in responses {
    match response.tier {
        ResponseTier::Hard | ResponseTier::Critical => {
            return Err(StatusCode::FORBIDDEN);
        }
        _ => {}
    }
}
```

## Configuration

All thresholds are configurable via `AbuseDetectionConfig`:

```rust
let config = AbuseDetectionConfig {
    // Authentication abuse
    credential_stuffing_threshold: 50,
    brute_force_threshold: 10,
    token_harvesting_threshold: 100,
    
    // Endpoint abuse
    scraping_distinct_resources_threshold: 100,
    quote_farming_threshold: 50,
    status_polling_threshold: 100,
    
    // Transaction abuse
    structuring_threshold: 5,
    velocity_multiplier_threshold: Decimal::new(50, 1), // 5.0x
    
    // Confidence thresholds
    soft_response_confidence_threshold: Decimal::new(60, 2),
    hard_response_confidence_threshold: Decimal::new(80, 2),
    critical_response_confidence_threshold: Decimal::new(95, 2),
    
    ..Default::default()
};
```

## Operational Procedures

### Handling False Positives

1. Review the abuse case in admin panel
2. Examine all detection signals and evidence
3. If legitimate, dismiss the case with reason
4. Optionally whitelist specific signal types for the consumer
5. System automatically removes response actions

### Escalating Cases

1. Review open cases regularly
2. For cases requiring stronger action, escalate to higher tier
3. System applies new response tier immediately
4. Original evidence is preserved

### Monitoring

Key metrics to monitor:
- False positive rate by signal type
- Response action distribution
- Average confidence scores
- Case resolution time
- Coordinated attack frequency

### Alerting

Critical alerts fire immediately for:
- Hard or critical response actions
- Coordinated attacks detected
- False positive rate exceeding threshold
- Unusual spike in abuse signals

## Testing

Comprehensive test coverage includes:
- Unit tests for confidence scoring
- Integration tests for signal detection
- End-to-end tests for response application
- Load tests for detection performance

Run tests:
```bash
cargo test --package aframp --lib abuse_detection
```

## Performance Considerations

- Redis-backed counters for real-time detection
- Asynchronous signal processing
- Database indexes on all query paths
- Configurable detection windows to balance accuracy vs. performance
- Batch processing for coordinated abuse detection

## Security Considerations

- All evidence is logged to immutable audit trail
- Consumer PII is masked in logs
- Admin actions require elevated permissions
- Appeal process provides transparency
- Automatic expiry of temporary responses

## Future Enhancements

- Machine learning-based confidence scoring
- Behavioral profiling for velocity abuse
- Geographic correlation for impossible travel
- Integration with external threat intelligence feeds
- Automated pattern recognition for new abuse types
