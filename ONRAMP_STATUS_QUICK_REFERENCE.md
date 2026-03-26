# Onramp Status Endpoint - Quick Reference

## Endpoint
```
GET /api/onramp/status/:tx_id
```

## Response Structure
```rust
OnrampStatusResponse {
    tx_id: String,
    status: String,                    // "pending" | "processing" | "completed" | "failed" | "refunded"
    stage: TransactionStage,           // User-friendly stage enum
    message: String,                   // Human-readable status message
    failure_reason: Option<String>,    // Error details if failed
    transaction: TransactionDetail,    // Core transaction info
    provider_status: Option<ProviderStatus>,  // Payment provider status
    blockchain: Option<BlockchainStatus>,     // Stellar blockchain status
    timeline: Vec<TimelineEntry>,      // Status change history
}
```

## Status Flow
```
pending → processing → completed
    ↓         ↓
  failed   failed
    ↓         ↓
 refunded  refunded
```

## Cache TTL by Status
- **pending**: 5 seconds
- **processing**: 10 seconds  
- **completed/failed/refunded**: 300 seconds (5 minutes)

## Error Codes
- `400`: Invalid transaction ID format
- `403`: Transaction doesn't belong to requesting wallet
- `404`: Transaction not found
- `500`: Internal server error

## Key Files
- **Handler**: `src/api/onramp/status.rs`
- **Service**: `OnrampStatusService`
- **Route**: `/api/onramp/status/:tx_id` in `src/main.rs`
- **Tests**: `tests/onramp_status_*_test.rs`

## Usage Example
```bash
curl -X GET "https://api.aframp.com/api/onramp/status/01234567-89ab-cdef-0123-456789abcdef" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

## Testing
```bash
# Run unit tests
cargo test onramp_status_unit_test

# Run integration tests  
cargo test onramp_status_integration_test
```

## Monitoring
- Cache hit rates: `cache_hits_total{key_prefix="api:onramp:status"}`
- Response times: `http_request_duration_seconds{endpoint="/api/onramp/status/:tx_id"}`
- Error rates: `http_requests_total{status="4xx|5xx"}`