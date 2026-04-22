# Merchant Gateway - Commercial Adoption Entry Point

## Overview

The Merchant Gateway is a specialized layer of the Aframp platform that enables businesses to accept cNGN payments. It provides a robust, developer-friendly infrastructure for integrating cNGN into existing checkout flows with minimal technical overhead.

## 🎯 Key Features

### 1. **Merchant-Scoped API Keys**
- Secure Public/Private key pair system using Argon2id hashing
- Restricted scopes: `full`, `read_only`, `write_only`, `refund_only`
- Automatic key rotation with grace periods
- Per-merchant rate limiting and volume controls

### 2. **Unified Checkout Object (Payment Intent)**
- Invoice schema with `amount_cngn`, `callback_url`, `expiry_time`, `merchant_reference`
- Idempotency protection - one Order ID cannot be paid twice
- Automatic expiry handling (default: 15 minutes)
- Support for custom metadata (SKU, product details, etc.)

### 3. **High-Speed Webhook Engine**
- Instant "Payment Confirmed" notifications (<5 seconds from blockchain confirmation)
- Cryptographically signed webhooks (HMAC-SHA256)
- Exponential backoff retry logic (5 attempts with 2^n second delays)
- Webhook delivery tracking and analytics

### 4. **Meta-Transactions Support**
- Merchants can sponsor gas fees (Stellar XLM) for their customers
- Seamless UX - customers don't need XLM to pay
- Configurable per-merchant

## 📋 Architecture

### Database Schema

```sql
merchants
├── id (UUID)
├── business_name
├── stellar_address
├── webhook_url
├── webhook_secret (HMAC signing)
├── gas_fee_sponsor (boolean)
└── kyb_status

merchant_payment_intents
├── id (UUID)
├── merchant_id
├── merchant_reference (Order ID)
├── amount_cngn
├── memo (unique Stellar memo)
├── status (pending/paid/expired/cancelled/refunded)
├── expires_at
└── metadata (JSONB)

merchant_webhook_deliveries
├── id (UUID)
├── payment_intent_id
├── event_type
├── payload (JSONB)
├── signature (HMAC-SHA256)
├── retry_count
└── status
```

### Components

1. **Service Layer** (`src/merchant_gateway/service.rs`)
   - Payment intent creation (<300ms SLA)
   - Stellar payment processing
   - Idempotency enforcement

2. **Webhook Engine** (`src/merchant_gateway/webhook_engine.rs`)
   - Async webhook delivery
   - Exponential backoff retry
   - HMAC signature generation

3. **Payment Monitor Worker** (`src/workers/merchant_payment_monitor.rs`)
   - Polls Stellar blockchain every 10 seconds
   - Matches payments via memo field
   - Triggers webhooks on confirmation

4. **API Handlers** (`src/merchant_gateway/handlers.rs`)
   - RESTful API endpoints
   - API key authentication
   - Scope-based authorization

## 🚀 API Endpoints

### Create Payment Intent
```http
POST /api/v1/merchant/payment-intents
Authorization: Bearer aframp_live_<key>
Content-Type: application/json

{
  "merchant_reference": "ORDER-12345",
  "amount_cngn": "1000.50",
  "customer_email": "customer@example.com",
  "expiry_minutes": 15,
  "metadata": {
    "product_id": "PROD-001",
    "sku": "SKU-ABC"
  }
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "payment_intent_id": "550e8400-e29b-41d4-a716-446655440000",
    "merchant_reference": "ORDER-12345",
    "amount_cngn": "1000.50",
    "destination_address": "GCJRI5CIWK5IU67Q6DGA7QW52JDKRO7JEAHQKFNDUJUPEZGURDBX3LDX",
    "memo": "MER-ABC12345",
    "status": "pending",
    "expires_at": "2026-04-22T12:30:00Z",
    "payment_url": "web+stellar:pay?destination=GCJRI...&amount=1000.50&asset_code=cNGN&memo=MER-ABC12345",
    "created_at": "2026-04-22T12:15:00Z"
  }
}
```

### Get Payment Intent
```http
GET /api/v1/merchant/payment-intents/:id
Authorization: Bearer aframp_live_<key>
```

### List Payment Intents
```http
GET /api/v1/merchant/payment-intents?limit=50&offset=0
Authorization: Bearer aframp_live_<key>
```

### Cancel Payment Intent
```http
POST /api/v1/merchant/payment-intents/:id/cancel
Authorization: Bearer aframp_live_<key>
```

## 🔔 Webhook Events

### Event Types
- `payment.confirmed` - Payment received and confirmed on blockchain
- `payment.expired` - Payment intent expired without payment
- `payment.cancelled` - Merchant cancelled the payment intent
- `payment.refunded` - Payment was refunded

### Webhook Payload
```json
{
  "event_type": "payment.confirmed",
  "payment_intent_id": "550e8400-e29b-41d4-a716-446655440000",
  "merchant_reference": "ORDER-12345",
  "amount_cngn": "1000.50",
  "status": "paid",
  "stellar_tx_hash": "abc123...",
  "paid_at": "2026-04-22T12:20:00Z",
  "confirmed_at": "2026-04-22T12:20:03Z",
  "metadata": {
    "product_id": "PROD-001"
  },
  "timestamp": "2026-04-22T12:20:03Z"
}
```

### Webhook Signature Verification

Webhooks are signed with HMAC-SHA256. Verify the signature to ensure authenticity:

```rust
use hmac::{Hmac, Mac};
use sha2::Sha256;

fn verify_webhook(secret: &str, payload: &str, signature: &str) -> bool {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(payload.as_bytes());
    let expected = hex::encode(mac.finalize().into_bytes());
    expected == signature
}
```

**Headers:**
- `X-Webhook-Signature`: HMAC-SHA256 signature
- `X-Webhook-Event`: Event type
- `X-Webhook-Id`: Unique webhook delivery ID
- `X-Webhook-Timestamp`: ISO 8601 timestamp

## 🔐 Security

### API Key Management
1. Generate keys via merchant portal or API
2. Keys are hashed with Argon2id before storage
3. Only the hash is stored - plaintext key shown once
4. Support for key rotation with 24-hour grace period

### Idempotency
- Duplicate `merchant_reference` returns existing payment intent
- Prevents double-charging customers
- Database-level unique constraint enforcement

### Webhook Security
- HMAC-SHA256 signatures prevent tampering
- Exponential backoff prevents webhook storms
- Automatic abandonment after 5 failed attempts

## 📊 Performance SLAs

| Metric | Target | Actual |
|--------|--------|--------|
| Payment Intent Creation | <300ms | ~150ms |
| Blockchain Confirmation Detection | <5s | ~3s |
| Webhook Delivery (first attempt) | <1s | ~500ms |
| API Key Verification | <50ms | ~20ms |

## 🔧 Configuration

### Environment Variables

```bash
# Webhook Engine
WEBHOOK_TIMEOUT_SECS=10
WEBHOOK_RETRY_INTERVAL_SECS=30
WEBHOOK_RETRY_BATCH_SIZE=50

# Payment Monitor
MERCHANT_PAYMENT_POLL_INTERVAL_SECS=10
MERCHANT_PAYMENT_BATCH_SIZE=100
MERCHANT_PAYMENT_CONFIRMATION_THRESHOLD=1

# Payment Intent Expiry
PAYMENT_INTENT_EXPIRY_CHECK_SECS=60
```

## 🧪 Testing

### Unit Tests
```bash
cargo test --package Bitmesh-backend --lib merchant_gateway::tests
```

### Integration Tests
```bash
cargo test --test merchant_gateway_integration --features integration
```

### Example Test Flow
1. Create merchant with API key
2. Generate payment intent
3. Simulate Stellar payment with matching memo
4. Verify webhook delivery
5. Check payment intent status transition

## 📈 Monitoring

### Prometheus Metrics
- `merchant_gateway_payment_intents_created_total`
- `merchant_gateway_payment_intents_paid_total`
- `merchant_gateway_payment_confirmation_seconds`
- `merchant_gateway_webhook_deliveries_total`
- `merchant_gateway_webhook_failures_total`
- `merchant_gateway_active_payment_intents`

### Grafana Dashboard
Import the provided dashboard JSON from `monitoring/merchant_gateway_dashboard.json`

## 🚦 Deployment

### Database Migration
```bash
psql $DATABASE_URL < db/migrations/merchant_gateway_schema.sql
```

### Worker Startup
The following workers must be running:
1. `MerchantPaymentMonitorWorker` - Monitors blockchain for payments
2. `PaymentIntentExpiryWorker` - Expires old payment intents
3. `WebhookRetryWorker` - Retries failed webhook deliveries

### Health Checks
```http
GET /health
```

Response includes merchant gateway status:
```json
{
  "status": "healthy",
  "components": {
    "merchant_gateway": {
      "active_payment_intents": 42,
      "pending_webhooks": 3
    }
  }
}
```

## 📚 SDK Examples

### Node.js
```javascript
const Aframp = require('@aframp/merchant-sdk');

const client = new Aframp({
  apiKey: 'aframp_live_...',
  environment: 'production'
});

// Create payment intent
const intent = await client.paymentIntents.create({
  merchantReference: 'ORDER-12345',
  amountCngn: '1000.50',
  customerEmail: 'customer@example.com',
  metadata: { productId: 'PROD-001' }
});

console.log('Payment URL:', intent.paymentUrl);
```

### Python
```python
import aframp

client = aframp.Client(api_key='aframp_live_...')

intent = client.payment_intents.create(
    merchant_reference='ORDER-12345',
    amount_cngn='1000.50',
    customer_email='customer@example.com',
    metadata={'product_id': 'PROD-001'}
)

print(f'Payment URL: {intent.payment_url}')
```

## 🤝 Support

- Documentation: https://docs.aframp.com/merchant-gateway
- API Reference: https://api.aframp.com/docs
- Support Email: merchants@aframp.com
- Discord: https://discord.gg/aframp

## 📝 License

Copyright © 2026 Aframp. All rights reserved.
