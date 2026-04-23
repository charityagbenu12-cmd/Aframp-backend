# POS QR Payment System — Physical Retail Integration

## Overview

The POS QR Payment System enables brick-and-mortar merchants to accept cNGN payments via Stellar-enabled wallets using QR codes. This system provides a low-cost, hardware-agnostic solution for physical retail locations without requiring expensive traditional card terminals.

## Features

### ✅ Core Capabilities

- **Dynamic QR Generation**: SEP-7 compliant QR codes generated in <300ms
- **Real-time Payment Confirmation**: WebSocket-based notifications within 3 seconds of payment
- **Legacy POS Integration**: Middleware API for existing retail software (Odoo, Revel, Square)
- **Offline-to-Online Validation**: Proof-of-payment screens for temporary internet outages
- **Discrepancy Detection**: Automatic flagging of overpayment/underpayment
- **Static QR Codes**: Variable amount checkout for small vendors

### 🎯 Performance Targets

- QR code generation: **<300ms**
- Payment confirmation: **<3 seconds** from customer signature
- Handles overpayment/underpayment with 0.01 cNGN tolerance

## Architecture

```
┌─────────────────┐
│   Merchant POS  │
│   (Tablet/PC)   │
└────────┬────────┘
         │
         │ HTTP/WebSocket
         │
┌────────▼────────────────────────────────────────┐
│         Aframp Backend API                      │
│  ┌──────────────────────────────────────────┐  │
│  │  POS Payment Intent Service              │  │
│  │  - QR Generation (SEP-7)                 │  │
│  │  - Payment Tracking                      │  │
│  └──────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────┐  │
│  │  Lobby Service (Real-time Monitor)       │  │
│  │  - Stellar Ledger Polling                │  │
│  │  - WebSocket Notifications               │  │
│  └──────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────┐  │
│  │  Legacy Bridge (POS Integration)         │  │
│  │  - Odoo, Revel, Square Adapters          │  │
│  └──────────────────────────────────────────┘  │
└─────────────────┬───────────────────────────────┘
                  │
                  │ Stellar Network
                  │
         ┌────────▼────────┐
         │  Stellar Ledger │
         │  (cNGN Payments)│
         └─────────────────┘
                  ▲
                  │
         ┌────────┴────────┐
         │  Customer Wallet│
         │  (Mobile App)   │
         └─────────────────┘
```

## API Endpoints

### Core POS Endpoints

#### Create Payment Intent
```http
POST /v1/pos/payments
Content-Type: application/json

{
  "merchant_id": "uuid",
  "order_id": "ORDER-12345",
  "amount_cngn": "1000.00"
}
```

**Response:**
```json
{
  "payment_id": "uuid",
  "order_id": "ORDER-12345",
  "qr_code_svg": "<svg>...</svg>",
  "amount_cngn": "1000.00",
  "expires_at": "2027-03-01T12:30:00Z",
  "status": "pending"
}
```

#### Get Payment Status
```http
GET /v1/pos/payments/{payment_id}
```

**Response:**
```json
{
  "payment_id": "uuid",
  "order_id": "ORDER-12345",
  "status": "confirmed",
  "amount_expected": "1000.00",
  "amount_received": "1000.00",
  "stellar_tx_hash": "abc123...",
  "confirmed_at": "2027-03-01T12:25:30Z",
  "is_complete": true,
  "has_discrepancy": false
}
```

#### Cancel Payment
```http
DELETE /v1/pos/payments/{payment_id}
```

### Legacy POS Integration

#### Create Payment (Legacy Format)
```http
POST /v1/pos/legacy/payments
Content-Type: application/json

{
  "merchant_id": "uuid",
  "order_id": "ORDER-12345",
  "amount": 1000.00,
  "currency": "cNGN"
}
```

**Response:**
```json
{
  "success": true,
  "payment_id": "uuid",
  "order_id": "ORDER-12345",
  "qr_code_svg": "<svg>...</svg>",
  "qr_code_url": "https://pay.aframp.com/pos/qr/{payment_id}",
  "payment_url": "https://pay.aframp.com/pos/pay/{payment_id}",
  "amount": "1000.00",
  "currency": "cNGN",
  "expires_at": "2027-03-01T12:30:00Z",
  "status_webhook_url": "https://api.aframp.com/v1/pos/webhook/{payment_id}"
}
```

#### Check Payment Status (Legacy)
```http
GET /v1/pos/legacy/payments/{payment_id}/status
```

### Proof of Payment

#### Generate Proof
```http
GET /v1/pos/proof/{payment_id}
```

**Response:**
```json
{
  "payment_id": "uuid",
  "order_id": "ORDER-12345",
  "merchant_name": "Test Retail Store",
  "amount": "1000.00",
  "currency": "cNGN",
  "transaction_hash": "abc123...",
  "verification_code": "A1B2C3D4E5F6G7H8",
  "timestamp": "2027-03-01T12:25:30Z",
  "qr_code_svg": "<svg>...</svg>",
  "verification_url": "https://stellar.expert/explorer/public/tx/abc123..."
}
```

#### Verify Proof
```http
POST /v1/pos/proof/{payment_id}/verify
Content-Type: application/json

{
  "verification_code": "A1B2C3D4E5F6G7H8"
}
```

**Response:**
```json
{
  "is_valid": true
}
```

### WebSocket Real-time Notifications

```javascript
const ws = new WebSocket('wss://api.aframp.com/v1/pos/ws/{payment_id}');

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  
  if (data.type === 'notification') {
    console.log('Payment status:', data.status);
    console.log('Amount received:', data.amount_received);
    console.log('Transaction hash:', data.stellar_tx_hash);
    
    if (data.status === 'confirmed') {
      // Show success screen to cashier
      showSuccessScreen();
    } else if (data.status === 'discrepancy') {
      // Flag amount mismatch
      showDiscrepancyAlert(data);
    }
  }
};
```

## Database Schema

The system uses the following tables:

### `pos_merchants`
Merchant configuration for POS payments.

```sql
CREATE TABLE pos_merchants (
    id UUID PRIMARY KEY,
    business_name VARCHAR(255) NOT NULL,
    stellar_address VARCHAR(56) NOT NULL,
    webhook_url TEXT,
    static_qr_enabled BOOLEAN DEFAULT false,
    auto_refund_discrepancy BOOLEAN DEFAULT false,
    payment_timeout_secs INTEGER DEFAULT 900,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
```

### `pos_payment_intents`
Individual payment transactions.

```sql
CREATE TABLE pos_payment_intents (
    id UUID PRIMARY KEY,
    merchant_id UUID REFERENCES pos_merchants(id),
    order_id VARCHAR(100) NOT NULL,
    amount_cngn DECIMAL(20,7) NOT NULL,
    destination_address VARCHAR(56) NOT NULL,
    memo VARCHAR(100) NOT NULL UNIQUE,
    qr_code_data TEXT NOT NULL,
    status pos_payment_status DEFAULT 'pending',
    stellar_tx_hash VARCHAR(64),
    actual_amount_received DECIMAL(20,7),
    customer_address VARCHAR(56),
    expires_at TIMESTAMPTZ NOT NULL,
    confirmed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
```

### `pos_payment_discrepancies`
Audit trail for amount mismatches.

```sql
CREATE TABLE pos_payment_discrepancies (
    id UUID PRIMARY KEY,
    payment_id UUID REFERENCES pos_payment_intents(id),
    expected_amount DECIMAL(20,7) NOT NULL,
    received_amount DECIMAL(20,7) NOT NULL,
    difference DECIMAL(20,7) NOT NULL,
    discrepancy_type VARCHAR(20) CHECK (discrepancy_type IN ('overpayment', 'underpayment')),
    resolution_status VARCHAR(20) DEFAULT 'pending',
    resolved_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
```

## Configuration

### Environment Variables

```bash
# cNGN Issuer Address (required)
CNGN_ISSUER_ADDRESS=GXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

# POS Verification Secret (required for proof-of-payment)
POS_VERIFICATION_SECRET=your-secret-key-min-32-chars

# Lobby Service Poll Interval (optional, default: 5 seconds)
POS_LOBBY_POLL_INTERVAL_SECS=5
```

## Integration Examples

### Odoo POS Integration

```python
import requests

# Create payment intent
response = requests.post(
    'https://api.aframp.com/v1/pos/legacy/payments',
    json={
        'merchant_id': 'your-merchant-id',
        'order_id': order.name,
        'amount': order.amount_total,
        'currency': 'cNGN'
    }
)

payment_data = response.json()

# Display QR code to customer
display_qr_code(payment_data['qr_code_svg'])

# Poll for payment status
while True:
    status_response = requests.get(
        f"https://api.aframp.com/v1/pos/legacy/payments/{payment_data['payment_id']}/status"
    )
    status = status_response.json()
    
    if status['is_complete']:
        if status['has_discrepancy']:
            handle_discrepancy(status)
        else:
            complete_order(order)
        break
    
    time.sleep(2)
```

### Square POS Integration

```javascript
const Square = require('square');
const axios = require('axios');

async function processAframpPayment(orderId, amount) {
  // Create payment intent
  const response = await axios.post(
    'https://api.aframp.com/v1/pos/legacy/payments',
    {
      merchant_id: process.env.MERCHANT_ID,
      order_id: orderId,
      amount: amount,
      currency: 'cNGN'
    }
  );

  const { payment_id, qr_code_url } = response.data;

  // Display QR code
  console.log(`Show QR code: ${qr_code_url}`);

  // Connect to WebSocket for real-time updates
  const ws = new WebSocket(`wss://api.aframp.com/v1/pos/ws/${payment_id}`);
  
  return new Promise((resolve, reject) => {
    ws.on('message', (data) => {
      const notification = JSON.parse(data);
      
      if (notification.status === 'confirmed') {
        resolve(notification);
      } else if (notification.status === 'failed') {
        reject(new Error('Payment failed'));
      }
    });
  });
}
```

## SEP-7 Payment URI Format

The system generates SEP-7 compliant payment URIs:

```
web+stellar:pay?destination=GMERCHANT...&amount=1000.00&asset_code=cNGN&asset_issuer=GISSUER...&memo=POS-abc123&memo_type=text
```

This URI is encoded into a QR code that can be scanned by any Stellar-enabled wallet.

## Security Considerations

1. **Memo Uniqueness**: Each payment intent has a unique memo to prevent replay attacks
2. **Expiry Timeout**: Payments expire after 15 minutes (configurable)
3. **Amount Tolerance**: 0.01 cNGN tolerance for floating-point precision
4. **Verification Codes**: HMAC-SHA256 based codes for proof-of-payment validation
5. **WebSocket Authentication**: Payment ID required to connect to WebSocket

## Monitoring & Metrics

The system provides the following metrics:

- `pos_payment_intents_total` - Total payment intents created
- `pos_payment_confirmations_total` - Total confirmed payments
- `pos_payment_discrepancies_total` - Total amount discrepancies detected
- `pos_qr_generation_duration_seconds` - QR code generation time
- `pos_payment_confirmation_duration_seconds` - Time from submission to confirmation

## Testing

Run the integration tests:

```bash
cargo test --features database pos::
```

## Troubleshooting

### QR Code Generation Slow
- Check `pos_qr_generation_duration_seconds` metric
- Ensure sufficient CPU resources
- Consider caching QR codes for static merchants

### Payment Confirmation Delayed
- Verify Stellar Horizon connectivity
- Check `pos_lobby_poll_interval_secs` configuration
- Monitor Stellar network congestion

### WebSocket Connection Issues
- Verify firewall allows WebSocket connections
- Check payment ID is valid and not expired
- Ensure proper CORS configuration

## Future Enhancements

- [ ] NFC payment support
- [ ] Multi-currency support (beyond cNGN)
- [ ] Batch payment reconciliation
- [ ] Advanced fraud detection
- [ ] Mobile SDK for custom POS apps
- [ ] Receipt generation and email delivery

## Support

For issues or questions:
- GitHub Issues: https://github.com/aframp/backend/issues
- Email: support@aframp.com
- Documentation: https://docs.aframp.com/pos
