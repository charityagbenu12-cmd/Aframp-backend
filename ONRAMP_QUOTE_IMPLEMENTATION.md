# Onramp Quote Endpoint Implementation

## Overview

This document describes the complete implementation of the `POST /api/onramp/quote` endpoint for generating purchase quotes for users buying cNGN with Nigerian Naira.

**Status**: ✅ Complete and Tested
**Spec Version**: Issue #26
**Implementation Date**: March 2026

## What Was Built

### Endpoint: `POST /api/onramp/quote`

Generates a time-limited quote for purchasing cNGN with NGN, including:
- Exchange rate snapshot (1 NGN = 1 cNGN fixed peg)
- Fee calculation (platform + provider)
- Trustline status verification
- 5-minute validity window
- Detailed fee breakdown

## Request Specification

### Request Body

```json
{
  "wallet_address": "GXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
  "from_currency": "NGN",
  "to_currency": "cNGN",
  "amount": "50000.00",
  "payment_method": "card"
}
```

### Request Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `wallet_address` | string | Yes | Stellar wallet address (56 chars, starts with G) |
| `from_currency` | string | Yes | Source currency (always "NGN") |
| `to_currency` | string | Yes | Target currency (always "cNGN") |
| `amount` | string | Yes | Amount in NGN to spend (100 - 5,000,000) |
| `payment_method` | string | No | Payment method: card, bank_transfer, ussd (default: card) |

### Validation Rules

1. **Wallet Address**
   - Must be valid Stellar public key (56 characters, starts with 'G')
   - Must exist on Stellar network
   - Returns 404 if wallet not found

2. **Amount**
   - Minimum: ₦100 (covers transaction fees)
   - Maximum: ₦5,000,000 (AML/risk management)
   - Must be positive number
   - Returns 400 if outside range

3. **Currencies**
   - `from_currency` must be "NGN"
   - `to_currency` must be "cNGN"
   - Returns 400 if invalid

## Response Specification

### Success Response (With Trustline) - 200 OK

```json
{
  "quote_id": "q_a1b2c3d4e5f6",
  "wallet_address": "GXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
  "from_currency": "NGN",
  "to_currency": "cNGN",
  "from_amount": "50000.00",
  "exchange_rate": 1.0,
  "gross_amount": "50000.00",
  "fees": {
    "provider_fee": {
      "amount": "700.00",
      "percentage": 1.4,
      "provider": "flutterwave"
    },
    "platform_fee": {
      "amount": "50.00",
      "percentage": 0.1
    },
    "payment_method_fee": {
      "amount": "0.00",
      "method": "card"
    },
    "total_fees": "750.00"
  },
  "net_amount": "49250.00",
  "breakdown": {
    "you_pay": "50000.00 NGN",
    "you_receive": "49250.00 cNGN",
    "effective_rate": 0.985
  },
  "trustline_status": {
    "exists": true,
    "ready_to_receive": true
  },
  "validity": {
    "expires_at": "2026-02-18T10:35:00Z",
    "expires_in_seconds": 300
  },
  "next_steps": {
    "endpoint": "/api/onramp/initiate",
    "method": "POST",
    "action": "Proceed to payment"
  },
  "created_at": "2026-02-18T10:30:00Z"
}
```

### Success Response (Without Trustline) - 200 OK

```json
{
  "quote_id": "q_a1b2c3d4e5f6",
  "wallet_address": "GXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
  "from_currency": "NGN",
  "to_currency": "cNGN",
  "from_amount": "50000.00",
  "net_amount": "49250.00",
  "trustline_status": {
    "exists": false,
    "ready_to_receive": false,
    "action_required": "create_trustline"
  },
  "trustline_requirements": {
    "asset_code": "cNGN",
    "asset_issuer": "GCNGNISSUERXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
    "min_xlm_required": "1.5",
    "current_xlm_balance": "0.5",
    "xlm_needed": "1.0",
    "instructions": "You need to add cNGN trustline before receiving cNGN. This requires 0.5 XLM base reserve.",
    "help_url": "/docs/trustline-setup"
  },
  "next_steps": {
    "step_1": "Add 1.0 XLM to your wallet",
    "step_2": "Create cNGN trustline",
    "step_3": "Return to get new quote",
    "action": "Create trustline first"
  },
  "validity": {
    "expires_at": "2026-02-18T10:35:00Z",
    "expires_in_seconds": 300
  },
  "created_at": "2026-02-18T10:30:00Z"
}
```

### Error Responses

#### 400 Bad Request - Invalid Amount

```json
{
  "error": "VALIDATION_ERROR",
  "message": "Amount must be between 100 and 5,000,000 NGN",
  "details": {
    "field": "amount",
    "min_amount": "100.00",
    "max_amount": "5000000.00"
  }
}
```

#### 400 Bad Request - Invalid Wallet

```json
{
  "error": "INVALID_WALLET_ADDRESS",
  "message": "Not a valid Stellar public key",
  "details": {
    "wallet_address": "INVALID_ADDRESS"
  }
}
```

#### 404 Not Found - Wallet Doesn't Exist

```json
{
  "error": "WALLET_NOT_FOUND",
  "message": "Wallet address not found on Stellar network",
  "details": {
    "wallet_address": "GXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
    "action": "Fund wallet with at least 1 XLM to activate"
  }
}
```

#### 503 Service Unavailable - Rate Service Down

```json
{
  "error": "EXTERNAL_SERVICE_TIMEOUT",
  "message": "Unable to generate quote at this time. Please try again.",
  "details": {
    "service": "rate_service",
    "retry_after": 30
  }
}
```

## Fee Calculation

### Fee Structure

**Platform Fees:**
- Percentage: 0.1%
- Minimum: ₦10
- Used for operational costs

**Provider Fees (Flutterwave):**
- Percentage: 1.4%
- Minimum: ₦50
- Maximum: ₦2,000 (cap)
- Covers payment processing

**Payment Method Fees:**
- Card: Included in provider fee
- Bank Transfer: Included in provider fee
- USSD: Included in provider fee

### Calculation Example

```
Input: 50,000 NGN
Exchange Rate: 1.0 (fixed peg)

Gross Amount: 50,000 × 1.0 = 50,000 cNGN

Platform Fee: max(50,000 × 0.001, 10) = 50 NGN
Provider Fee: max(50,000 × 0.014, 50) = 700 NGN (capped at 2,000)
Total Fees: 50 + 700 = 750 NGN

Net Amount: 50,000 - 750 = 49,250 cNGN
Effective Rate: 49,250 / 50,000 = 0.985 cNGN per NGN
```

## Quote Management

### Quote Properties

- **Quote ID**: Unique identifier (format: `q_{uuid}`)
- **Validity**: 5 minutes from creation
- **Locked Rate**: Rate won't change during validity
- **Locked Fees**: Fee structure fixed at quote time
- **Single Use**: Quote consumed when payment initiated

### Quote Storage

**Redis Key**: `v1:onramp:quote:{quote_id}`
**TTL**: 300 seconds (5 minutes)

**Stored Data**:
```json
{
  "quote_id": "q_abc123",
  "wallet_address": "GXXX...",
  "from_currency": "NGN",
  "to_currency": "cNGN",
  "from_amount": "50000.00",
  "exchange_rate": "1.0",
  "gross_amount": "50000.00",
  "net_amount": "49250.00",
  "fees": { ... },
  "trustline_exists": true,
  "payment_method": "card",
  "created_at": "2026-02-18T10:30:00Z",
  "expires_at": "2026-02-18T10:35:00Z",
  "status": "pending"
}
```

### Quote Expiration

- Quote created: 10:30:00
- Quote expires: 10:35:00
- If user initiates at 10:36:00: Quote invalid, generate new one

## Trustline Handling

### With Trustline

✓ cNGN trustline exists
✓ Ready to receive cNGN
→ Proceed to payment

### Without Trustline

✗ No cNGN trustline
✗ Cannot receive cNGN yet

**Action Required:**
1. Ensure 1.5 XLM in wallet (you have 0.5 XLM)
2. Create cNGN trustline (costs 0.5 XLM reserve)
3. Return for new quote

**XLM Requirements:**
- Base reserve: 0.5 XLM
- Trustline reserve: 0.5 XLM
- Total minimum: 1.5 XLM

## Implementation Details

### File Structure

```
src/api/onramp/
├── mod.rs              # Module exports
├── models.rs           # Request/response models
├── quote.rs            # Quote endpoint handler
└── status.rs           # Status check endpoint

src/cache/
└── keys.rs             # Cache key builders (includes onramp::QuoteKey)

tests/
└── onramp_quote_api_test.rs  # Comprehensive tests
```

### Key Components

#### 1. Request Validation (`validate_quote_request`)
- Validates wallet address format
- Checks amount range (100 - 5,000,000)
- Validates currency pair (NGN → cNGN)

#### 2. Exchange Rate Fetching
- Calls `ExchangeRateService`
- Uses fixed peg rate (1.0)
- Caches rate for 90 seconds

#### 3. Fee Calculation (`calculate_fees`)
- Platform fee: 0.1% (min ₦10)
- Provider fee: 1.4% (min ₦50, max ₦2,000)
- Returns tuple of (platform_fee, provider_fee)

#### 4. Trustline Checking
- Uses `CngnTrustlineManager`
- Queries Stellar for account balances
- Checks for cNGN trustline existence
- Calculates XLM requirements if missing

#### 5. Quote Storage
- Generates unique quote ID
- Stores in Redis with 5-minute TTL
- Includes all calculation details

#### 6. Response Formatting
- Two response types based on trustline status
- Includes detailed fee breakdown
- Provides clear next steps

### Error Handling

All errors follow unified error system:
- **Validation Errors** (400): Invalid input
- **Domain Errors** (4xx): Business logic violations
- **Infrastructure Errors** (5xx): System issues
- **External Errors** (502/503/504): Service unavailable

### Logging

Comprehensive logging at key points:
- Quote request received
- Validation results
- Exchange rate fetched
- Fees calculated
- Trustline status checked
- Quote stored in Redis
- Quote created successfully

## Testing

### Test Coverage

Run tests with:
```bash
cargo test onramp_quote_api -- --ignored --nocapture
```

**Test Categories:**

1. **Validation Tests**
   - Valid request with trustline
   - Valid request without trustline
   - Amount too small
   - Amount too large
   - Invalid wallet address
   - Invalid currency pair

2. **Fee Calculation Tests**
   - Correct platform fee calculation
   - Correct provider fee calculation
   - Fee minimums applied
   - Fee maximums applied
   - Effective rate calculation

3. **Trustline Tests**
   - Trustline exists scenario
   - Trustline missing scenario
   - XLM requirement calculation
   - Trustline creation instructions

4. **Quote Management Tests**
   - Quote ID generation
   - Quote expiration (5 minutes)
   - Quote storage in Redis
   - Concurrent quote requests
   - Decimal precision

5. **Response Structure Tests**
   - Response with trustline
   - Response without trustline
   - Fee breakdown display
   - Next steps guidance

## Acceptance Criteria - All Met ✅

- ✅ POST /api/onramp/quote endpoint implemented
- ✅ Validates wallet address format
- ✅ Checks wallet exists on Stellar
- ✅ Checks if cNGN trustline exists
- ✅ Calculates gross cNGN amount correctly
- ✅ Applies all applicable fees
- ✅ Returns net cNGN amount accurately
- ✅ Generates unique quote ID
- ✅ Stores quote in Redis with 5-min TTL
- ✅ Returns detailed fee breakdown
- ✅ Shows effective exchange rate
- ✅ Includes quote expiration time
- ✅ Validates minimum purchase amount
- ✅ Validates maximum purchase amount
- ✅ Prompts trustline creation if needed
- ✅ Shows XLM requirements for trustline
- ✅ Returns clear errors for all failure cases
- ✅ Logs quote generation for analytics
- ✅ Comprehensive test coverage

## Usage Example

### Request

```bash
curl -X POST http://localhost:8000/api/onramp/quote \
  -H "Content-Type: application/json" \
  -d '{
    "wallet_address": "GXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
    "from_currency": "NGN",
    "to_currency": "cNGN",
    "amount": "50000.00",
    "payment_method": "card"
  }'
```

### Response (With Trustline)

```json
{
  "quote_id": "q_a1b2c3d4e5f6",
  "wallet_address": "GXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
  "from_currency": "NGN",
  "to_currency": "cNGN",
  "from_amount": "50000.00",
  "exchange_rate": 1.0,
  "gross_amount": "50000.00",
  "fees": {
    "provider_fee": {
      "amount": "700.00",
      "percentage": 1.4,
      "provider": "flutterwave"
    },
    "platform_fee": {
      "amount": "50.00",
      "percentage": 0.1
    },
    "payment_method_fee": {
      "amount": "0.00",
      "method": "card"
    },
    "total_fees": "750.00"
  },
  "net_amount": "49250.00",
  "breakdown": {
    "you_pay": "50000.00 NGN",
    "you_receive": "49250.00 cNGN",
    "effective_rate": 0.985
  },
  "trustline_status": {
    "exists": true,
    "ready_to_receive": true
  },
  "validity": {
    "expires_at": "2026-02-18T10:35:00Z",
    "expires_in_seconds": 300
  },
  "next_steps": {
    "endpoint": "/api/onramp/initiate",
    "method": "POST",
    "action": "Proceed to payment"
  },
  "created_at": "2026-02-18T10:30:00Z"
}
```

## Performance Considerations

- **Exchange Rate Caching**: 90-second TTL reduces external calls
- **Quote Storage**: Redis provides sub-millisecond lookups
- **Trustline Checking**: Cached for 5 minutes per wallet
- **Concurrent Requests**: Fully async/await for high throughput

## Security Considerations

- ✅ Wallet address validation prevents injection
- ✅ Amount validation prevents overflow/underflow
- ✅ Quote ID is cryptographically random (UUID)
- ✅ Redis TTL prevents quote reuse
- ✅ All inputs sanitized before use
- ✅ Error messages don't leak sensitive info

## Future Enhancements

1. **Dynamic Fees**: Adjust fees based on market conditions
2. **Rate Providers**: Integrate external rate APIs
3. **Liquidity Checks**: Verify cNGN availability
4. **Quote Analytics**: Track conversion rates
5. **A/B Testing**: Test different fee structures
6. **Bulk Quotes**: Support multiple quotes in one request

## Troubleshooting

### Quote Not Stored in Redis
- Check Redis connection
- Verify Redis URL in environment
- Check Redis TTL settings

### Trustline Check Failing
- Verify Stellar network connectivity
- Check wallet address format
- Ensure Stellar client is initialized

### Fee Calculation Incorrect
- Verify fee percentages in code
- Check minimum/maximum fee caps
- Validate BigDecimal precision

### Quote Expiring Too Quickly
- Verify system clock is synchronized
- Check Redis TTL settings
- Ensure quote creation timestamp is correct

## References

- Exchange Rate Service: `src/services/exchange_rate.rs`
- Trustline Management: `src/chains/stellar/trustline.rs`
- Cache Implementation: `src/cache/cache.rs`
- Error Handling: `src/error.rs`
- API Models: `src/api/onramp/models.rs`

## Support

For issues or questions:
1. Check test cases in `tests/onramp_quote_api_test.rs`
2. Review error handling in `src/error.rs`
3. Check Stellar integration in `src/chains/stellar/`
4. Verify Redis configuration in `.env`
