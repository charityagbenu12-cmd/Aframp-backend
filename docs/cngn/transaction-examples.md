# cNGN Transaction Examples

This guide covers how cNGN payment transactions are constructed, submitted, and interpreted
within the platform.

## How a cNGN Payment Transaction is Constructed

The platform's `CngnPaymentBuilder` service constructs Stellar `Payment` operations. Each payment
transaction includes:

1. **Source account** — the sender's Stellar public key (or the platform system wallet)
2. **Destination account** — the recipient's Stellar public key
3. **Asset** — cNGN identified by its asset code and issuer address
4. **Amount** — the number of cNGN tokens to send
5. **Memo** — an optional structured memo for transaction tracing
6. **Fee** — in stroops (1 XLM = 10,000,000 stroops); minimum 100 stroops
7. **Sequence number** — must be exactly `account.sequence + 1`

## Annotated Transaction Envelope (XDR Decoded)

Below is a decoded view of a cNGN payment transaction envelope as it appears in Stellar
Laboratory's XDR viewer. Fields are annotated with explanations.

```json
{
  "tx": {
    "source_account": "GABC...1234",     // Sender's Stellar public key
    "fee": 100,                           // Transaction fee in stroops (100 = 0.00001 XLM)
    "seq_num": 12345678901234567,         // Sender's current sequence + 1
    "cond": { "type": "PRECOND_NONE" },  // No time bounds or ledger bounds
    "memo": {
      "type": "MEMO_TEXT",               // Platform uses TEXT memos for transaction references
      "text": "ONRAMP:aframp-tx-uuid"    // Aframp internal transaction ID for reconciliation
    },
    "operations": [
      {
        "source_account": null,          // Uses the transaction source account
        "body": {
          "type": "PAYMENT",
          "payment": {
            "destination": "GXYZ...5678", // Recipient's Stellar public key
            "asset": {
              "type": "ASSET_TYPE_CREDIT_ALPHANUM4",
              "alpha_num4": {
                "asset_code": "cNGN",    // The asset code — must be exactly "cNGN"
                "issuer": "GISS...0000"  // cNGN issuer address (testnet or mainnet)
              }
            },
            "amount": 100000000          // Amount in stroops: 10 cNGN = 100,000,000
          }
        }
      }
    ],
    "ext": { "v": 0 }
  },
  "signatures": [
    {
      "hint": "AABB...",                 // Last 4 bytes of the signing key's public key
      "signature": "CCDD..."            // Ed25519 signature over the transaction hash
    }
  ]
}
```

### Amount Calculation

Stellar stores all amounts as 64-bit integers in "stroops" (1/10,000,000 of the base unit):

| cNGN Amount | Stroops |
|---|---|
| 0.0000001 cNGN | 1 |
| 1 cNGN | 10,000,000 |
| 100 cNGN | 1,000,000,000 |
| 1,000,000 cNGN | 10,000,000,000,000 |

## Submitting a cNGN Transaction via Stellar Laboratory

### Step-by-Step

1. **Build** — Go to https://laboratory.stellar.org/#txbuilder on **Testnet**
2. Set Source Account to the sender's public key → click **Fetch next sequence number**
3. Set Fee to `100`
4. Set Memo Type to `Text` → enter your transaction reference (e.g. `test-payment-001`)
5. Add Operation → select **Payment**
   - Destination: recipient's public key (must have active cNGN trustline)
   - Asset: `cNGN` / `<CNGN_ISSUER_TESTNET>`
   - Amount: `10` (sends 10 cNGN)
6. **Sign** — Click **Sign in Transaction Signer** → paste your secret key → click **Sign**
7. **Submit** — Click **Submit to Stellar Network** → click **Submit**

### What a Successful Submission Returns

```json
{
  "hash": "abc123...",
  "ledger": 12345678,
  "successful": true,
  "envelope_xdr": "AAAAAQ...",
  "result_xdr": "AAAAAAAAAGQ...",
  "result_meta_xdr": "..."
}
```

## Finding a Transaction on the Testnet Explorer

Given a transaction hash, use either:

**Stellar Expert:**
```
https://stellar.expert/explorer/testnet/tx/<TRANSACTION_HASH>
```

**Horizon API:**
```bash
curl "https://horizon-testnet.stellar.org/transactions/<TRANSACTION_HASH>"
```

**Listing payments for an account:**
```bash
curl "https://horizon-testnet.stellar.org/accounts/<YOUR_PUBLIC_KEY>/payments?order=desc&limit=10"
```

## Interpreting a Horizon Transaction Response

```json
{
  "id": "abc123...",
  "paging_token": "1234567890",
  "successful": true,                    // true = all operations succeeded
  "hash": "abc123...",
  "ledger": 12345678,                    // Ledger (block) where tx was included
  "created_at": "2026-03-24T10:00:00Z", // UTC timestamp of confirmation
  "source_account": "GABC...1234",
  "source_account_sequence": "12345678901234567",
  "fee_account": "GABC...1234",
  "fee_charged": "100",                  // Actual fee paid in stroops
  "max_fee": "100",
  "operation_count": 1,
  "envelope_xdr": "...",
  "result_xdr": "AAAAAAAAAGQ...",        // Encoded result (see result codes below)
  "result_meta_xdr": "...",
  "memo_type": "text",
  "memo": "ONRAMP:aframp-tx-uuid",
  "signatures": ["..."],
  "valid_after": null,
  "valid_before": null
}
```

### Key Fields

| Field | Meaning |
|---|---|
| `successful` | `true` if the transaction and all operations succeeded |
| `ledger` | The ledger sequence where the transaction was finalized — treat as a block number |
| `fee_charged` | Actual fee deducted in stroops; may differ from `max_fee` during surge pricing |
| `memo` | Platform's internal reference for reconciliation |
| `result_xdr` | Base64-encoded operation results — decode to inspect individual operation outcomes |

### Checking Operation Results

To see per-operation results:

```bash
curl "https://horizon-testnet.stellar.org/transactions/<HASH>/operations"
```

A successful payment operation returns:

```json
{
  "type": "payment",
  "type_i": 1,
  "transaction_successful": true,
  "from": "GABC...1234",
  "to": "GXYZ...5678",
  "asset_type": "credit_alphanum4",
  "asset_code": "cNGN",
  "asset_issuer": "GISS...0000",
  "amount": "10.0000000"
}
```

## End-to-End cNGN Transfer Test (Testnet)

The following curl sequence runs a complete transfer test using Horizon:

```bash
# 1. Fund two testnet accounts
curl "https://friendbot.stellar.org?addr=<SENDER_PUBLIC_KEY>"
curl "https://friendbot.stellar.org?addr=<RECIPIENT_PUBLIC_KEY>"

# 2. Verify both accounts exist
curl "https://horizon-testnet.stellar.org/accounts/<SENDER_PUBLIC_KEY>" | python3 -m json.tool

# 3. Check if recipient has a cNGN trustline (look for cNGN in balances)
curl "https://horizon-testnet.stellar.org/accounts/<RECIPIENT_PUBLIC_KEY>" | \
  python3 -c "import sys, json; \
  acct = json.load(sys.stdin); \
  cngn = [b for b in acct['balances'] if b.get('asset_code') == 'cNGN']; \
  print('Has trustline:', bool(cngn))"

# 4. After establishing trustline, submit a payment via platform API
curl -X POST https://api.aframp.example.com/api/onramp/initiate \
  -H "Content-Type: application/json" \
  -d '{
    "quote_id": "<QUOTE_UUID>",
    "wallet_address": "<RECIPIENT_PUBLIC_KEY>"
  }'
```
