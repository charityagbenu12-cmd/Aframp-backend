# Stellar Wallet Setup for cNGN

This guide walks through creating a Stellar keypair, funding a testnet account, and establishing
a cNGN trustline — all prerequisites for sending or receiving cNGN.

## Step 1: Create a Stellar Keypair

A Stellar keypair consists of a **public key** (wallet address, starts with `G`) and a
**secret key** (private key, starts with `S`). Never share your secret key.

### Using Stellar Laboratory

1. Open https://laboratory.stellar.org/#account-creator
2. Click **Generate keypair**
3. Copy and store both the **Public Key** and **Secret Key** securely

### Using the Stellar SDK (JavaScript)

```javascript
const StellarSdk = require('@stellar/stellar-sdk');

const keypair = StellarSdk.Keypair.random();
console.log('Public Key:', keypair.publicKey());
console.log('Secret Key:', keypair.secret());
```

### Using the Stellar SDK (Python)

```python
from stellar_sdk import Keypair

keypair = Keypair.random()
print("Public Key:", keypair.public_key)
print("Secret Key:", keypair.secret)
```

A freshly generated keypair is not yet active on the network. You must fund it before it can
hold any balance or trustlines.

## Step 2: Minimum XLM Balance Requirements

Stellar accounts must maintain a **minimum balance** of XLM at all times, calculated as:

```
minimum_balance = (2 + number_of_subentries) * base_reserve
base_reserve = 0.5 XLM
```

For a new account with no trustlines or other subentries:

| State | Required XLM |
|---|---|
| Bare account (no subentries) | 1.0 XLM |
| + 1 trustline (cNGN) | 1.5 XLM |
| + 2 trustlines | 2.0 XLM |
| Recommended buffer for fees | + 0.5 XLM |

**Practical minimum for a cNGN wallet: 2.0 XLM** (1.5 XLM reserve + 0.5 XLM fee buffer).

The platform checks this before building a trustline transaction and will return an error if the
account has insufficient XLM.

## Step 3: Fund the Testnet Account Using Friendbot

On testnet, Friendbot is a service that creates and funds accounts with 10,000 XLM.

```bash
# Replace <YOUR_PUBLIC_KEY> with your generated public key
curl "https://friendbot.stellar.org?addr=<YOUR_PUBLIC_KEY>"
```

Example response:

```json
{
  "hash": "a1b2c3...",
  "ledger": 12345678,
  "envelope_xdr": "AAAAAQ...",
  "result_xdr": "AAAAAAAAAGQ...",
  "result_meta_xdr": "AAAAAQAA..."
}
```

Verify the account was created:

```bash
curl "https://horizon-testnet.stellar.org/accounts/<YOUR_PUBLIC_KEY>"
```

Look for `"balance": "10000.0000000"` in the native XLM balance entry.

## Step 4: Establish a cNGN Trustline

A trustline is a Stellar account's explicit opt-in to hold a specific asset from a specific
issuer. Without a trustline, a wallet cannot receive cNGN — any payment attempt will fail.

### Using the Platform API

The platform provides an endpoint that builds the unsigned trustline transaction:

```bash
POST /api/wallet/trustline/build
Content-Type: application/json

{
  "wallet_address": "<YOUR_PUBLIC_KEY>",
  "limit": "1000000"
}
```

The response includes an `unsigned_envelope_xdr` field containing the unsigned Stellar
transaction. You sign it with your secret key and submit it via:

```bash
POST /api/wallet/trustline/submit
Content-Type: application/json

{
  "signed_envelope_xdr": "<SIGNED_XDR_STRING>"
}
```

### Using Stellar Laboratory (Manual)

1. Go to https://laboratory.stellar.org/#txbuilder
2. Set **Network** to `Testnet`
3. Set **Source Account** to your public key — click **Fetch next sequence number**
4. Set **Base Fee** to `100` (stroops)
5. Click **Add Operation** and select **Change Trust**
6. Set **Asset** to:
   - Code: `cNGN`
   - Issuer: `<CNGN_ISSUER_TESTNET>` (from environment config)
7. Set **Trust Limit** to `1000000` (or leave blank for maximum)
8. Click **Sign in Transaction Signer** → enter your secret key → sign
9. Click **Submit to Stellar Network**

### Using the Stellar SDK (JavaScript)

```javascript
const StellarSdk = require('@stellar/stellar-sdk');
const server = new StellarSdk.Horizon.Server('https://horizon-testnet.stellar.org');

const sourceKeypair = StellarSdk.Keypair.fromSecret('<YOUR_SECRET_KEY>');
const sourcePublicKey = sourceKeypair.publicKey();

const cngnIssuer = process.env.CNGN_ISSUER_TESTNET;
const cngnAsset = new StellarSdk.Asset('cNGN', cngnIssuer);

async function createTrustline() {
  const account = await server.loadAccount(sourcePublicKey);

  const transaction = new StellarSdk.TransactionBuilder(account, {
    fee: StellarSdk.BASE_FEE,
    networkPassphrase: StellarSdk.Networks.TESTNET,
  })
    .addOperation(
      StellarSdk.Operation.changeTrust({
        asset: cngnAsset,
        limit: '1000000', // Maximum cNGN this wallet will hold
      })
    )
    .setTimeout(30)
    .build();

  transaction.sign(sourceKeypair);

  const result = await server.submitTransaction(transaction);
  console.log('Trustline created! Transaction hash:', result.hash);
}

createTrustline();
```

## Step 5: Verify the Trustline is Active

### Via Stellar Laboratory

1. Go to https://laboratory.stellar.org/#explorer
2. Select **Testnet**
3. Enter your public key in the **Account** search
4. Look for `cNGN` in the **Balances** section

### Via Horizon API

```bash
curl "https://horizon-testnet.stellar.org/accounts/<YOUR_PUBLIC_KEY>" | \
  python3 -c "import sys, json; acct = json.load(sys.stdin); \
  [print(b) for b in acct['balances'] if b.get('asset_code') == 'cNGN']"
```

A successful trustline appears as:

```json
{
  "balance": "0.0000000",
  "limit": "1000000.0000000",
  "buying_liabilities": "0.0000000",
  "selling_liabilities": "0.0000000",
  "last_modified_ledger": 12345678,
  "is_authorized": true,
  "is_authorized_to_maintain_liabilities": true,
  "asset_type": "credit_alphanum4",
  "asset_code": "cNGN",
  "asset_issuer": "<CNGN_ISSUER_TESTNET>"
}
```

Key fields to verify:

| Field | Expected Value |
|---|---|
| `asset_code` | `cNGN` |
| `asset_issuer` | Must match `CNGN_ISSUER_TESTNET` exactly |
| `is_authorized` | `true` |
| `limit` | Greater than `0` |

If `is_authorized` is `false`, the issuer has not yet authorized your account. Contact the
platform operator.
