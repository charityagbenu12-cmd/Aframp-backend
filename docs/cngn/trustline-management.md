# Trustline Management

This document covers what happens when trustlines are missing, how to detect them, and the
implications of adding or removing a cNGN trustline.

## What Happens When a Destination Has No cNGN Trustline

If you attempt to send cNGN to a Stellar account that has not established a cNGN trustline, the
Stellar network rejects the transaction immediately. The transaction result code is:

```
op_no_trust
```

The transaction is **not** submitted to a ledger — it fails at validation time. No fee is
charged (fees are only charged if the transaction is included in a ledger, which requires passing
preliminary validation; however, note that once the tx is in the queue and the ledger processes
it, the fee is deducted even on failure).

### Platform Behavior

The platform's onramp processor checks for a trustline before submitting any cNGN payment:

1. The quote response includes `"trustline_required": true` if the wallet lacks a trustline
2. The onramp initiation endpoint returns a `409 Conflict` if the wallet has no trustline
3. The error response includes the wallet address and instructions to establish the trustline

## Detecting a Missing Trustline via Horizon API

```bash
curl "https://horizon-testnet.stellar.org/accounts/<WALLET_ADDRESS>"
```

Parse the `balances` array and look for an entry where `asset_code == "cNGN"` and
`asset_issuer == "<CNGN_ISSUER_TESTNET>`:

```bash
curl -s "https://horizon-testnet.stellar.org/accounts/<WALLET_ADDRESS>" | \
  python3 -c "
import sys, json
acct = json.load(sys.stdin)
cngn = [b for b in acct['balances']
        if b.get('asset_code') == 'cNGN'
        and b.get('asset_issuer') == '<CNGN_ISSUER_TESTNET>']
if cngn:
    print('Trustline ACTIVE:', json.dumps(cngn[0], indent=2))
else:
    print('Trustline MISSING')
"
```

### Account Does Not Exist

If the wallet address has never been funded, Horizon returns `404 Not Found`:

```json
{
  "type": "https://stellar.org/horizon-errors/not_found",
  "title": "Resource Missing",
  "status": 404,
  "detail": "The resource at the url requested was not found...",
  "extras": {
    "resource_type": "account",
    "resource_id": "<WALLET_ADDRESS>"
  }
}
```

This is a different problem from a missing trustline — the account must be funded with XLM via
Friendbot (testnet) or a regular XLM transfer (mainnet) before any trustline can be created.

## Adding a cNGN Trustline

Adding a trustline costs **0.5 XLM in base reserve** — this amount is locked (not spendable)
for as long as the trustline exists. The reserve is released when the trustline is removed.

### Balance Impact

| Event | Spendable XLM Change | Locked Reserve Change |
|---|---|---|
| Add cNGN trustline | -0.5 XLM | +0.5 XLM |
| Remove cNGN trustline | +0.5 XLM | -0.5 XLM |

The **minimum account balance** calculation:

```
minimum_balance = (2 + subentry_count) * 0.5 XLM
```

With one trustline (subentry_count = 1):
```
minimum_balance = (2 + 1) * 0.5 = 1.5 XLM
```

If the account drops below the minimum balance, no further transactions can be submitted until
the balance is restored.

## Removing a cNGN Trustline

A trustline can be removed by submitting a `ChangeTrust` operation with `limit = 0`.

**Important:** A trustline can only be removed if the account holds **zero cNGN**. Attempting
to remove a trustline with a non-zero balance returns `op_invalid_limit`.

### Implications for Platform Usage

Removing a cNGN trustline while interacting with the platform has the following consequences:

| Scenario | Impact |
|---|---|
| Remove trustline mid-onramp | The platform's outbound cNGN transfer will fail (`op_no_trust`). The platform will detect the failure, mark the transaction as failed, and initiate a refund of the NGN. |
| Remove trustline mid-offramp | The offramp is not affected — the user is sending cNGN to the platform, not receiving it. |
| Remove trustline while cNGN balance > 0 | Rejected by Stellar (`op_invalid_limit`) — must transfer or sell all cNGN first. |
| Remove trustline after all cNGN sent | Allowed. Releases 0.5 XLM from reserve. |

### Removing via Stellar SDK (JavaScript)

```javascript
const StellarSdk = require('@stellar/stellar-sdk');
const server = new StellarSdk.Horizon.Server('https://horizon-testnet.stellar.org');

const sourceKeypair = StellarSdk.Keypair.fromSecret('<YOUR_SECRET_KEY>');
const cngnAsset = new StellarSdk.Asset('cNGN', '<CNGN_ISSUER_TESTNET>');

async function removeTrustline() {
  const account = await server.loadAccount(sourceKeypair.publicKey());

  const transaction = new StellarSdk.TransactionBuilder(account, {
    fee: StellarSdk.BASE_FEE,
    networkPassphrase: StellarSdk.Networks.TESTNET,
  })
    .addOperation(
      StellarSdk.Operation.changeTrust({
        asset: cngnAsset,
        limit: '0', // Setting limit to 0 removes the trustline
      })
    )
    .setTimeout(30)
    .build();

  transaction.sign(sourceKeypair);
  const result = await server.submitTransaction(transaction);
  console.log('Trustline removed! Hash:', result.hash);
}
```

## Subentry Count Reference

Each of the following adds 1 to an account's `subentry_count` (each costs 0.5 XLM reserve):

- Each trustline (e.g. cNGN)
- Each offer (buy/sell order on the DEX)
- Each additional signer on the account
- Each data entry (key/value data stored on account)

Use the Horizon account endpoint to check the current subentry count:

```bash
curl -s "https://horizon-testnet.stellar.org/accounts/<WALLET_ADDRESS>" | \
  python3 -c "import sys, json; a = json.load(sys.stdin); print('subentry_count:', a['subentry_count'])"
```
