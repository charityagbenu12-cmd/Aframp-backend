# Troubleshooting Guide

This guide covers common errors encountered when working with cNGN on Stellar and how to
resolve them.

## Insufficient XLM Balance

### Symptom

The platform returns an error like:

```json
{
  "error": {
    "code": "INSUFFICIENT_XLM",
    "message": "Insufficient XLM for trustline reserve/fees. Need at least 2.0000000 XLM."
  }
}
```

Or Horizon returns `op_underfunded` when submitting a transaction.

### Cause

The account does not have enough XLM to cover:
- The base account reserve (1.0 XLM for a new account)
- The trustline reserve (0.5 XLM per trustline)
- Transaction fees (minimum 100 stroops = 0.00001 XLM per operation)

### Resolution

1. **Testnet:** Fund via Friendbot:
   ```bash
   curl "https://friendbot.stellar.org?addr=<YOUR_PUBLIC_KEY>"
   ```

2. **Mainnet:** Transfer XLM to the account from an exchange or another Stellar wallet.
   Send at least **2.0 XLM** to cover a bare account with one trustline plus fees.

3. Verify the balance:
   ```bash
   curl -s "https://horizon-testnet.stellar.org/accounts/<YOUR_PUBLIC_KEY>" | \
     python3 -c "import sys, json; a = json.load(sys.stdin); \
     xlm = [b for b in a['balances'] if b['asset_type'] == 'native'][0]; \
     print('XLM balance:', xlm['balance'])"
   ```

---

## Missing Trustline Error

### Symptom

Horizon returns `op_no_trust` or the platform API returns:

```json
{
  "error": {
    "code": "TRUSTLINE_REQUIRED",
    "message": "Destination wallet has no cNGN trustline. Establish trustline before receiving cNGN."
  }
}
```

### Cause

The destination Stellar account has not created a `ChangeTrust` operation for the cNGN asset.

### Resolution

1. Confirm the trustline is missing:
   ```bash
   curl -s "https://horizon-testnet.stellar.org/accounts/<WALLET_ADDRESS>" | \
     python3 -c "
   import sys, json
   a = json.load(sys.stdin)
   cngn = [b for b in a['balances'] if b.get('asset_code') == 'cNGN']
   print('cNGN trustline found:', bool(cngn))
   "
   ```

2. Create the trustline — see [wallet-setup.md](wallet-setup.md) Step 4.

3. Retry the onramp or payment after the trustline transaction is confirmed.

---

## Transaction Submission Failures

### Common Horizon Error Codes

| Error Code | Meaning | Resolution |
|---|---|---|
| `tx_bad_auth` | Invalid or missing signature | Re-sign the transaction with the correct secret key |
| `tx_bad_seq` | Sequence number mismatch | Fetch the latest sequence number and rebuild the transaction |
| `tx_insufficient_fee` | Fee too low during surge pricing | Increase fee or use fee bump transactions |
| `tx_no_account` | Source account does not exist | Fund the account before submitting |
| `tx_too_late` | Transaction expired (time bounds passed) | Rebuild the transaction with a fresh time bound |
| `op_no_trust` | Destination has no trustline | Destination must establish a cNGN trustline |
| `op_no_destination` | Destination account does not exist | Fund the destination account first |
| `op_underfunded` | Source has insufficient cNGN balance | Add more cNGN to the source wallet |
| `op_invalid_limit` | Trustline removal with non-zero balance | Transfer all cNGN out before removing trustline |
| `op_line_full` | Destination's trustline limit would be exceeded | Recipient must increase their trust limit |

### Horizon Error Response Format

```json
{
  "type": "https://stellar.org/horizon-errors/transaction_failed",
  "title": "Transaction Failed",
  "status": 400,
  "detail": "The transaction failed when tried by the Stellar network.",
  "extras": {
    "envelope_xdr": "...",
    "result_xdr": "...",
    "result_codes": {
      "transaction": "tx_failed",
      "operations": ["op_no_trust"]
    }
  }
}
```

Always check `extras.result_codes.operations` — a transaction can have a generic `tx_failed`
code while the specific operation code explains the actual problem.

---

## Stuck or Unconfirmed Stellar Transaction

### Symptom

A transaction was submitted but never confirmed. The hash was returned but the transaction does
not appear in the ledger.

### Causes and Checks

**1. Sequence number conflict**

If another transaction from the same source account used the same or a higher sequence number,
the stuck transaction is permanently invalid. Check the account's current sequence:

```bash
curl -s "https://horizon-testnet.stellar.org/accounts/<YOUR_PUBLIC_KEY>" | \
  python3 -c "import sys, json; a = json.load(sys.stdin); print('sequence:', a['sequence'])"
```

If the current sequence is already past the stuck transaction's sequence, you must rebuild
and resubmit the transaction with a fresh sequence number.

**2. Insufficient fee during surge**

During high network load, transactions with low fees are dropped. Monitor the recommended fee:

```bash
curl "https://horizon-testnet.stellar.org/fee_stats"
```

Look at `fee_charged.p90` — set your fee at or above this value.

**3. Transaction too old (time bounds expired)**

If the transaction had `timeBounds.maxTime` set, it expires after that time. Rebuild with
a new time bound or no time bound.

### Checking if a Transaction Exists

```bash
# Check by transaction hash
curl "https://horizon-testnet.stellar.org/transactions/<TRANSACTION_HASH>"

# If 404, it was never included in a ledger
# If 200 with "successful": false, it was included but failed
# If 200 with "successful": true, it succeeded
```

### Resubmitting via Stellar Laboratory

1. Go to https://laboratory.stellar.org/#xdr-viewer on **Testnet**
2. Paste the original `envelope_xdr` into the XDR field
3. Select **Transaction Envelope** as the type
4. Click **Submit to Stellar Network**

Note: If the sequence number is stale, resubmission will fail. Rebuild the transaction.

---

## Using Stellar Laboratory to Inspect Transactions

### Decode a Result XDR

1. Go to https://laboratory.stellar.org/#xdr-viewer
2. Paste the `result_xdr` from a Horizon response
3. Select type **TransactionResult**
4. Click **Submit** — the decoded result shows individual operation results

### Decode a Meta XDR

The `result_meta_xdr` contains ledger state changes. Decode it with type **TransactionMeta** to
see exactly which account balances changed and by how much.

---

## Platform-Specific Error Codes

| Code | HTTP Status | Meaning |
|---|---|---|
| `INVALID_WALLET_ADDRESS` | 400 | Stellar address format is invalid |
| `TRUSTLINE_REQUIRED` | 409 | Destination lacks a cNGN trustline |
| `INSUFFICIENT_XLM` | 400 | Not enough XLM for reserve/fees |
| `TRUSTLINE_ALREADY_EXISTS` | 409 | Account already has a cNGN trustline |
| `QUOTE_EXPIRED` | 410 | Onramp quote has expired — request a new one |
| `QUOTE_ALREADY_CONSUMED` | 409 | Quote was already used to initiate a transaction |
| `RATE_SERVICE_UNAVAILABLE` | 503 | Exchange rate service is temporarily unavailable |
| `INSUFFICIENT_CNGN_BALANCE` | 400 | Source wallet has insufficient cNGN for the operation |

---

## Diagnostic Checklist

When debugging a cNGN integration issue, work through this checklist in order:

- [ ] Is the Stellar account funded with at least 2.0 XLM?
- [ ] Does the destination account have a cNGN trustline pointing to the correct issuer?
- [ ] Is the trustline `is_authorized: true`?
- [ ] Is the transaction using the correct network (`testnet` vs `mainnet`)?
- [ ] Is the cNGN issuer address matching the configured `CNGN_ISSUER_TESTNET` or `CNGN_ISSUER_MAINNET`?
- [ ] Is the sequence number up to date (fetch fresh from Horizon before building)?
- [ ] Is the fee at least 100 stroops? Is it above the p90 fee during surge?
- [ ] Does the transaction appear on the testnet explorer at all?
- [ ] Is `result_codes.operations` inspected rather than just `result_codes.transaction`?
