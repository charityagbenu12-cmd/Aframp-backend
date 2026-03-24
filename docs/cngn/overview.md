# cNGN Overview

## What is cNGN?

cNGN is a Nigerian Naira (NGN) pegged stablecoin issued on the Stellar blockchain. It is a
Stellar custom asset (also called an IOU) where each token represents exactly one Nigerian Naira.
The peg is maintained 1:1 — 1 cNGN always equals 1 NGN.

cNGN is the on-chain settlement layer for the Aframp platform. When a user converts NGN to
cNGN (onramp), the platform receives fiat, mints or releases cNGN, and sends it to the user's
Stellar wallet. When a user converts cNGN back to NGN (offramp), the platform receives cNGN and
sends the equivalent NGN to the user's bank account or mobile money wallet.

## Issuer Addresses

| Network | Issuer Address |
|---|---|
| Testnet | Set via `CNGN_ISSUER_TESTNET` environment variable |
| Mainnet | Set via `CNGN_ISSUER_MAINNET` environment variable |

The issuer address is the Stellar account that has the authority to create (issue) and destroy
(burn) cNGN tokens. All cNGN trustlines must reference this issuer. A wallet that creates a
trustline to a different issuer address holds a different asset — not the platform's cNGN.

### Verifying the Issuer

You can verify the issuer at any time via the Horizon API:

```bash
# Testnet — list all assets matching the cNGN code
curl "https://horizon-testnet.stellar.org/assets?asset_code=cNGN"
```

The response lists all Stellar accounts that have issued an asset with the `cNGN` code. Identify
the one matching the platform's configured `CNGN_ISSUER_TESTNET` address.

## Asset Properties

| Property | Value |
|---|---|
| Asset Code | `cNGN` |
| Asset Type | `credit_alphanum4` (4-character code) |
| Pegging Mechanism | 1 cNGN = 1 NGN (fixed peg, enforced at platform level) |
| Precision | 7 decimal places (Stellar stroops: 1 cNGN = 10,000,000 units) |
| Issuance | Controlled by the platform issuer account |
| Redemption | Platform receives cNGN and releases equivalent NGN |

## Role in Platform Flows

### Onramp Flow (NGN → cNGN)

```
User pays NGN via bank transfer / mobile money
        ↓
Platform payment provider receives NGN
        ↓
Platform validates payment and creates onramp quote
        ↓
Platform's issuer or reserve account sends cNGN to user's Stellar wallet
        ↓
User receives cNGN (requires active trustline)
```

The user's Stellar wallet **must have an active cNGN trustline** before receiving cNGN. If the
trustline is missing, the Stellar transaction will fail with `op_no_trust`.

### Offramp Flow (cNGN → NGN)

```
User initiates offramp — specifies destination bank/mobile money
        ↓
Platform provides a quote with the NGN amount after fees
        ↓
User sends cNGN to platform's collection address
        ↓
Platform detects the on-chain cNGN receipt
        ↓
Platform initiates NGN payout to user's bank account
```

### Bill Payment Flow

```
User requests bill payment (electricity, airtime, cable TV)
        ↓
Platform deducts cNGN from user's balance or wallet
        ↓
Platform converts cNGN to NGN internally
        ↓
Platform pays the bill provider in NGN
```

## Pegging Mechanism

The 1:1 peg between cNGN and NGN is maintained at the **platform layer**, not at the Stellar
protocol level. Stellar itself treats cNGN as a freely-tradeable asset. The platform enforces the
peg by:

1. Only minting new cNGN when equivalent NGN has been received
2. Only releasing NGN when equivalent cNGN has been received and burned/returned to issuer
3. Maintaining a reserve account that holds cNGN backing inventory

The platform's exchange rate service always returns a fixed 1.0 rate for NGN/cNGN and
cNGN/NGN pairs — any external FX rates (e.g. USD/NGN) are sourced from external providers.

## Key Stellar Concepts for cNGN

| Concept | Relevance |
|---|---|
| Trustline | Every wallet that wants to hold cNGN must explicitly authorize it via a ChangeTrust operation |
| Base reserve | Stellar accounts must hold minimum XLM to remain active |
| Trustline reserve | Each trustline costs 0.5 XLM in additional reserve |
| Stroops | Stellar's smallest unit: 1 XLM = 10,000,000 stroops; same for cNGN |
| Sequence number | Each Stellar transaction must use the account's current sequence + 1 |
