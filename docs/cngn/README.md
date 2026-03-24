# cNGN Stablecoin Integration Guide

This directory contains the complete developer reference for integrating with cNGN — the Nigerian Naira-pegged stablecoin issued on the Stellar network and used within the Aframp platform.

## Contents

| Document | Description |
|---|---|
| [overview.md](overview.md) | What cNGN is, its issuer addresses, and its role in the platform |
| [wallet-setup.md](wallet-setup.md) | Keypair creation, XLM funding, and trustline setup |
| [transaction-examples.md](transaction-examples.md) | Annotated transaction envelopes and submission examples |
| [trustline-management.md](trustline-management.md) | Missing trustlines, removal implications, and balance impact |
| [troubleshooting.md](troubleshooting.md) | Common errors and Horizon error code reference |

## Quick Links

- Stellar Testnet Explorer: https://stellar.expert/explorer/testnet
- Stellar Laboratory: https://laboratory.stellar.org
- Horizon Testnet API: https://horizon-testnet.stellar.org
- Friendbot (testnet funder): https://friendbot.stellar.org

## Environment Configuration

| Variable | Description | Example |
|---|---|---|
| `CNGN_ASSET_CODE` | Asset code for cNGN | `cNGN` |
| `CNGN_ISSUER_TESTNET` | Issuer address on testnet | `GC...` |
| `CNGN_ISSUER_MAINNET` | Issuer address on mainnet | `GC...` |
| `STELLAR_NETWORK` | Network selection | `testnet` or `mainnet` |
| `STELLAR_HORIZON_URL` | Override Horizon endpoint | `https://horizon-testnet.stellar.org` |
