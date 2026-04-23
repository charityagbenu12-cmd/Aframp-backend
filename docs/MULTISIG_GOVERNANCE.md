# Multi-Signature Governance Framework

## Overview

The Multi-Signature (Multi-Sig) Governance Framework implements M-of-N signing for all high-privilege Stellar treasury operations: **Mint**, **Burn**, and **SetOptions** (signer management / threshold changes).

By requiring consensus from multiple authorized stakeholders before any critical operation is executed, the platform eliminates the "Single Point of Failure" and protects the cNGN supply from:
- Internal fraud
- Accidental errors
- External hacking of a single administrative account

## Architecture

```
Treasury Officer
      │
      ▼
[propose]  ──► multisig_proposals (unsigned_xdr stored)
      │
      ▼
[notify]   ──► Email / Slack / Push to all N signers
      │
      ▼
[sign]     ──► Each signer reviews XDR, submits DecoratedSignature
      │         (hardware wallet: Ledger / Trezor)
      ▼
[threshold met?]
  ├── governance change? ──► time_lock_until = NOW() + 48h  (status: time_locked)
  └── mint/burn?         ──► status: ready
      │
      ▼
[submit]   ──► Stellar Horizon  (status: submitted → confirmed)
      │
      ▼
[governance_log] ──► every event appended with actor public key + timestamp
```

## Key Features

### 1. M-of-N Signature Threshold

Every critical operation requires **M** signatures from a pool of **N** authorized signers before execution. The threshold is configurable per operation type:

| Operation Type      | Default M-of-N | Time-Lock |
|---------------------|----------------|-----------|
| Mint                | 3-of-5         | None      |
| Burn                | 3-of-5         | None      |
| SetOptions          | 3-of-5         | None      |
| Add Signer          | 3-of-5         | 48 hours  |
| Remove Signer       | 3-of-5         | 48 hours  |
| Change Threshold    | 4-of-5         | 48 hours  |

### 2. Transaction XDR Preview

Before signing, every signer can retrieve the **unsigned XDR** (base64-encoded Stellar transaction) via:

```
GET /api/v1/governance/proposals/:id
```

The response includes:
- `unsigned_xdr` — the exact transaction that will be submitted to Stellar
- `description` — human-readable summary of the operation
- `op_type` — mint / burn / set_options / add_signer / remove_signer / change_threshold
- `required_signatures` — M
- `total_signers` — N
- `signatures_collected` — current signature count
- `time_lock_until` — deadline for governance changes (NULL for mint/burn)

Signers MUST inspect the XDR on their hardware wallet (Ledger / Trezor) before signing.

### 3. Hardware Wallet Integration

The framework is designed for **cold storage** signing:

1. **Ledger Nano S/X** — Stellar app supports XDR signing
2. **Trezor Model T** — Stellar app supports XDR signing
3. **Air-gapped signing** — offline key management systems

The signer workflow:
1. Retrieve the proposal via the API
2. Load the `unsigned_xdr` onto the hardware wallet
3. Review the transaction details on the device screen
4. Approve and sign on the device
5. Submit the resulting `DecoratedSignature` XDR via `POST /api/v1/governance/proposals/:id/sign`

### 4. Time-Lock for Governance Changes

Extreme governance changes (adding/removing signers, changing thresholds) are **time-locked for 48 hours** after the M-of-N threshold is met. This provides a safety window for:
- Detecting malicious proposals
- Allowing other signers to reject the proposal
- Coordinating emergency response if needed

The time-lock is enforced by the `time_lock_until` field. The proposal status transitions:
- `pending` → `time_locked` (when threshold is met)
- `time_locked` → `ready` (when 48 hours elapse)
- `ready` → `submitted` → `confirmed`

### 5. Tamper-Evident Governance Log

Every governance event is appended to an immutable, hash-chained audit log:

```sql
CREATE TABLE multisig_governance_log (
    id              UUID PRIMARY KEY,
    proposal_id     UUID,
    event_type      VARCHAR(64),    -- 'proposal_created', 'signature_added', 'submitted', etc.
    actor_key       VARCHAR(64),    -- Stellar public key of the actor
    actor_id        UUID,
    payload         JSONB,
    previous_hash   VARCHAR(64),    -- SHA-256 of previous entry
    current_hash    VARCHAR(64),    -- SHA-256 of this entry
    created_at      TIMESTAMPTZ
);
```

The hash chain ensures:
- **Immutability** — any retroactive modification breaks the chain
- **Auditability** — every signature, proposal, and execution is logged with timestamp + actor public key
- **Compliance** — satisfies regulatory requirements for tamper-evident audit trails

## API Endpoints

### POST /api/v1/governance/proposals

Create a new treasury operation proposal.

**Request:**
```json
{
  "op_type": "mint",
  "description": "Mint 1,000,000 cNGN for customer deposit #12345",
  "op_params": {
    "destination": "GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN",
    "amount_stroops": "10000000000000"
  }
}
```

**Response:**
```json
{
  "proposal_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "pending",
  "op_type": "mint",
  "unsigned_xdr": "AAAAAgAAAAC...",
  "required_signatures": 3,
  "total_signers": 5,
  "time_lock_until": null,
  "expires_at": "2026-04-25T12:00:00Z",
  "message": "Proposal created. All authorised signers have been notified."
}
```

### GET /api/v1/governance/proposals

List all proposals (filterable by status / op_type).

**Query Parameters:**
- `status` — pending / time_locked / ready / submitted / confirmed / rejected / expired
- `op_type` — mint / burn / set_options / add_signer / remove_signer / change_threshold
- `page` — page number (default: 1)
- `page_size` — results per page (default: 20, max: 100)

### GET /api/v1/governance/proposals/:id

Get full proposal detail including unsigned XDR and collected signatures.

**Response:**
```json
{
  "proposal": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "op_type": "mint",
    "description": "Mint 1,000,000 cNGN for customer deposit #12345",
    "unsigned_xdr": "AAAAAgAAAAC...",
    "signed_xdr": null,
    "stellar_tx_hash": null,
    "required_signatures": 3,
    "total_signers": 5,
    "time_lock_until": null,
    "status": "pending",
    "proposed_by": "...",
    "proposed_by_key": "GCJRI5CIWK5IU67Q6DGA7QW52JDKRO7JEAHQKFNDUJUPEZGURDBX3LDX",
    "expires_at": "2026-04-25T12:00:00Z",
    "created_at": "2026-04-22T12:00:00Z"
  },
  "signatures": [
    {
      "id": "...",
      "signer_key": "GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN",
      "signer_role": "cfo",
      "signature_xdr": "AAAAAgAAAAC...",
      "signed_at": "2026-04-22T13:00:00Z"
    }
  ],
  "signatures_collected": 1,
  "signatures_required": 3,
  "time_lock_remaining_secs": null
}
```

### POST /api/v1/governance/proposals/:id/sign

Submit a cryptographic signature for a proposal.

**Request:**
```json
{
  "signer_key": "GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN",
  "signature_xdr": "AAAAAgAAAAC..."
}
```

**Headers:**
- `X-Signer-Key` — Stellar public key of the signer (G...)

**Response:**
```json
{
  "proposal": { ... },
  "signatures": [ ... ],
  "signatures_collected": 2,
  "signatures_required": 3,
  "time_lock_remaining_secs": null
}
```

### POST /api/v1/governance/proposals/:id/submit

Submit the fully-signed XDR to Stellar Horizon.

**Request:**
```json
{
  "signed_xdr": "AAAAAgAAAAC..."
}
```

**Response:**
```json
{
  "proposal_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "confirmed",
  "stellar_tx_hash": "abc123...",
  "confirmed_at": "2026-04-22T14:00:00Z",
  "message": "Transaction submitted and confirmed on Stellar."
}
```

### POST /api/v1/governance/proposals/:id/reject

Reject a proposal.

**Request:**
```json
{
  "reason": "Amount exceeds daily mint limit"
}
```

### GET /api/v1/governance/proposals/:id/log

Retrieve the tamper-evident governance audit log for a proposal.

**Response:**
```json
{
  "proposal_id": "550e8400-e29b-41d4-a716-446655440000",
  "entries": [
    {
      "id": "...",
      "event_type": "proposal_created",
      "actor_key": "GCJRI5CIWK5IU67Q6DGA7QW52JDKRO7JEAHQKFNDUJUPEZGURDBX3LDX",
      "payload": { ... },
      "previous_hash": null,
      "current_hash": "abc123...",
      "created_at": "2026-04-22T12:00:00Z"
    },
    {
      "id": "...",
      "event_type": "signature_added",
      "actor_key": "GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN",
      "payload": { "signer_role": "cfo", "signatures_collected": 1 },
      "previous_hash": "abc123...",
      "current_hash": "def456...",
      "created_at": "2026-04-22T13:00:00Z"
    }
  ],
  "total": 2
}
```

## Configuration

### Environment Variables

| Variable                          | Default                      | Description                                      |
|-----------------------------------|------------------------------|--------------------------------------------------|
| `STELLAR_ISSUER_ADDRESS`          | (required)                   | cNGN issuing account public key (G...)           |
| `MULTISIG_PROPOSAL_TTL_HOURS`     | `72`                         | Proposal expiry time in hours                    |
| `MULTISIG_SLACK_WEBHOOK_URL`      | (optional)                   | Slack incoming webhook for signer notifications  |
| `MULTISIG_SMTP_HOST`              | (optional)                   | SMTP relay for email notifications               |
| `MULTISIG_EMAIL_FROM`             | `treasury@cngn.io`           | From address for email notifications             |
| `MULTISIG_SIGNER_EMAILS`          | (comma-separated)            | Email addresses of all N signers                 |
| `MULTISIG_PORTAL_BASE_URL`        | `https://treasury.cngn.io`   | Base URL for deep-links in notifications         |

### Database Seed

The default quorum configuration is seeded in the migration:

```sql
INSERT INTO multisig_quorum_config (op_type, required_signatures, total_signers, time_lock_seconds)
VALUES
    ('mint',             3, 5,     0),
    ('burn',             3, 5,     0),
    ('set_options',      3, 5,     0),
    ('add_signer',       3, 5, 172800),  -- 48-hour time-lock
    ('remove_signer',    3, 5, 172800),  -- 48-hour time-lock
    ('change_threshold', 4, 5, 172800);  -- 48-hour time-lock
```

Update these values via the admin API after onboarding signers.

## Acceptance Criteria

✅ **The Issuing Account successfully rejects any transaction with fewer than the required number of signatures.**

- Enforced on-chain by Stellar's threshold configuration (high_threshold = M)
- Enforced off-chain by the service before submission (defence-in-depth)

✅ **Signers can view the full transaction XDR (Transaction Data) before applying their cryptographic signature.**

- `GET /api/v1/governance/proposals/:id` returns the `unsigned_xdr` field
- Signers load the XDR onto their hardware wallet for review

✅ **The system supports "Time-Locking" for extreme governance changes (e.g., adding a new signer takes 48 hours to become active).**

- `add_signer`, `remove_signer`, `change_threshold` operations have a 48-hour time-lock
- The proposal status transitions to `time_locked` when the threshold is met
- The proposal becomes `ready` only after the time-lock elapses

## Security Guarantees

### 1. No Single Point of Failure

No single signer can unilaterally:
- Mint cNGN
- Burn cNGN
- Add/remove signers
- Change thresholds

All operations require consensus from M signers.

### 2. Self-Signing Prevention

The proposer of a transaction cannot sign their own proposal. This prevents a malicious insider from creating and approving their own fraudulent mint.

### 3. Duplicate Signature Prevention

Each signer can only sign a proposal once. The database enforces a `UNIQUE (proposal_id, signer_id)` constraint.

### 4. Tamper-Evident Audit Trail

Every governance event is logged with a SHA-256 hash chain:

```
hash(entry_N) = SHA256(hash(entry_N-1) || proposal_id || event_type || actor_key || payload)
```

Any retroactive modification breaks the chain and is immediately detectable.

### 5. Time-Lock for Governance Changes

Adding/removing signers or changing thresholds requires a 48-hour waiting period after the M-of-N threshold is met. This provides a safety window for:
- Detecting malicious proposals
- Coordinating emergency response
- Allowing other signers to reject the proposal

## Workflow Example: Minting 1,000,000 cNGN

### Step 1: Treasury Officer Proposes

```bash
curl -X POST https://api.cngn.io/api/v1/governance/proposals \
  -H "X-Signer-Key: GCJRI5CIWK5IU67Q6DGA7QW52JDKRO7JEAHQKFNDUJUPEZGURDBX3LDX" \
  -H "Content-Type: application/json" \
  -d '{
    "op_type": "mint",
    "description": "Mint 1,000,000 cNGN for customer deposit #12345",
    "op_params": {
      "destination": "GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN",
      "amount_stroops": "10000000000000"
    }
  }'
```

**Response:**
```json
{
  "proposal_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "pending",
  "unsigned_xdr": "AAAAAgAAAAC...",
  "required_signatures": 3,
  "total_signers": 5,
  "message": "Proposal created. All authorised signers have been notified."
}
```

### Step 2: All Signers Receive Notification

**Slack:**
```
🔐 New MINT Proposal Requires Your Signature

Proposal #550e8400 has been created by GCJRI5CI.
Operation: MINT
Description: Mint 1,000,000 cNGN for customer deposit #12345
Required signatures: 3/5
Expires: 2026-04-25 12:00 UTC
⚠️  Review the full transaction XDR before signing.

<https://treasury.cngn.io/governance/proposals/550e8400-e29b-41d4-a716-446655440000|View Proposal>
```

**Email:**
Subject: 🔐 New MINT Proposal Requires Your Signature
Body: (same as Slack)

### Step 3: Signer 1 Reviews and Signs

```bash
# 1. Retrieve the proposal
curl https://api.cngn.io/api/v1/governance/proposals/550e8400-e29b-41d4-a716-446655440000

# 2. Extract unsigned_xdr and load onto Ledger Nano X
# 3. Review transaction details on device screen
# 4. Approve and sign on device
# 5. Submit the DecoratedSignature XDR

curl -X POST https://api.cngn.io/api/v1/governance/proposals/550e8400-e29b-41d4-a716-446655440000/sign \
  -H "X-Signer-Key: GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN" \
  -H "Content-Type: application/json" \
  -d '{
    "signer_key": "GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN",
    "signature_xdr": "AAAAAgAAAAC..."
  }'
```

**Response:**
```json
{
  "proposal": { ... },
  "signatures_collected": 1,
  "signatures_required": 3,
  "message": "Signature recorded. 2 more signature(s) needed."
}
```

### Step 4: Signers 2 and 3 Sign

(Repeat Step 3 for each signer)

After the 3rd signature, the proposal status transitions to `ready`.

### Step 5: Submit to Stellar

```bash
curl -X POST https://api.cngn.io/api/v1/governance/proposals/550e8400-e29b-41d4-a716-446655440000/submit \
  -H "X-Signer-Key: GCJRI5CIWK5IU67Q6DGA7QW52JDKRO7JEAHQKFNDUJUPEZGURDBX3LDX" \
  -H "Content-Type: application/json" \
  -d '{
    "signed_xdr": "AAAAAgAAAAC..."
  }'
```

**Response:**
```json
{
  "proposal_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "confirmed",
  "stellar_tx_hash": "abc123...",
  "confirmed_at": "2026-04-22T14:00:00Z",
  "message": "Transaction submitted and confirmed on Stellar."
}
```

## Database Schema

### multisig_proposals

Stores all treasury operation proposals.

| Column              | Type                        | Description                                      |
|---------------------|-----------------------------|--------------------------------------------------|
| id                  | UUID                        | Primary key                                      |
| op_type             | multisig_op_type            | mint / burn / set_options / add_signer / ...     |
| description         | TEXT                        | Human-readable summary                           |
| unsigned_xdr        | TEXT                        | Unsigned Stellar transaction XDR (base64)        |
| signed_xdr          | TEXT                        | Fully-signed XDR (NULL until submitted)          |
| stellar_tx_hash     | VARCHAR(64)                 | On-chain transaction hash                        |
| required_signatures | SMALLINT                    | M (minimum signatures needed)                    |
| total_signers       | SMALLINT                    | N (total authorized signers)                     |
| time_lock_until     | TIMESTAMPTZ                 | Deadline for governance changes (NULL for mint/burn) |
| status              | multisig_proposal_status    | pending / time_locked / ready / submitted / ...  |
| proposed_by         | UUID                        | Proposer's signer ID                             |
| proposed_by_key     | VARCHAR(64)                 | Proposer's Stellar public key                    |
| expires_at          | TIMESTAMPTZ                 | Proposal expiry (default: 72 hours)              |

### multisig_signatures

Stores each signer's cryptographic signature.

| Column        | Type        | Description                                      |
|---------------|-------------|--------------------------------------------------|
| id            | UUID        | Primary key                                      |
| proposal_id   | UUID        | Foreign key to multisig_proposals                |
| signer_id     | UUID        | Foreign key to mint_signers                      |
| signer_key    | VARCHAR(64) | Stellar public key used to sign                  |
| signer_role   | VARCHAR(64) | cfo / cto / cco / treasury_manager / ...         |
| signature_xdr | TEXT        | Base64-encoded DecoratedSignature XDR           |
| signed_at     | TIMESTAMPTZ | Signature timestamp                              |
| ip_address    | INET        | IP address of the signing request                |
| user_agent    | TEXT        | User agent of the signing request                |

**Constraint:** `UNIQUE (proposal_id, signer_id)` — prevents duplicate signatures.

### multisig_governance_log

Immutable, hash-chained audit trail.

| Column        | Type        | Description                                      |
|---------------|-------------|--------------------------------------------------|
| id            | UUID        | Primary key                                      |
| proposal_id   | UUID        | Foreign key to multisig_proposals (NULL for system events) |
| event_type    | VARCHAR(64) | proposal_created / signature_added / submitted / ... |
| actor_key     | VARCHAR(64) | Stellar public key of the actor (NULL for system) |
| actor_id      | UUID        | Foreign key to mint_signers (NULL for system)    |
| payload       | JSONB       | Event-specific data                              |
| previous_hash | VARCHAR(64) | SHA-256 of previous entry (NULL for genesis)     |
| current_hash  | VARCHAR(64) | SHA-256 of this entry                            |
| created_at    | TIMESTAMPTZ | Event timestamp                                  |

### multisig_quorum_config

Active M-of-N configuration for each operation type.

| Column              | Type             | Description                                      |
|---------------------|------------------|--------------------------------------------------|
| id                  | UUID             | Primary key                                      |
| op_type             | multisig_op_type | mint / burn / set_options / ...                  |
| required_signatures | SMALLINT         | M (minimum signatures needed)                    |
| total_signers       | SMALLINT         | N (total authorized signers)                     |
| time_lock_seconds   | INTEGER          | Time-lock duration (0 = no time-lock)            |
| updated_by          | UUID             | Admin who last updated this config               |
| updated_at          | TIMESTAMPTZ      | Last update timestamp                            |

## Testing

Run the integration tests:

```bash
cargo test --test multisig_governance_test --features database
```

The test suite covers:
- XDR builders (mint / burn / set_options)
- Governance log hash chain integrity
- Operation type time-lock requirements
- Proposal status terminal state detection

## Deployment Checklist

- [ ] Run migration: `migrations/20270201000000_multisig_governance.sql`
- [ ] Onboard N signers via the existing `mint_signers` table
- [ ] Update `multisig_quorum_config` with production M-of-N values
- [ ] Configure Stellar issuing account with matching thresholds (high_threshold = M)
- [ ] Set environment variables (STELLAR_ISSUER_ADDRESS, MULTISIG_SLACK_WEBHOOK_URL, etc.)
- [ ] Test the full workflow on testnet before mainnet deployment
- [ ] Distribute hardware wallets (Ledger Nano X) to all N signers
- [ ] Train signers on the XDR review and signing workflow

## Troubleshooting

### "UnauthorisedSigner" error

The signer's Stellar public key is not in the `mint_signers` table with `status = 'active'`.

**Fix:** Onboard the signer via the admin API or directly insert into `mint_signers`.

### "TimeLocked" error

The proposal is a governance change (add/remove signer, change threshold) and the 48-hour time-lock has not yet elapsed.

**Fix:** Wait for the time-lock to elapse, then retry the submission.

### "InsufficientSignatures" error

The proposal has not reached the M-of-N threshold.

**Fix:** Collect more signatures from authorized signers.

### "DuplicateSignature" error

The signer has already signed this proposal.

**Fix:** Each signer can only sign once. If the signature was submitted in error, the proposal must be rejected and re-created.

## References

- [Stellar Multi-Sig Documentation](https://developers.stellar.org/docs/encyclopedia/signatures-multisig)
- [Ledger Stellar App](https://support.ledger.com/hc/en-us/articles/115003797194-Stellar-XLM-)
- [Trezor Stellar Support](https://trezor.io/learn/a/stellar-on-trezor)
- [Issue #98: Audit Trail Implementation](../AUDIT_TRAIL.md)
