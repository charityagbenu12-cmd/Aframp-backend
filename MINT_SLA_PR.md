## feat(mint): SLA Timers, Escalation Engine & Stellar Timebounds — Issue #MINT-SLA-001

### Summary

Implements a production-grade SLA timer and automated escalation system for mint requests that stall in `PENDING` / `PARTIALLY_APPROVED` state. Integrates directly with the existing multi-tier approval workflow and Stellar transaction pipeline.

---

### State Machine

```
mint_sla_state.stage:

  pending ──(4h)──► warned ──(12h)──► escalated ──(24h)──► expired
      │                │                   │
      └───────────────────────────────────► resolved
                                           (request left pending state)
```

```
mint_requests.status (SLA-driven transitions):

  pending_approval ──(24h SLA)──► expired
  partially_approved ──(24h SLA)──► expired
  [any] ──(Stellar timebound missed)──► expired  (TIMEOUT_FAILED)
```

---

### Files Changed

| File | Description |
|---|---|
| `db/migrations/mint_sla_schema.sql` | 3 new tables + DB trigger to auto-init SLA state |
| `src/services/mint_sla.rs` | Core SLA service: cycle runner, state machine, atomic DB updates |
| `src/services/mint_sla_notifier.rs` | Notification dispatcher: Slack + Email per escalation level |
| `src/services/mint_timebound_guard.rs` | Stellar timebound guard: pre-submission check + timeout detection |
| `src/workers/mint_sla_worker.rs` | Background worker: 30-min Tokio interval, idempotent, graceful shutdown |
| `src/services/mint_approval.rs` | Added SLA breach guard to `assert_executable()` |
| `src/database/mint_request_repository.rs` | Added `pool()` accessor |
| `src/services/mod.rs` | Registered new service modules |
| `src/workers/mod.rs` | Registered `mint_sla_worker` |

---

### SLA Thresholds

| Elapsed | Action | Target |
|---|---|---|
| 4 hours | Warning reminder | Tier-1 approver (Slack + Email) |
| 12 hours | Escalation | Tier-2 manager + department lead (Slack + Email) |
| 24 hours | Auto-expiration | All parties; request marked `EXPIRED` |

---

### Escalation Logic (Pseudocode)

```
every 30 minutes:
  run_id = new_uuid()

  // Step 0: detect Stellar timebound failures
  for each mint_stellar_timebounds where max_time < now AND stellar_tx_hash IS NULL:
    mark is_timeout_failed = TRUE
    transition mint_request → expired
    append stellar_timeout_failed to escalation_log + mint_audit_log

  // Step 1: evaluate all stalled requests
  for each (mint_request JOIN mint_sla_state) where sla_stage NOT IN (expired, resolved):

    if request.status NOT IN (pending_approval, partially_approved):
      → resolve_sla()   // request left pending state naturally

    elif now > request.expires_at:
      → expire_request()  // hard deadline

    else:
      elapsed = now - request.created_at

      action = match (elapsed_hours, sla_stage):
        (≥24, *)          → Expire
        (≥12, pending|warned) → Escalate
        (≥4,  pending)    → Warn
        _                 → None

      execute action atomically:
        UPDATE mint_sla_state WHERE stage = <expected>  // optimistic lock
        if rows_affected == 0: skip (already fired by another run)
        else: append to mint_audit_log + mint_escalation_log + dispatch notifications
```

---

### Stellar Timebounds Integration

Every mint transaction envelope must pass through `MintTimeboundGuard::assert_submittable()` before building the XDR:

```rust
// In the mint execution path:
let guard = MintTimeboundGuard::new(db.clone());
let window = guard.assert_submittable(mint_request_id, request.expires_at).await?;
// Returns TimeboundError::SlaBreached if sla_stage = expired

let builder = CngnPaymentBuilder::new(stellar_client)
    .with_timeout(Duration::from_secs(window.window_secs));
// window_secs flows into build_unsigned_transaction → XDR TimeBounds.max_time
```

The guard enforces:
1. **SLA breach block**: if `sla_stage = expired` or `status = expired` → `TimeboundError::SlaBreached` — no transaction reaches Stellar
2. **Window alignment**: `max_time = min(sla_expires_at, now + 23h)` — always closes before the 24h SLA hard limit
3. **Audit record**: every window is persisted to `mint_stellar_timebounds`

---

### Idempotency

- Each worker run is assigned a `run_id` (UUID)
- All DB updates use `WHERE stage = <expected_stage>` — concurrent runs cannot double-fire
- `ON CONFLICT DO UPDATE` on `mint_stellar_timebounds` prevents duplicate timebound records
- `mint_escalation_log` is append-only — safe to replay

---

### Expiration Guard (#123)

`EXPIRED` requests are blocked at two layers:
1. `MintApprovalService::load_active_request()` — returns `TerminalState` for expired requests
2. `MintApprovalService::assert_executable()` — checks `sla_stage = expired` and returns `ExecutionNotAllowed`

Fresh re-submission is the only path forward.

---

### Database Schema

```sql
-- mint_sla_state: one row per request, auto-created by DB trigger
-- mint_escalation_log: immutable audit trail for every SLA action
-- mint_stellar_timebounds: timebound window registry per request
```

Auto-init trigger on `mint_requests INSERT` ensures every new request gets an SLA state row with zero application-layer coordination.

---

### Environment Variables Required

```env
# SLA notifications
SLACK_MINT_OPS_WEBHOOK_URL=https://hooks.slack.com/services/...
SLACK_TREASURY_WEBHOOK_URL=https://hooks.slack.com/services/...
MINT_TIER1_APPROVER_EMAIL=ops@cngn.io
MINT_TIER2_MANAGER_EMAIL=treasury-manager@cngn.io
MINT_DEPT_LEAD_EMAIL=finance-lead@cngn.io

# Escalation target
TIER2_MANAGER_ID=user-id-of-tier2-manager

# SMTP (reuses existing config)
SMTP_HOST=smtp.cngn.io
SMTP_USER=...
SMTP_PASS=...
SMTP_FROM=noreply@cngn.io
```

---

### Worker Registration (example)

```rust
// In main.rs, after db_pool is initialised:
use workers::mint_sla_worker::MintSlaWorker;

let sla_worker = MintSlaWorker::new(db_pool.clone(), reqwest::Client::new());
let shutdown_rx_clone = shutdown_rx.clone();
tokio::spawn(async move {
    sla_worker.run(shutdown_rx_clone).await;
});
```

---

### Audit Trail (#117)

Every SLA action writes to two audit surfaces:
- `mint_audit_log` — existing per-request audit trail (actor=`sla_worker`)
- `mint_escalation_log` — new dedicated SLA action log with `worker_run_id` for traceability

---

### Reviewers

- [ ] Backend Lead — SLA state machine correctness, idempotency review
- [ ] Security — confirm no privilege escalation in Tier-2 visibility grant
- [ ] Compliance — verify 24h expiration aligns with CBN mint policy
- [ ] DBA — schema review (trigger, indexes, generated columns)
- [ ] Stellar Integration — timebound window alignment with XDR envelope

Closes #MINT-SLA-001
Refs #117 (Audit Trail)
Refs #123 (Expiration Guard)
