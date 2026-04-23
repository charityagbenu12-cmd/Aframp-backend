## feat(treasury): Smart Treasury Allocation Engine — Issue #TREASURY-001

### Summary

Implements a production-grade Smart Treasury Allocation Engine for the NGN-pegged stablecoin platform. The engine enforces concentration limits across Tier-1 custodian banks and cash equivalents (T-Bills, REPOs), supports real-time monitoring, automated alerting, daily RWA calculation, semi-automated rebalancing, and a sanitised public transparency dashboard — all in support of the 1:1 NGN peg guarantee.

---

### Files Changed

| File | Description |
|---|---|
| `db/migrations/treasury_allocation_schema.sql` | Full schema: 7 tables + materialised view + helper functions |
| `src/treasury/allocation/types.rs` | All domain types, enums, request/response structs |
| `src/treasury/allocation/repository.rs` | sqlx queries for all tables; public dashboard row fetch |
| `src/treasury/allocation/engine.rs` | Core engine: concentration pipeline, RWA calc, PoR check, handler accessors |
| `src/treasury/allocation/alerts.rs` | Breach detection, Slack + PagerDuty dispatch, auto-resolution |
| `src/treasury/allocation/rebalancer.rs` | Transfer order generation for breach and rating downgrade triggers |
| `src/treasury/allocation/handlers.rs` | All Axum HTTP handlers (internal + public) |
| `src/treasury/allocation/routes.rs` | Route registration (`internal_router` + `public_router`) |

---

### Feature Checklist

- [x] **Allocation Monitor** — `GET /treasury/allocation/monitor` returns per-custodian balance, concentration %, breach flag, peg coverage ratio
- [x] **Concentration Limit Alerts** — auto-fires on breach; severity: Warning (≤200 bps excess) / Critical (>200 bps); dispatches to Slack + PagerDuty; auto-resolves when breach clears
- [x] **Liquidity Tiering** — Tier 1 (instant cash), Tier 2 (overnight REPO), Tier 3 (T-Bills/MMF); enforced in rebalancer destination selection
- [x] **Emergency Rebalancing Workflow** — transfer orders generated on concentration breach or risk rating downgrade; semi-automated (engine generates, operator approves via `POST /orders/:id/decision`)
- [x] **RWA Calculation** — daily snapshot via `POST /treasury/allocation/rwa/calculate`; CBN risk weights: banks 20%, T-Bills 0%, REPOs 10%, MMFs 15%
- [x] **Proof-of-Reserves Integration** — `verify_por()` called on every RWA calculation; logs `🚨 PoR MISMATCH` if `|reserves − supply| > 0.01%`
- [x] **Public Transparency Dashboard** — `GET /treasury/allocation/public` exposes `public_alias` only; no `internal_name`, no account refs
- [x] **Full Audit Trail** — every transfer order state change written to `transfer_order_audit_log`; all operator actions written to the platform audit log

---

### API Endpoints

#### Internal (treasury-operator auth required)

```
POST   /treasury/allocation/record                — record balance snapshot
GET    /treasury/allocation/monitor               — real-time allocation dashboard
GET    /treasury/allocation/alerts                — unresolved concentration alerts
GET    /treasury/allocation/rwa/latest            — latest RWA snapshot
POST   /treasury/allocation/rwa/calculate         — trigger daily RWA calculation
GET    /treasury/allocation/orders                — list transfer orders (filterable by status)
GET    /treasury/allocation/orders/:id            — get single transfer order
POST   /treasury/allocation/orders/:id/decision   — approve / reject transfer order
POST   /treasury/allocation/orders/:id/complete   — mark transfer order completed
POST   /treasury/allocation/custodians/:id/rating — update custodian risk rating
```

#### Public (no auth)

```
GET    /treasury/allocation/public                — sanitised holdings dashboard
```

---

### Concentration Limit Logic

```
on every balance update:
  total_reserves = Σ confirmed balances across all custodians
  for each custodian:
    concentration_bps = (balance / total_reserves) × 10_000
    if concentration_bps > max_concentration_bps:
      excess_bps = concentration_bps − max_concentration_bps
      severity   = CRITICAL if excess_bps > 200 else WARNING
      → persist ConcentrationAlert
      → notify Slack + PagerDuty (async, non-blocking)
      → generate TransferOrder (pending_approval)
    else:
      → auto-resolve any open alert for this custodian
```

---

### Rebalancing Strategy

**Breach trigger:**
- Transfer amount = `source_balance − (max_bps − 200) × total / 10_000`
- Destination = active custodian with most headroom, same or lower liquidity tier, that won't breach its own limit after receiving the transfer

**Downgrade trigger:**
- Full balance distributed across up to 3 destinations (sorted by headroom descending)
- Remainder assigned to first destination

---

### Security Constraints Met

- `encrypted_account_ref` (AES-256-GCM) stored in DB; never returned by any API
- `internal_name` excluded from all public responses
- `public_reserve_dashboard` materialised view enforces sanitisation at the DB layer
- All rebalancing actions require explicit operator approval before execution
- Audit log is append-only (`BIGSERIAL` PK, no `DELETE` path)

---

### Environment Variables Required

```env
SLACK_TREASURY_WEBHOOK_URL=https://hooks.slack.com/services/...
PAGERDUTY_ROUTING_KEY=...
```

---

### Mounting (example)

```rust
// In your main router setup:
use treasury::allocation::routes::{internal_router, public_router};

let engine = Arc::new(AllocationEngine::new(db_pool.clone(), Some(audit_writer)));

let app = Router::new()
    .nest("/treasury/allocation", public_router(Arc::clone(&engine)))
    .nest(
        "/treasury/allocation",
        internal_router(Arc::clone(&engine))
            .layer(treasury_operator_auth_middleware),
    );
```

---

### Testing

```bash
# Run existing integration suite
cargo test --features database

# Manual smoke test — record a balance and check monitor
curl -X POST /treasury/allocation/record \
  -H "Content-Type: application/json" \
  -d '{"custodian_id":"<uuid>","balance_kobo":5000000000}'

curl /treasury/allocation/monitor
curl /treasury/allocation/public
```

---

### Reviewers

- [ ] Treasury Engineering Lead — logic review (concentration math, rebalancer strategy)
- [ ] Security — confirm no PII/account data leaks in public endpoint
- [ ] DBA — schema review (indexes, generated columns, materialised view refresh strategy)
- [ ] Compliance — RWA weights align with CBN prudential guidelines

Closes #TREASURY-001
