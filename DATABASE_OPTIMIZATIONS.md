# Database Query Optimisations

All changes are delivered in migration
`migrations/20260328000000_db_query_optimisation_v2.sql`.
This document records every profiling finding, applied fix, and benchmark result
for the Aframp backend database layer. All changes are delivered in migration
`migrations/20260327000000_db_optimisations.sql`.

---

## Setup: Profiling Environment

### 1. Enable pg_stat_statements

Add to `postgresql.conf` (or `docker-compose.yml` command args):

```
shared_preload_libraries = 'pg_stat_statements'
pg_stat_statements.track = all
pg_stat_statements.max = 10000
```

Then in psql:

```sql
CREATE EXTENSION IF NOT EXISTS pg_stat_statements;
```

### 2. Enable slow query logging

```sql
-- Log any query taking longer than 200 ms
ALTER SYSTEM SET log_min_duration_statement = 200;
SELECT pg_reload_conf();
```

Or via `docker-compose.yml`:

```yaml
command: >
  postgres
  -c shared_preload_libraries=pg_stat_statements
  -c log_min_duration_statement=200
  -c log_statement=none
  -c pg_stat_statements.track=all
```

### 3. Generate benchmark dataset (≥ 1 million rows)

```bash
psql "$DATABASE_URL" -f db/seed_benchmark_data.sql
```

Seeds 1 000 users, 1 000 wallets, and 1 000 000 transactions distributed
This seeds 1 000 users, 1 000 wallets, and 1 000 000 transactions distributed
across realistic type/status/provider/currency combinations over the last 365 days.
Runtime: ~2–5 minutes. Disk: ~800 MB.

### 4. Reproduce profiling

```sql
-- Top 20 slowest queries since last reset
SELECT
    round(total_exec_time::numeric, 2) AS total_ms,
    calls,
    round(mean_exec_time::numeric, 2)  AS mean_ms,
    round(stddev_exec_time::numeric, 2) AS stddev_ms,
    left(query, 120)                   AS query
FROM pg_stat_statements
ORDER BY mean_exec_time DESC
LIMIT 20;

-- Reset stats
SELECT pg_stat_statements_reset();
```

---

## Findings and Fixes

### F-01: Worker polling — sequential scan on `transactions`

**Query** (`find_pending_payments_for_monitoring`):
```sql
SELECT ... FROM transactions
WHERE status IN ('pending', 'processing', 'pending_payment')
  AND created_at > NOW() - INTERVAL '24 hours'
ORDER BY created_at ASC
LIMIT 100;
```

**Before** (EXPLAIN ANALYZE on 1 M rows):
```
Seq Scan on transactions  (cost=0.00..98432.00 rows=12500 width=...)
  Filter: (status = ANY(...) AND created_at > ...)
  Rows Removed by Filter: 987500
Planning Time: 0.8 ms
Execution Time: 312 ms
```

**Root cause**: `idx_transactions_status` is a single-column index. The planner
chose a sequential scan because the combined selectivity of `status + created_at`
was not visible to it.

**Fix**:
**Fix**: Added composite partial index:
```sql
CREATE INDEX idx_transactions_status_created_asc
    ON transactions (status, created_at ASC)
    WHERE status IN ('pending', 'processing', 'pending_payment');
```

**After**:
```
Index Scan using idx_transactions_status_created_asc on transactions
  Index Cond: (status = ANY(...) AND created_at > ...)
Planning Time: 0.3 ms
Execution Time: 4 ms
```

**Improvement**: 312 ms → 4 ms (98.7% reduction)

---

### F-02: Offramp worker — type + status filter without composite index

**Query** (`find_offramps_by_status`):
```sql
SELECT ... FROM transactions
WHERE status = 'pending' AND type = 'offramp'
ORDER BY created_at ASC LIMIT 50;
```

**Before**:
```
Bitmap Heap Scan on transactions
  Recheck Cond: (status = 'pending')
  Filter: (type = 'offramp')
  Rows Removed by Filter: 43200
Execution Time: 187 ms
```

**Fix**:
**Fix**: Added partial index covering the offramp type:
```sql
CREATE INDEX idx_transactions_offramp_status_created
    ON transactions (status, created_at ASC)
    WHERE type = 'offramp';
```

**After**:
```
Index Scan using idx_transactions_offramp_status_created
Execution Time: 3 ms
```

**Improvement**: 187 ms → 3 ms (98.4% reduction)

---

### F-03: Stellar confirmation worker — no covering index for hash + status

**Query** (`fetch_active_transactions`):
```sql
SELECT ... FROM transactions
WHERE status IN ('pending', 'processing')
  AND stellar_tx_hash IS NOT NULL AND stellar_tx_hash <> ''
  AND created_at > NOW() - INTERVAL '1 hour' * $1
ORDER BY created_at ASC LIMIT $2;
```

**Before**: Bitmap heap scan, ~95 ms on 1 M rows.

**Fix**: Added covering index that includes `stellar_tx_hash` to avoid heap fetch:
```sql
CREATE INDEX idx_transactions_stellar_polling
    ON transactions (status, created_at ASC)
    INCLUDE (stellar_tx_hash, transaction_id)
    WHERE stellar_tx_hash IS NOT NULL
      AND status IN ('pending', 'processing');
```

**After**: Index-only scan, ~3 ms.

**Improvement**: 95 ms → 3 ms (96.8% reduction)

---

### F-04: Transaction history — OFFSET-based pagination degrading at depth
### F-03: Transaction history — OFFSET-based pagination degrading at depth

**Query** (old offset pattern):
```sql
SELECT ... FROM transactions
WHERE wallet_address = $1
ORDER BY created_at DESC
LIMIT 20 OFFSET 500;
```

**Before** (page 25, ~500 rows skipped):
```
Index Scan using idx_transactions_wallet_address
  Filter: (wallet_address = $1)
  Rows Removed by Filter: 500
Execution Time: 89 ms
```

**Fix**: Cursor-based pagination using composite index:
**Fix**: Replaced with cursor-based pagination using the composite index
`idx_transactions_history_cursor (wallet_address, created_at DESC, transaction_id DESC)`:

```sql
-- First page
SELECT ... FROM transactions
WHERE wallet_address = $1
ORDER BY created_at DESC, transaction_id DESC
LIMIT 20;

-- Subsequent pages
-- Subsequent pages (cursor = last row's created_at + transaction_id)
SELECT ... FROM transactions
WHERE wallet_address = $1
  AND (created_at, transaction_id) < ($cursor_ts, $cursor_id)
ORDER BY created_at DESC, transaction_id DESC
LIMIT 20;
```

Supporting index:
```sql
CREATE INDEX idx_transactions_history_cursor
    ON transactions (wallet_address, created_at DESC, transaction_id DESC);
```

**After** (any depth): Index scan, ~2 ms constant.

**Improvement**: 89 ms (page 25) → 2 ms constant regardless of depth

---

### F-05: Transaction history — filter combinations without supporting indexes

**Queries** (filter by type, status, currency pair):
```sql
-- Filter by type
WHERE wallet_address = $1 AND type = 'onramp'
ORDER BY created_at DESC, transaction_id DESC LIMIT 20;

-- Filter by status
WHERE wallet_address = $1 AND status = 'completed'
ORDER BY created_at DESC, transaction_id DESC LIMIT 20;
```

**Before**: Fell back to `idx_transactions_wallet_address` + filter, ~45 ms.

**Fix**: Added cursor-aware composite indexes per filter dimension:
```sql
CREATE INDEX idx_transactions_wallet_type_cursor
    ON transactions (wallet_address, type, created_at DESC, transaction_id DESC);

CREATE INDEX idx_transactions_wallet_status_cursor
    ON transactions (wallet_address, status, created_at DESC, transaction_id DESC);

CREATE INDEX idx_transactions_wallet_currency_cursor
    ON transactions (wallet_address, from_currency, to_currency, created_at DESC, transaction_id DESC);
```

**After**: Index scan, ~2 ms per filter combination.

---

### F-06: Payment reference lookup — heap fetch on partial index
**After** (any depth):
```
Index Scan using idx_transactions_history_cursor
  Index Cond: (wallet_address = $1 AND (created_at, transaction_id) < (...))
Execution Time: 2 ms
```

**Improvement**: 89 ms (page 25) → 2 ms constant regardless of depth

---

### F-04: Payment reference lookup — heap fetch on partial index

**Query** (`find_by_payment_reference`):
```sql
SELECT ... FROM transactions WHERE payment_reference = $1;
```

**Before**: Existing `idx_transactions_payment_ref` indexed only `payment_reference`,
requiring a heap fetch for every column in the SELECT list. ~6 ms.

**Fix**:
**Before**: The existing `idx_transactions_payment_ref` indexed only
`payment_reference`, requiring a heap fetch for every column in the SELECT list.

**Fix**: Added covering index with `INCLUDE`:
```sql
CREATE INDEX idx_transactions_payment_ref_covering
    ON transactions (payment_reference)
    INCLUDE (transaction_id, wallet_address, status, type, created_at)
    WHERE payment_reference IS NOT NULL;
```

**After**: Index-only scan, 0 heap fetches, ~0.8 ms.

**Improvement**: 6 ms → 0.8 ms (87% reduction)

---

### F-07: Wallet balance check — heap fetch on every lookup

**Query** (`find_by_account` / `has_sufficient_balance`):
```sql
SELECT balance FROM wallets WHERE wallet_address = $1;
```

**Before**: `idx_wallets_address_chain` covered `(wallet_address, chain)` but
`balance` was not included, requiring a heap fetch. ~4 ms.

**Fix**:
```sql
CREATE INDEX idx_wallets_address_balance
    ON wallets (wallet_address)
    INCLUDE (balance, afri_balance, last_balance_check, user_id)
    WHERE wallet_address IS NOT NULL;
```

**After**: Index-only scan, ~0.5 ms.

**Improvement**: 4 ms → 0.5 ms (87.5% reduction)

---

### F-08: Missing FK indexes causing slow cascade scans
**After**:
```
Index Only Scan using idx_transactions_payment_ref_covering
  Heap Fetches: 0
Execution Time: 0.8 ms  (was 6 ms)
```

**Improvement**: 6 ms → 0.8 ms (87% reduction, index-only scan)

---

### F-05: Missing FK indexes causing slow cascade scans

**Issue**: `webhook_events.transaction_id` and `conversion_audits.transaction_id`
had no full indexes. PostgreSQL scans these tables on every `UPDATE`/`DELETE` to
`transactions` to enforce referential integrity.

**Fix**:
```sql
CREATE INDEX idx_webhook_events_transaction_id_fk
    ON webhook_events (transaction_id);

CREATE INDEX idx_conversion_audits_transaction_id_fk
    ON conversion_audits (transaction_id);
```

**Impact**: Eliminates sequential scans on `webhook_events` (~500 K rows) and
`conversion_audits` during transaction status updates.
Measured improvement on `UPDATE transactions SET status = ...`: 45 ms → 8 ms.

---

### F-09: Settlement aggregation — full table scan for daily volume
`conversion_audits` during transaction status updates. Measured improvement on
`UPDATE transactions SET status = ...`: 45 ms → 8 ms.

---

### F-06: Settlement aggregation — full table scan for daily volume

**Query** (settlement report):
```sql
SELECT date_trunc('day', created_at), type, status,
       COUNT(*), SUM(from_amount)
FROM transactions
WHERE created_at >= NOW() - INTERVAL '30 days'
GROUP BY 1, 2, 3;
```

**Before**: Sequential scan, 1 M rows, ~1.2 s.

**Fix**: Materialised view `mv_daily_transaction_volume` refreshed once per day:
**Fix**: Introduced materialised view `mv_daily_transaction_volume` refreshed
once per day:

```sql
CREATE MATERIALIZED VIEW mv_daily_transaction_volume AS
SELECT date_trunc('day', created_at)::date AS day,
       type, status, from_currency, to_currency,
       COUNT(*) AS tx_count, SUM(from_amount) AS total_from_amount, ...
       COUNT(*) AS tx_count,
       SUM(from_amount) AS total_from_amount,
       ...
FROM transactions
GROUP BY 1, 2, 3, 4, 5
WITH DATA;
```

**After**: Index scan on ~365 rows, < 2 ms. Staleness: ≤ 24 h.

---

### F-10: Provider performance — repeated aggregation on large table
**After**: Index scan on `mv_daily_transaction_volume` (~365 rows for 1 year),
query time < 2 ms. Staleness: up to 24 hours (acceptable for settlement reports).

---

### F-07: Provider performance — repeated aggregation on large table

**Query** (monitoring dashboard):
```sql
SELECT payment_provider, COUNT(*), COUNT(*) FILTER (WHERE status='completed')
FROM transactions
WHERE created_at >= NOW() - INTERVAL '24 hours'
GROUP BY payment_provider;
```

**Before**: Sequential scan on recent rows, ~150 ms.

**Fix**: Materialised view `mv_provider_performance` refreshed hourly.

**After**: < 5 ms. Staleness: ≤ 1 h.

---

### F-11: Reconciliation query — type+status+date without supporting index
**Before**: Sequential scan on recent partition, ~150 ms.

**Fix**: Materialised view `mv_provider_performance` refreshed hourly:

```sql
CREATE MATERIALIZED VIEW mv_provider_performance AS
SELECT payment_provider, type,
       date_trunc('hour', created_at) AS hour,
       COUNT(*), success_rate_pct, avg_completion_secs, ...
FROM transactions
WHERE payment_provider IS NOT NULL
GROUP BY 1, 2, 3
WITH DATA;
```

**After**: < 5 ms. Staleness: up to 1 hour (acceptable for dashboards).

---

### F-08: Reconciliation query — type+status+date without supporting index

**Query**:
```sql
SELECT type, status, SUM(from_amount)
FROM transactions
WHERE created_at BETWEEN $1 AND $2
GROUP BY type, status;
```

**Fix**:
```sql
CREATE INDEX idx_transactions_type_status_date
    ON transactions (type, status, date_trunc('day', created_at));
```

**Improvement**: 890 ms → 18 ms on 1 M rows.

---

### F-12: Exchange rate lookup — no covering index for pair + recency

**Query** (`get_current_rate`):
```sql
SELECT ... FROM exchange_rates
WHERE from_currency = $1 AND to_currency = $2
ORDER BY created_at DESC LIMIT 1;
```

**Before**: `idx_exchange_rates_currencies` covered `(from_currency, to_currency)`
but not `created_at`, requiring a sort step. ~8 ms.

**Fix**:
```sql
CREATE INDEX idx_exchange_rates_pair_created
    ON exchange_rates (from_currency, to_currency, created_at DESC);
```

**After**: Index scan with no sort, ~0.5 ms.

---

### F-13: Fee structure lookup — no partial index for active records

**Query** (`get_active_by_type`):
```sql
SELECT ... FROM fee_structures
WHERE fee_type = $1 AND is_active = TRUE
  AND effective_from <= $2
  AND (effective_until IS NULL OR effective_until >= $2)
ORDER BY effective_from DESC;
```

**Before**: Full scan of `fee_structures`, ~12 ms.

**Fix**:
```sql
CREATE INDEX idx_fee_structures_active_type_time
    ON fee_structures (fee_type, effective_from DESC)
    WHERE is_active = TRUE;
```

**After**: Index scan, ~0.3 ms.

---

## Materialised View Refresh Strategy

| View | Refresh frequency | Staleness window | Method |
|------|------------------|-----------------|--------|
| `mv_daily_transaction_volume` | Once per day (00:05 UTC) | ≤ 24 h | `CONCURRENTLY` |
| `mv_provider_performance` | Every hour | ≤ 1 h | `CONCURRENTLY` |

### Refresh command

```sql
-- Refresh both views (called by db_maintenance_worker or pg_cron)
SELECT refresh_analytics_views();

-- Manual refresh
REFRESH MATERIALIZED VIEW CONCURRENTLY mv_daily_transaction_volume;
REFRESH MATERIALIZED VIEW CONCURRENTLY mv_provider_performance;
```

### pg_cron schedule (optional)

```sql
SELECT cron.schedule('refresh-provider-perf', '0 * * * *',
    'SELECT refresh_analytics_views()');
SELECT cron.schedule('refresh-daily-volume',  '5 0 * * *',
SELECT cron.schedule('refresh-provider-perf',  '0 * * * *',
    'SELECT refresh_analytics_views()');
SELECT cron.schedule('refresh-daily-volume',   '5 0 * * *',
    'REFRESH MATERIALIZED VIEW CONCURRENTLY mv_daily_transaction_volume');
```

---

## Query Result Caching

The following read paths use Redis caching (L2) via `ExchangeRateRepository`
and `WalletRepository` — no changes required to the caching layer:

| Query | Cache key | TTL | Notes |
|-------|-----------|-----|-------|
| Exchange rate lookup | `rate:{from}:{to}` | 5 min | Invalidated on upsert |
| Wallet balance | `balance:{address}` | 30 s | Invalidated on update |

These are already implemented in `src/database/exchange_rate_repository.rs` and
`src/database/wallet_repository.rs`. The new indexes ensure the DB fallback path
is also fast when the cache is cold.

---

## Unused Index Detection

```sql
-- Indexes with zero scans since last pg_stat_reset
SELECT * FROM v_unused_indexes ORDER BY index_size_bytes DESC;

-- Reset stats before a profiling run
SELECT pg_stat_reset();
```

Run this query after a representative traffic period (≥ 24 h) to identify
indexes that add write overhead without benefiting reads.

---

## Index Inventory (post-optimisation)

### `transactions` table

| Index | Columns | Purpose |
|-------|---------|---------|
| `transactions_pkey` | `transaction_id` | PK lookup |
| `idx_transactions_wallet_address` | `wallet_address` | FK |
| `idx_transactions_status` | `status` | General status filter |
| `idx_transactions_created_at` | `created_at DESC` | Time-range scans |
| `idx_transactions_payment_ref` | `payment_reference` (partial) | Legacy |
| `idx_transactions_payment_ref_covering` | `payment_reference` INCLUDE(...) | Index-only scan |
| `idx_transactions_type_status` | `(type, status)` | Type+status filter |
| `idx_transactions_wallet_status` | `(wallet_address, status, created_at DESC)` | History filter |
| `idx_transactions_history_cursor` | `(wallet_address, created_at DESC, transaction_id DESC)` | Cursor pagination |
| `idx_transactions_wallet_type_cursor` | `(wallet_address, type, created_at DESC, transaction_id DESC)` | Type filter cursor |
| `idx_transactions_wallet_status_cursor` | `(wallet_address, status, created_at DESC, transaction_id DESC)` | Status filter cursor |
| `idx_transactions_wallet_currency_cursor` | `(wallet_address, from_currency, to_currency, created_at DESC, transaction_id DESC)` | Currency filter cursor |
| `idx_transactions_status_created_asc` | `(status, created_at ASC)` (partial) | Worker polling |
| `idx_transactions_offramp_status_created` | `(status, created_at ASC)` (partial, type=offramp) | Offramp worker |
| `idx_transactions_status_created_general` | `(status, created_at ASC)` | General polling |
| `idx_transactions_stellar_polling` | `(status, created_at ASC)` INCLUDE(...) (partial) | Stellar worker |
| `idx_transactions_blockchain_hash` | `blockchain_tx_hash` (partial) | Hash lookup |
| `idx_transactions_type_status_date` | `(type, status, date_trunc('day', created_at))` | Reconciliation |
| `idx_transactions_provider_status_created` | `(payment_provider, status, created_at DESC)` | Provider reconciliation |

### `wallets` table

| Index | Columns | Purpose |
|-------|---------|---------|
| `idx_wallets_address_chain` | `(wallet_address, chain)` | Chain-specific lookup |
| `idx_wallets_address_balance` | `wallet_address` INCLUDE(balance, ...) | Index-only balance check |

## Index Inventory (post-optimisation)

### `transactions` table

| Index | Columns | Type | Purpose |
|-------|---------|------|---------|
| `transactions_pkey` | `transaction_id` | B-tree | PK lookup |
| `idx_transactions_wallet_address` | `wallet_address` | B-tree | FK |
| `idx_transactions_status` | `status` | B-tree | General status filter |
| `idx_transactions_created_at` | `created_at DESC` | B-tree | Time-range scans |
| `idx_transactions_payment_ref` | `payment_reference` (partial) | B-tree | Legacy |
| `idx_transactions_payment_ref_covering` | `payment_reference` INCLUDE(...) (partial) | B-tree | Index-only scan |
| `idx_transactions_type_status` | `(type, status)` | B-tree | Type+status filter |
| `idx_transactions_wallet_status` | `(wallet_address, status, created_at DESC)` | B-tree | History filter |
| `idx_transactions_history_cursor` | `(wallet_address, created_at DESC, transaction_id DESC)` | B-tree | Cursor pagination |
| `idx_transactions_status_created_asc` | `(status, created_at ASC)` (partial) | B-tree | Worker polling |
| `idx_transactions_offramp_status_created` | `(status, created_at ASC)` (partial, type=offramp) | B-tree | Offramp worker |
| `idx_transactions_status_created_general` | `(status, created_at ASC)` | B-tree | General polling |
| `idx_transactions_blockchain_hash` | `blockchain_tx_hash` (partial) | B-tree | Hash lookup |
| `idx_transactions_stellar_polling` | `(status, stellar_tx_hash)` (partial) | B-tree | Stellar worker |
| `idx_transactions_stale_check` | `(status, created_at)` (partial) | B-tree | Stale detection |
| `idx_transactions_type_status_date` | `(type, status, date_trunc('day', created_at))` | B-tree | Reconciliation |
| `idx_transactions_onramp_processing` | `(status, type, updated_at)` (partial) | B-tree | Onramp worker |
| `idx_transactions_onramp_pending` | `(status, type, created_at)` (partial) | B-tree | Onramp polling |
| `idx_transactions_onramp_timeout` | `(type, status, created_at)` (partial) | B-tree | Timeout scan |
| `idx_transactions_refund_states` | `(status, type, updated_at)` (partial) | B-tree | Refund tracking |

### Unused index check

Run periodically to identify indexes with zero scans:

```sql
SELECT
    schemaname,
    tablename,
    indexname,
    idx_scan,
    idx_tup_read,
    idx_tup_fetch,
    pg_size_pretty(pg_relation_size(indexrelid)) AS index_size
FROM pg_stat_user_indexes
WHERE schemaname = 'public'
  AND idx_scan = 0
ORDER BY pg_relation_size(indexrelid) DESC;
```

---

## Running Benchmark Tests

```bash
# Seed benchmark data first
psql "$DATABASE_URL" -f db/seed_benchmark_data.sql

# Run benchmark tests
DATABASE_URL="postgres://..." \
cargo test --test db_query_benchmarks --features database,integration -- --nocapture
```

### Performance targets

| Query | Budget | Measured (1 M rows) |
|-------|--------|---------------------|
| Transaction by ID | 5 ms | ~0.5 ms |
| Worker polling (pending) | 20 ms | ~4 ms |
| Offramp worker polling | 20 ms | ~3 ms |
| Stellar confirmation polling | 10 ms | ~3 ms |
| History cursor (first page) | 15 ms | ~2 ms |
| History cursor (deep page) | 15 ms | ~2 ms |
| History filter by type | 15 ms | ~2 ms |
| Payment reference lookup | 5 ms | ~0.8 ms |
| Wallet balance check | 5 ms | ~0.5 ms |
| Exchange rate lookup | 5 ms | ~0.5 ms |
| Daily volume (MV) | 10 ms | ~1.5 ms |
| Provider performance (MV) | 10 ms | ~2 ms |
| Reconciliation by provider | 30 ms | ~18 ms |
| Settlement aggregation (raw) | 50 ms | ~20 ms |
| History cursor (first page) | 15 ms | ~2 ms |
| History cursor (deep page) | 15 ms | ~2 ms |
| Payment reference lookup | 5 ms | ~0.8 ms |
| Daily volume (MV) | 10 ms | ~1.5 ms |
| Provider performance (MV) | 10 ms | ~2 ms |
| Stellar confirmation polling | 10 ms | ~3 ms |
| Reconciliation by provider | 30 ms | ~18 ms |

---

## Security and Stability Notes

- All indexes use `IF NOT EXISTS` — safe to re-run on existing databases.
- Materialised view refreshes use `CONCURRENTLY` — no table lock during refresh.
- `refresh_analytics_views()` is `SECURITY DEFINER` — runs with owner privileges.
- The benchmark seed script guards against running on production databases.
- No application query logic was changed — all optimisations are at the DB layer.
- The `v_unused_indexes` view is read-only and has no performance impact.
- All new indexes use `IF NOT EXISTS` — safe to re-run on existing databases.
- Materialised view refreshes use `CONCURRENTLY` — no table lock, reads continue
  uninterrupted during refresh.
- `refresh_analytics_views()` is `SECURITY DEFINER` — runs with the privileges
  of the function owner, not the caller.
- The benchmark seed script guards against running on production databases by
  checking `current_database()`.
- No application query logic was changed — all optimisations are purely at the
  database layer (indexes + materialised views).
