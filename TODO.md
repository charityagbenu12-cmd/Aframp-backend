# Settlement Worker Implementation TODO
Approved plan from BLACKBOXAI. Progress tracked here. Steps from plan breakdown.

## [x] 0. Git Branch & PR ✅
- Created `blackboxai/settlement-worker-part1` branch
- Committed schema, types, metadata (steps 1-4 partial)
- Pushed & created draft PR

## [x] 1. Database Migration ✅
- Created `migrations/20261001000000_create_settlement_schema.sql`
  - `settlement_batches` table (w/ CHECK constraints)
  - `reconciliation_reports` table
  - Indexes + updated_at triggers + comments

## [x] 2. Core Types ✅
- Created `src/database/settlement.rs` - `SettlementBatchStatus` + `ReconciliationStatus` enums, transitions, tests

## [x] 3. Metadata Types ✅
- Created `src/workers/settlement_metadata.rs` - `SettlementMetadata` struct w/ json roundtrip, tx tracking, failure/retry logic, tests

## [ ] 4. Repository
- `src/database/settlement_repository.rs`
  - CRUD for batches/reports
  - Query eligible txns
  - Fee calcs

## [ ] 5. Config
- Edit `src/config.rs` - Add `SettlementWorkerConfig`

## [ ] 6. Worker Implementation
- `src/workers/settlement_worker.rs`
  - Config, new(), run(), run_cycle()
  - Stages: initiations, monitoring, reconciliation

## [ ] 7. Exports & Registration
- Edit `src/workers/mod.rs` - `pub mod settlement_worker;`
- Edit `src/main.rs` - Spawn tokio::spawn(worker.run(shutdown_rx.clone()))

## [ ] 8. Tests
- Unit tests in settlement_worker.rs
- Integration tests/settlement_integration.rs

## [ ] 9. Seeds & Scripts
- `db/seed_settlement_fees.sql`
- `setup-settlement-fees.sh`

## [ ] 10. Verification
- `sqlx migrate run`
- `cargo test`
- `cargo run` - log/metric checks
- Manual E2E: insert completed txns, verify batch/recon

**Next:** Complete step 4 - Repository implementation.
