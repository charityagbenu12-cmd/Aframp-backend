/// Smart Treasury Allocation Engine — Issue #TREASURY-001
///
/// Modules:
///   types      — domain types (custodians, allocations, tiers, RWA, transfer orders)
///   repository — all DB queries (sqlx)
///   engine     — core allocation logic, concentration checks, RWA calculation
///   alerts     — concentration breach detection and multi-channel notification
///   rebalancer — transfer order generation and recommendation engine
///   handlers   — Axum HTTP handlers (internal + public)
///   routes     — route registration
pub mod alerts;
pub mod engine;
pub mod handlers;
pub mod rebalancer;
pub mod repository;
pub mod routes;
pub mod types;
