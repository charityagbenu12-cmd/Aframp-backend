//! Payment Corridor Router (Issue #2.04).
//!
//! Provides a modular, database-driven framework for managing cross-border
//! payment routes. New corridors can be added via API without a service restart.

pub mod models;
pub mod repository;
pub mod service;
pub mod handlers;
pub mod routes;
