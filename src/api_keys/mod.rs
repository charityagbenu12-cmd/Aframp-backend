//! API Key Generation & Issuance System (Issue #131)
//!
//! Modules:
//!   generator   — cryptographically secure key generation with Argon2id hashing
//!   repository  — database layer for key CRUD and audit logging
//!   middleware  — verification middleware (lives in src/middleware/api_key.rs)

pub mod generator;
pub mod repository;
