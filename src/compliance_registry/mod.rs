//! Compliance Registry module (Issue #2.02).
//!
//! Tracks licenses, regulatory constraints, and corridor governance for every
//! active cross-border payment corridor.

pub mod expiry_worker;
pub mod handlers;
pub mod models;
pub mod repository;
pub mod routes;

pub use handlers::ComplianceRegistryState;
pub use repository::ComplianceRegistryRepository;
pub use routes::compliance_registry_router;
