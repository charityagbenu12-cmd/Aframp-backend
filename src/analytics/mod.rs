
pub mod models;
pub mod repository;
pub mod handlers;
pub mod routes;
#[cfg(test)]
pub mod tests;

pub use models::*;
pub use repository::AnalyticsRepository;
pub use handlers::*;
pub use routes::analytics_routes;

// ! Consumer Usage Analytics & Reporting System
//!
//! Comprehensive business-level analytics for API consumer adoption, health monitoring,
//! feature utilization, and revenue attribution.

pub mod models;
pub mod repository;
pub mod snapshot;
pub mod health;
pub mod anomaly;
pub mod reports;
pub mod handlers;
pub mod routes;
pub mod metrics;
pub mod worker;
pub mod cache;
mod tests;

pub use models::*;
pub use repository::AnalyticsRepository;
pub use snapshot::SnapshotGenerator;
pub use health::HealthScoreCalculator;
pub use anomaly::AnomalyDetector;
pub use reports::ReportGenerator;

