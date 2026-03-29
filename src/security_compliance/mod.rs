//! Security Compliance & Vulnerability Scanning Framework
//!
//! Implements continuous security posture assessment covering:
//!   - Dependency vulnerability management (cargo audit integration)
//!   - Static application security testing (SAST)
//!   - Container image vulnerability scanning
//!   - Secrets detection
//!   - OWASP API Security Top 10 compliance
//!   - Infrastructure configuration compliance
//!   - Vulnerability management lifecycle (acknowledge / resolve / accept-risk)
//!   - Compliance posture scoring and reporting
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────┐
//! │               SecurityComplianceFramework                    │
//! │                                                              │
//! │  ┌─────────────┐  ┌──────────────┐  ┌──────────────────┐   │
//! │  │ VulnRegistry│  │PostureScorer │  │ ComplianceReporter│  │
//! │  │ (lifecycle) │  │ (daily score)│  │ (monthly reports) │  │
//! │  └─────────────┘  └──────────────┘  └──────────────────┘   │
//! │                                                              │
//! │  ┌─────────────┐  ┌──────────────┐                          │
//! │  │ SlaEnforcer │  │ AllowlistMgr │                          │
//! │  │ (deadlines) │  │ (fp tracking)│                          │
//! │  └─────────────┘  └──────────────┘                          │
//! └──────────────────────────────────────────────────────────────┘
//! ```

pub mod config;
pub mod handlers;
pub mod metrics;
pub mod models;
pub mod repository;
pub mod scoring;
pub mod tests;
pub mod worker;

pub use config::SecurityComplianceConfig;
pub use models::{
    CompliancePosture, ScanRun, VulnSeverity, VulnSource, VulnStatus, Vulnerability,
};
pub use scoring::PostureScorer;
