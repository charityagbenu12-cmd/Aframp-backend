//! AML Financial Intelligence Layer — Cross-Border Transaction Screening
//!
//! Implements FATF-compliant AML controls for international payment corridors:
//! - Sanctions screening (OFAC, UN, EU SDN lists) via external AML provider
//! - Velocity & pattern analysis (smurfing, rapid-flip detection)
//! - Corridor-specific risk scoring (Basel AML Index / FATF Grey List)
//! - Automated case management with compliance officer workflow

pub mod models;
pub mod screening;
pub mod risk_scoring;
pub mod case_management;
pub mod repository;
pub mod handlers;

pub use models::{
    AmlScreeningRequest, AmlScreeningResult, AmlFlag, AmlFlagLevel, AmlCaseStatus,
    CorridorRiskWeight, VelocityPattern,
};
pub use screening::SanctionsScreeningService;
pub use risk_scoring::CorridorRiskScorer;
pub use case_management::AmlCaseManager;
