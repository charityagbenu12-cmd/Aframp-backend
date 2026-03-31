//! Partner Reporting Engine — Cross-Border Settlement Reporting
//!
//! Multi-tenant reporting for regional settlement partners:
//! - Partners see only their own corridor transaction legs
//! - Daily Settlement Statements (PDF/CSV) auto-emailed at 00:00 UTC
//! - Reconciliation API for partner ERP integration
//! - Corridor latency and success/failure analytics
//! - PII masked per GDPR framework

pub mod models;
pub mod repository;
pub mod statement;
pub mod handlers;

pub use models::{PartnerReport, DailySettlementStatement, CorridorAnalytics, ReconciliationEntry};
pub use repository::ReportingRepository;
pub use statement::StatementGenerator;
