//! Partner reporting data models

use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use sqlx::types::BigDecimal;
use uuid::Uuid;

/// A single transaction leg visible to a partner
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct ReconciliationEntry {
    pub transaction_id: Uuid,
    pub corridor_id: String,
    /// cNGN amount locked/burned
    pub cngn_amount: BigDecimal,
    /// FX rate applied
    pub fx_rate: BigDecimal,
    /// Destination currency (KES / GHS / ZAR)
    pub destination_currency: String,
    /// Destination amount paid out
    pub destination_amount: BigDecimal,
    /// Partner commission for this transaction
    pub partner_commission: BigDecimal,
    pub status: String,
    /// Masked sender reference (PII-safe)
    pub sender_ref: String,
    pub created_at: DateTime<Utc>,
    pub settled_at: Option<DateTime<Utc>>,
}

/// Daily Settlement Statement for a partner
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DailySettlementStatement {
    pub partner_id: Uuid,
    pub corridor_id: String,
    pub date: NaiveDate,
    pub total_transactions: i64,
    pub total_cngn_volume: BigDecimal,
    pub total_destination_amount: BigDecimal,
    pub total_partner_commission: BigDecimal,
    pub success_count: i64,
    pub failure_count: i64,
    pub entries: Vec<ReconciliationEntry>,
    pub generated_at: DateTime<Utc>,
}

/// Corridor performance analytics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorridorAnalytics {
    pub corridor_id: String,
    pub partner_id: Uuid,
    pub period_start: NaiveDate,
    pub period_end: NaiveDate,
    /// Average time from cNGN lock to fiat payout (seconds)
    pub avg_latency_seconds: f64,
    pub success_rate: f64,
    pub total_volume: BigDecimal,
    pub transaction_count: i64,
}

/// Summary for partner report listing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartnerReport {
    pub id: Uuid,
    pub partner_id: Uuid,
    pub corridor_id: String,
    pub report_date: NaiveDate,
    pub format: String, // "csv" | "pdf"
    pub download_url: Option<String>,
    pub generated_at: DateTime<Utc>,
}
