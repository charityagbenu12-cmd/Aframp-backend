/// Domain types for the Smart Treasury Allocation Engine.
use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ── Enums ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "institution_type", rename_all = "snake_case")]
pub enum InstitutionType {
    Tier1Bank,
    Tbill,
    Repo,
    MoneyMarketFund,
}

impl InstitutionType {
    /// CBN risk weight (basis points) used in RWA calculation.
    /// Tier-1 banks: 20%, T-Bills (sovereign): 0%, REPOs: 10%, MMF: 15%
    pub fn risk_weight_bps(self) -> u32 {
        match self {
            Self::Tier1Bank => 2000,
            Self::Tbill => 0,
            Self::Repo => 1000,
            Self::MoneyMarketFund => 1500,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "risk_rating", rename_all = "lowercase")]
pub enum RiskRating {
    Aaa,
    Aa,
    A,
    Bbb,
    Bb,
    B,
    Ccc,
    Downgraded,
    Suspended,
}

impl RiskRating {
    /// Returns true when the rating warrants an automatic rebalancing trigger.
    pub fn requires_rebalance(self) -> bool {
        matches!(self, Self::Bb | Self::B | Self::Ccc | Self::Downgraded | Self::Suspended)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "allocation_status", rename_all = "snake_case")]
pub enum AllocationStatus {
    Pending,
    Confirmed,
    Disputed,
    Superseded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "alert_severity", rename_all = "lowercase")]
pub enum AlertSeverity {
    Warning,
    Critical,
    Resolved,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "alert_channel", rename_all = "lowercase")]
pub enum AlertChannel {
    Slack,
    Pagerduty,
    Email,
    Sms,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "transfer_order_status", rename_all = "snake_case")]
pub enum TransferOrderStatus {
    PendingApproval,
    Approved,
    Executing,
    Completed,
    Rejected,
    Cancelled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "transfer_order_trigger", rename_all = "snake_case")]
pub enum TransferOrderTrigger {
    ConcentrationBreach,
    RiskRatingDowngrade,
    ManualRebalance,
    ScheduledRebalance,
}

// ── Liquidity Tier ────────────────────────────────────────────────────────────

/// Liquidity tier classification for reserve assets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LiquidityTier {
    /// Tier 1 — Instant cash (bank current/savings accounts). T+0.
    Instant = 1,
    /// Tier 2 — Next-day liquidity (overnight REPOs). T+1.
    NextDay = 2,
    /// Tier 3 — 30-day liquidity (T-Bills, MMFs). T+30.
    ThirtyDay = 3,
}

impl LiquidityTier {
    pub fn from_i16(v: i16) -> Option<Self> {
        match v {
            1 => Some(Self::Instant),
            2 => Some(Self::NextDay),
            3 => Some(Self::ThirtyDay),
            _ => None,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Instant => "Tier 1 — Instant Cash",
            Self::NextDay => "Tier 2 — Next-Day Liquidity",
            Self::ThirtyDay => "Tier 3 — 30-Day Liquidity",
        }
    }
}

// ── DB Row Types ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct CustodianInstitution {
    pub id: Uuid,
    pub public_alias: String,
    pub internal_name: String,
    pub institution_type: InstitutionType,
    pub liquidity_tier: i16,
    pub max_concentration_bps: i32,
    pub risk_rating: RiskRating,
    pub cbn_bank_code: Option<String>,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct ReserveAllocation {
    pub id: Uuid,
    pub custodian_id: Uuid,
    pub balance_kobo: i64,
    pub snapshot_at: DateTime<Utc>,
    pub status: AllocationStatus,
    pub source: String,
    pub statement_hash: Option<String>,
    pub confirmed_by: Option<String>,
    pub confirmed_at: Option<DateTime<Utc>>,
    pub notes: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct ConcentrationSnapshot {
    pub id: Uuid,
    pub custodian_id: Uuid,
    pub snapshot_at: DateTime<Utc>,
    pub balance_kobo: i64,
    pub total_reserves_kobo: i64,
    pub concentration_bps: i32,
    pub max_concentration_bps: i32,
    pub is_breached: bool,
    pub liquidity_tier: i16,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct ConcentrationAlert {
    pub id: Uuid,
    pub custodian_id: Uuid,
    pub snapshot_id: Uuid,
    pub severity: AlertSeverity,
    pub concentration_bps: i32,
    pub max_allowed_bps: i32,
    pub excess_bps: i32,
    pub message: String,
    pub acknowledged_by: Option<String>,
    pub acknowledged_at: Option<DateTime<Utc>>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct RwaDailySnapshot {
    pub id: Uuid,
    pub snapshot_date: NaiveDate,
    pub total_reserves_kobo: i64,
    pub total_rwa_kobo: i64,
    pub onchain_supply_kobo: i64,
    pub peg_coverage_bps: i32,
    pub tier1_kobo: i64,
    pub tier2_kobo: i64,
    pub tier3_kobo: i64,
    pub rwa_breakdown: serde_json::Value,
    pub calculated_by: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct TransferOrder {
    pub id: Uuid,
    pub from_custodian_id: Uuid,
    pub to_custodian_id: Uuid,
    pub amount_kobo: i64,
    pub trigger: TransferOrderTrigger,
    pub trigger_ref_id: Option<Uuid>,
    pub status: TransferOrderStatus,
    pub rationale: String,
    pub projected_from_bps: Option<i32>,
    pub projected_to_bps: Option<i32>,
    pub requested_by: String,
    pub approved_by: Option<String>,
    pub approved_at: Option<DateTime<Utc>>,
    pub rejection_reason: Option<String>,
    pub executed_at: Option<DateTime<Utc>>,
    pub bank_reference: Option<String>,
    pub completed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// ── API Request / Response Types ──────────────────────────────────────────────

/// Request to record a new balance snapshot for a custodian.
#[derive(Debug, Deserialize)]
pub struct RecordAllocationRequest {
    pub custodian_id: Uuid,
    /// Balance in NGN kobo (1 NGN = 100 kobo).
    pub balance_kobo: i64,
    pub source: Option<String>,
    pub statement_hash: Option<String>,
    pub notes: Option<String>,
}

/// Request to approve or reject a transfer order.
#[derive(Debug, Deserialize)]
pub struct TransferOrderDecisionRequest {
    /// "approve" | "reject"
    pub action: String,
    pub rejection_reason: Option<String>,
    pub bank_reference: Option<String>,
}

/// Request to mark a transfer order as completed.
#[derive(Debug, Deserialize)]
pub struct CompleteTransferRequest {
    pub bank_reference: String,
}

/// Request to update a custodian's risk rating (triggers rebalance check).
#[derive(Debug, Deserialize)]
pub struct UpdateRiskRatingRequest {
    pub risk_rating: RiskRating,
    pub reason: Option<String>,
}

/// Allocation monitor dashboard entry (internal — includes internal_name).
#[derive(Debug, Serialize)]
pub struct AllocationMonitorEntry {
    pub custodian_id: Uuid,
    pub public_alias: String,
    pub internal_name: String,
    pub institution_type: InstitutionType,
    pub liquidity_tier: i16,
    pub balance_kobo: i64,
    pub balance_ngn: f64,
    pub concentration_bps: i32,
    pub concentration_pct: f64,
    pub max_concentration_bps: i32,
    pub is_breached: bool,
    pub risk_rating: RiskRating,
    pub snapshot_at: DateTime<Utc>,
}

/// Public dashboard entry (sanitised — no internal_name or account refs).
#[derive(Debug, Serialize)]
pub struct PublicDashboardEntry {
    pub institution_alias: String,
    pub institution_type: InstitutionType,
    pub liquidity_tier: i16,
    pub liquidity_tier_label: String,
    pub concentration_pct: f64,
    pub max_concentration_pct: f64,
    pub is_breached: bool,
    pub snapshot_at: DateTime<Utc>,
}

/// Full allocation monitor response.
#[derive(Debug, Serialize)]
pub struct AllocationMonitorResponse {
    pub entries: Vec<AllocationMonitorEntry>,
    pub total_reserves_kobo: i64,
    pub total_reserves_ngn: f64,
    pub onchain_supply_kobo: i64,
    pub peg_coverage_pct: f64,
    pub active_breaches: usize,
    pub generated_at: DateTime<Utc>,
}

/// Public transparency response (signed by Ed25519 key).
#[derive(Debug, Serialize)]
pub struct PublicReserveResponse {
    pub holdings: Vec<PublicDashboardEntry>,
    pub total_institutions: usize,
    pub tier1_pct: f64,
    pub tier2_pct: f64,
    pub tier3_pct: f64,
    pub peg_status: String,
    pub last_updated: DateTime<Utc>,
}

/// Rebalance recommendation from the engine.
#[derive(Debug, Clone, Serialize)]
pub struct RebalanceRecommendation {
    pub from_custodian_id: Uuid,
    pub from_alias: String,
    pub to_custodian_id: Uuid,
    pub to_alias: String,
    pub amount_kobo: i64,
    pub trigger: TransferOrderTrigger,
    pub rationale: String,
    pub projected_from_bps: i32,
    pub projected_to_bps: i32,
}

/// Query params for listing transfer orders.
#[derive(Debug, Deserialize)]
pub struct ListTransferOrdersQuery {
    pub status: Option<TransferOrderStatus>,
    pub page: Option<i64>,
    pub page_size: Option<i64>,
}

impl ListTransferOrdersQuery {
    pub fn page(&self) -> i64 { self.page.unwrap_or(1).max(1) }
    pub fn page_size(&self) -> i64 { self.page_size.unwrap_or(20).clamp(1, 100) }
    pub fn offset(&self) -> i64 { (self.page() - 1) * self.page_size() }
}
