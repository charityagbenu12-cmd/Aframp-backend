//! Mint request API models
//!
//! Request/response types for the mint approval workflow endpoints.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ===== SUBMIT MINT REQUEST =====

/// POST /api/mint/requests
#[derive(Debug, Deserialize)]
pub struct SubmitMintRequest {
    /// Stellar destination wallet address
    pub destination_wallet: String,
    /// Amount in NGN (tier is calculated from this)
    pub amount_ngn: String,
    /// Optional external reference
    #[serde(default)]
    pub reference: Option<String>,
    /// Optional metadata
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
}

/// Response after submitting a mint request
#[derive(Debug, Serialize)]
pub struct SubmitMintResponse {
    pub mint_request_id: Uuid,
    pub status: String,
    pub approval_tier: u8,
    pub required_approvals: u8,
    pub amount_ngn: String,
    pub amount_cngn: String,
    pub expires_at: DateTime<Utc>,
    pub message: String,
}

// ===== APPROVE / REJECT =====

/// POST /api/mint/requests/:id/approve
#[derive(Debug, Deserialize)]
pub struct ApproveMintRequest {
    /// Optional comment from the approver
    #[serde(default)]
    pub comment: Option<String>,
}

/// POST /api/mint/requests/:id/reject
#[derive(Debug, Deserialize)]
pub struct RejectMintRequest {
    /// Mandatory reason code (e.g. "SUSPICIOUS_ACTIVITY", "AMOUNT_EXCEEDS_LIMIT")
    pub reason_code: String,
    /// Optional human-readable comment
    #[serde(default)]
    pub comment: Option<String>,
}

/// Generic action response
#[derive(Debug, Serialize)]
pub struct MintActionResponse {
    pub mint_request_id: Uuid,
    pub status: String,
    pub message: String,
    pub approvals_received: usize,
    pub approvals_required: usize,
}

// ===== GET MINT REQUEST =====

/// Single approval entry in the timeline
#[derive(Debug, Serialize)]
pub struct ApprovalEntry {
    pub approver_id: String,
    pub approver_role: String,
    pub action: String,
    pub reason_code: Option<String>,
    pub comment: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Single audit log entry in the timeline
#[derive(Debug, Serialize)]
pub struct AuditEntry {
    pub id: i64,
    pub actor_id: String,
    pub actor_role: Option<String>,
    pub event_type: String,
    pub from_status: Option<String>,
    pub to_status: Option<String>,
    pub payload: serde_json::Value,
    pub created_at: DateTime<Utc>,
}

/// Full mint request detail response
#[derive(Debug, Serialize)]
pub struct MintRequestDetail {
    pub id: Uuid,
    pub submitted_by: String,
    pub destination_wallet: String,
    pub amount_ngn: String,
    pub amount_cngn: String,
    pub approval_tier: u8,
    pub required_approvals: u8,
    pub status: String,
    pub reference: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub stellar_tx_hash: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// Ordered approval timeline
    pub approvals: Vec<ApprovalEntry>,
}

// ===== LIST MINT REQUESTS =====

/// Query params for listing mint requests
#[derive(Debug, Deserialize)]
pub struct ListMintRequestsQuery {
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub limit: Option<i64>,
    #[serde(default)]
    pub offset: Option<i64>,
}

/// Paginated list response
#[derive(Debug, Serialize)]
pub struct ListMintRequestsResponse {
    pub items: Vec<MintRequestDetail>,
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
}
