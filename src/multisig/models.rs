//! Domain models for the Multi-Sig Governance module.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ─────────────────────────────────────────────────────────────────────────────
// Enums
// ─────────────────────────────────────────────────────────────────────────────

/// The class of Stellar operation that requires M-of-N consensus.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "multisig_op_type", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum MultiSigOpType {
    Mint,
    Burn,
    SetOptions,
    AddSigner,
    RemoveSigner,
    ChangeThreshold,
}

impl MultiSigOpType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Mint => "mint",
            Self::Burn => "burn",
            Self::SetOptions => "set_options",
            Self::AddSigner => "add_signer",
            Self::RemoveSigner => "remove_signer",
            Self::ChangeThreshold => "change_threshold",
        }
    }

    /// Returns true for governance changes that require a time-lock.
    pub fn requires_time_lock(self) -> bool {
        matches!(
            self,
            Self::AddSigner | Self::RemoveSigner | Self::ChangeThreshold
        )
    }
}

impl std::fmt::Display for MultiSigOpType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Lifecycle state of a governance proposal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "multisig_proposal_status", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum MultiSigProposalStatus {
    /// Awaiting signatures.
    Pending,
    /// Threshold met but time-lock has not elapsed (governance changes only).
    TimeLocked,
    /// Threshold met and time-lock elapsed (or no time-lock required). Ready to submit.
    Ready,
    /// XDR submitted to Stellar Horizon.
    Submitted,
    /// On-chain confirmation received.
    Confirmed,
    /// Explicitly rejected by a quorum signer.
    Rejected,
    /// Proposal TTL elapsed without reaching threshold.
    Expired,
}

impl MultiSigProposalStatus {
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Confirmed | Self::Rejected | Self::Expired
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Core domain structs
// ─────────────────────────────────────────────────────────────────────────────

/// A treasury operation proposal awaiting M-of-N signatures.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct MultiSigProposal {
    pub id: Uuid,
    pub op_type: MultiSigOpType,
    pub description: String,

    /// The unsigned Stellar transaction XDR (base64).
    /// Signers MUST inspect this before signing.
    pub unsigned_xdr: String,

    /// Accumulated signed XDR after each signer contributes their
    /// DecoratedSignature. NULL until the first signature is collected.
    pub signed_xdr: Option<String>,

    /// Stellar transaction hash after on-chain submission.
    pub stellar_tx_hash: Option<String>,

    /// Quorum snapshot at proposal time.
    pub required_signatures: i16,
    pub total_signers: i16,

    /// Time-lock deadline for governance changes (NULL for mint/burn).
    pub time_lock_until: Option<DateTime<Utc>>,

    pub status: MultiSigProposalStatus,
    pub failure_reason: Option<String>,

    pub proposed_by: Uuid,
    pub proposed_by_key: String,

    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub submitted_at: Option<DateTime<Utc>>,
    pub confirmed_at: Option<DateTime<Utc>>,
}

/// A single signer's cryptographic signature on a proposal.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct MultiSigSignature {
    pub id: Uuid,
    pub proposal_id: Uuid,
    pub signer_id: Uuid,
    pub signer_key: String,
    pub signer_role: String,
    /// Base64-encoded XDR DecoratedSignature from the signer's hardware wallet.
    pub signature_xdr: String,
    pub signed_at: DateTime<Utc>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

/// Active M-of-N quorum configuration for a given operation type.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct QuorumConfig {
    pub id: Uuid,
    pub op_type: MultiSigOpType,
    pub required_signatures: i16,
    pub total_signers: i16,
    /// Time-lock duration in seconds (0 = no time-lock).
    pub time_lock_seconds: i32,
    pub updated_by: Uuid,
    pub updated_at: DateTime<Utc>,
}

/// An immutable governance audit log entry.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct GovernanceLogEntry {
    pub id: Uuid,
    pub proposal_id: Option<Uuid>,
    pub event_type: String,
    pub actor_key: Option<String>,
    pub actor_id: Option<Uuid>,
    pub payload: serde_json::Value,
    pub previous_hash: Option<String>,
    pub current_hash: String,
    pub created_at: DateTime<Utc>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Request / Response DTOs
// ─────────────────────────────────────────────────────────────────────────────

/// Request body for proposing a new treasury operation.
#[derive(Debug, Deserialize)]
pub struct ProposeRequest {
    pub op_type: MultiSigOpType,
    pub description: String,
    /// Optional: caller-supplied unsigned XDR. If omitted, the service builds
    /// it from `op_params`.
    pub unsigned_xdr: Option<String>,
    /// Operation-specific parameters used to build the XDR when `unsigned_xdr`
    /// is not provided.
    pub op_params: Option<serde_json::Value>,
}

/// Request body for a signer to submit their signature.
#[derive(Debug, Deserialize)]
pub struct SignRequest {
    /// Base64-encoded XDR DecoratedSignature produced by the signer's hardware wallet.
    pub signature_xdr: String,
    /// The signer's Stellar public key (G…).
    pub signer_key: String,
}

/// Request body for explicitly rejecting a proposal.
#[derive(Debug, Deserialize)]
pub struct RejectRequest {
    pub reason: String,
}

/// Proposal detail response including collected signatures.
#[derive(Debug, Serialize)]
pub struct ProposalDetail {
    pub proposal: MultiSigProposal,
    pub signatures: Vec<MultiSigSignature>,
    pub signatures_collected: usize,
    pub signatures_required: usize,
    pub time_lock_remaining_secs: Option<i64>,
}

/// Paginated list of proposals.
#[derive(Debug, Serialize)]
pub struct ProposalListResponse {
    pub proposals: Vec<MultiSigProposal>,
    pub total: i64,
    pub page: i64,
    pub page_size: i64,
}

/// Query parameters for listing proposals.
#[derive(Debug, Deserialize)]
pub struct ListProposalsQuery {
    pub status: Option<MultiSigProposalStatus>,
    pub op_type: Option<MultiSigOpType>,
    pub page: Option<i64>,
    pub page_size: Option<i64>,
}

impl ListProposalsQuery {
    pub fn page(&self) -> i64 {
        self.page.unwrap_or(1).max(1)
    }
    pub fn page_size(&self) -> i64 {
        self.page_size.unwrap_or(20).clamp(1, 100)
    }
    pub fn offset(&self) -> i64 {
        (self.page() - 1) * self.page_size()
    }
}
