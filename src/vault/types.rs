use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("custodian API error: {0}")]
    CustodianApi(String),
    #[error("outbound transfer blocked: requires {required} of {total} signatures, have {provided}")]
    InsufficientSignatures {
        required: usize,
        total: usize,
        provided: usize,
    },
    #[error("outbound transfers are disabled on this account type")]
    OutboundBlocked,
    #[error("signature already recorded for signer {0}")]
    DuplicateSignature(String),
    #[error("transfer request not found: {0}")]
    TransferNotFound(Uuid),
    #[error("database error: {0}")]
    Database(String),
    #[error("serialization error: {0}")]
    Serialization(String),
}

pub type VaultResult<T> = Result<T, VaultError>;

// ---------------------------------------------------------------------------
// Account segregation
// ---------------------------------------------------------------------------

/// Logical account types within the reserve vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "vault_account_type", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum AccountType {
    /// Holds NGN collateral backing cNGN 1:1. Outbound transfers require M-of-N approval.
    MintingReserve,
    /// Day-to-day operational expenses. Separate from reserve.
    OperationalExpense,
}

// ---------------------------------------------------------------------------
// Balance
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReserveBalance {
    pub account_id: String,
    pub account_type: AccountType,
    /// Funds available for immediate use (cleared).
    pub available_balance: Decimal,
    /// Total balance including uncleared/pending credits.
    pub ledger_balance: Decimal,
    pub currency: String,
    pub fetched_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Transactions
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultTransaction {
    pub id: String,
    pub account_id: String,
    pub direction: TransactionDirection,
    pub amount: Decimal,
    pub currency: String,
    pub narration: Option<String>,
    pub reference: String,
    pub status: TransactionStatus,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransactionDirection {
    Inbound,
    Outbound,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransactionStatus {
    Pending,
    Settled,
    Failed,
    Reversed,
}

// ---------------------------------------------------------------------------
// Multi-sig outbound transfer request
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundTransferRequest {
    pub id: Uuid,
    pub account_id: String,
    pub amount: Decimal,
    pub currency: String,
    pub destination_account: String,
    pub destination_bank_code: String,
    pub narration: String,
    pub signatures: Vec<ApprovalSignature>,
    pub status: TransferRequestStatus,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalSignature {
    pub signer_id: String,
    pub role: String,
    pub signed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferRequestStatus {
    /// Awaiting more signatures.
    PendingApproval,
    /// M-of-N threshold met; ready to execute.
    Approved,
    /// Executed on the banking API.
    Executed,
    /// Rejected by a signer or expired.
    Rejected,
}

// ---------------------------------------------------------------------------
// Inbound deposit webhook payload
// ---------------------------------------------------------------------------

/// Normalised inbound-deposit event emitted by the custodian webhook.
/// Triggers the Mint Request Lifecycle (Issue #123).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboundDepositEvent {
    pub event_id: String,
    pub account_id: String,
    pub amount: Decimal,
    pub currency: String,
    pub sender_name: Option<String>,
    pub sender_account: Option<String>,
    pub reference: String,
    pub received_at: DateTime<Utc>,
}
