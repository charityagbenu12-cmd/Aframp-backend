//! Domain models for the Nigeria → Kenya corridor.

use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Transfer request / response
// ---------------------------------------------------------------------------

/// Initiate a cNGN → KES cross-border transfer.
#[derive(Debug, Clone, Deserialize)]
pub struct KenyaTransferRequest {
    /// Sender's Stellar wallet address (holds cNGN).
    pub sender_wallet: String,
    /// Amount of cNGN to send (will be converted to KES).
    pub cngn_amount: Decimal,
    /// Recipient's Kenyan M-Pesa phone number (or KES bank account).
    pub recipient_phone: Option<String>,
    /// Recipient's KES bank account (alternative to M-Pesa).
    pub recipient_bank: Option<KenyaBankDetails>,
    /// Recipient's full name (for CBK reporting).
    pub recipient_name: String,
    /// Recipient's Kenyan National ID (CBK requirement for inbound remittances).
    pub recipient_national_id: Option<String>,
    /// Idempotency key to prevent duplicate transfers.
    pub idempotency_key: String,
    /// Optional sender note / purpose of transfer.
    pub purpose: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct KenyaBankDetails {
    pub bank_code: String,
    pub account_number: String,
    pub account_name: String,
}

/// Quote for a cNGN → KES transfer (before committing).
#[derive(Debug, Clone, Serialize)]
pub struct KenyaTransferQuote {
    pub quote_id: Uuid,
    pub cngn_amount: Decimal,
    pub ngn_equivalent: Decimal,
    pub ngn_kes_rate: Decimal,
    pub kes_gross: Decimal,
    pub corridor_fee_kes: Decimal,
    pub kes_net: Decimal,
    pub fee_breakdown: CorridorFeeBreakdown,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CorridorFeeBreakdown {
    /// Platform corridor fee (basis points on KES gross).
    pub platform_fee_bps: u32,
    pub platform_fee_kes: Decimal,
    /// M-Pesa B2C disbursement fee (charged by Safaricom).
    pub provider_fee_kes: Decimal,
    /// CBK levy (if applicable).
    pub regulatory_levy_kes: Decimal,
    pub total_fee_kes: Decimal,
}

/// Result of initiating a Kenya transfer.
#[derive(Debug, Clone, Serialize)]
pub struct KenyaTransferResponse {
    pub transfer_id: Uuid,
    pub status: KenyaTransferStatus,
    pub quote: KenyaTransferQuote,
    pub recipient_validated: bool,
    pub compliance_tag_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub message: String,
}

// ---------------------------------------------------------------------------
// Transfer status state machine
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "text", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum KenyaTransferStatus {
    /// Waiting for cNGN to arrive on system wallet.
    PendingCngn,
    /// cNGN received; FX conversion in progress.
    Converting,
    /// KES disbursement queued with M-Pesa.
    DisbursementPending,
    /// M-Pesa confirmed receipt.
    Completed,
    /// Disbursement failed; cNGN refund initiated.
    RefundInitiated,
    /// cNGN refunded to sender.
    Refunded,
    /// Terminal failure.
    Failed,
}

impl KenyaTransferStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            KenyaTransferStatus::PendingCngn => "pending_cngn",
            KenyaTransferStatus::Converting => "converting",
            KenyaTransferStatus::DisbursementPending => "disbursement_pending",
            KenyaTransferStatus::Completed => "completed",
            KenyaTransferStatus::RefundInitiated => "refund_initiated",
            KenyaTransferStatus::Refunded => "refunded",
            KenyaTransferStatus::Failed => "failed",
        }
    }

    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            KenyaTransferStatus::Completed
                | KenyaTransferStatus::Refunded
                | KenyaTransferStatus::Failed
        )
    }
}

// ---------------------------------------------------------------------------
// CBK compliance metadata
// ---------------------------------------------------------------------------

/// Central Bank of Kenya reporting metadata attached to every inbound
/// international remittance (per CBK Prudential Guideline CBK/PG/15).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CbkRemittanceMetadata {
    /// Sender country (always "NG" for this corridor).
    pub sender_country: String,
    /// Destination country (always "KE").
    pub destination_country: String,
    /// KES amount received by recipient.
    pub kes_amount: Decimal,
    /// NGN/KES exchange rate used.
    pub exchange_rate: Decimal,
    /// Recipient's National ID (required for amounts > KES 150,000).
    pub recipient_national_id: Option<String>,
    /// Purpose of remittance.
    pub purpose: Option<String>,
    /// CBK reporting reference (generated by Aframp).
    pub cbk_reference: String,
}

// ---------------------------------------------------------------------------
// M-Pesa daily limit constants (CBK / Safaricom)
// ---------------------------------------------------------------------------

/// Maximum single M-Pesa B2C transaction (KES).
pub fn mpesa_max_single_txn_kes() -> Decimal {
    Decimal::new(150_000, 0)
}

/// Maximum daily M-Pesa B2C volume per recipient (KES).
pub fn mpesa_max_daily_kes() -> Decimal {
    Decimal::new(300_000, 0)
}

/// CBK threshold above which National ID is mandatory (KES).
pub fn cbk_id_required_threshold_kes() -> Decimal {
    Decimal::new(150_000, 0)
}
