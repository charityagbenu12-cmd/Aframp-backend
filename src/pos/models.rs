use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Payment intent status lifecycle
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, sqlx::Type)]
#[sqlx(type_name = "pos_payment_status", rename_all = "lowercase")]
pub enum PosPaymentStatus {
    /// QR code generated, awaiting customer scan
    Pending,
    /// Customer scanned QR, transaction submitted to Stellar
    Submitted,
    /// Payment confirmed on Stellar ledger
    Confirmed,
    /// Payment amount mismatch detected
    Discrepancy,
    /// Payment failed or expired
    Failed,
    /// Payment refunded
    Refunded,
}

/// POS payment intent — represents a single retail transaction
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct PosPaymentIntent {
    pub id: Uuid,
    pub merchant_id: Uuid,
    pub order_id: String,
    pub amount_cngn: rust_decimal::Decimal,
    pub destination_address: String,
    pub memo: String,
    pub qr_code_data: String,
    pub status: PosPaymentStatus,
    pub stellar_tx_hash: Option<String>,
    pub actual_amount_received: Option<rust_decimal::Decimal>,
    pub customer_address: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub confirmed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Merchant configuration for POS payments
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct PosMerchant {
    pub id: Uuid,
    pub business_name: String,
    pub stellar_address: String,
    pub webhook_url: Option<String>,
    pub static_qr_enabled: bool,
    pub auto_refund_discrepancy: bool,
    pub payment_timeout_secs: i32,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Real-time payment notification via WebSocket
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentNotification {
    pub payment_id: Uuid,
    pub order_id: String,
    pub status: PosPaymentStatus,
    pub amount_expected: rust_decimal::Decimal,
    pub amount_received: Option<rust_decimal::Decimal>,
    pub stellar_tx_hash: Option<String>,
    pub timestamp: DateTime<Utc>,
}

/// Payment discrepancy details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentDiscrepancy {
    pub payment_id: Uuid,
    pub expected_amount: rust_decimal::Decimal,
    pub received_amount: rust_decimal::Decimal,
    pub difference: rust_decimal::Decimal,
    pub discrepancy_type: DiscrepancyType,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DiscrepancyType {
    Overpayment,
    Underpayment,
}

/// Static QR code configuration for small vendors
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct StaticQrConfig {
    pub id: Uuid,
    pub merchant_id: Uuid,
    pub qr_code_data: String,
    pub variable_amount_url: String,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
}

/// Proof of payment record for offline validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofOfPaymentRecord {
    pub payment_id: Uuid,
    pub order_id: String,
    pub stellar_tx_hash: String,
    pub amount_cngn: rust_decimal::Decimal,
    pub merchant_name: String,
    pub timestamp: DateTime<Utc>,
    pub verification_code: String,
}
