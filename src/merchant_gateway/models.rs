//! Domain models for Merchant Gateway

use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

// ============================================================================
// MERCHANT
// ============================================================================

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct Merchant {
    pub id: Uuid,
    pub business_name: String,
    pub business_email: String,
    pub business_phone: Option<String>,
    pub stellar_address: String,
    pub webhook_url: Option<String>,
    pub webhook_secret: String,
    pub is_active: bool,
    pub kyb_status: String,
    pub monthly_volume_limit: Option<Decimal>,
    pub gas_fee_sponsor: bool,
    pub metadata: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct CreateMerchantRequest {
    pub business_name: String,
    pub business_email: String,
    pub business_phone: Option<String>,
    pub stellar_address: String,
    pub webhook_url: Option<String>,
    pub monthly_volume_limit: Option<Decimal>,
    pub gas_fee_sponsor: Option<bool>,
}

// ============================================================================
// PAYMENT INTENT (Unified Checkout Object)
// ============================================================================

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct MerchantPaymentIntent {
    pub id: Uuid,
    pub merchant_id: Uuid,
    pub merchant_reference: String,
    pub amount_cngn: Decimal,
    pub currency: String,
    
    // Customer details
    pub customer_email: Option<String>,
    pub customer_phone: Option<String>,
    pub customer_address: Option<String>,
    
    // Blockchain details
    pub destination_address: String,
    pub memo: String,
    pub stellar_tx_hash: Option<String>,
    pub actual_amount_received: Option<Decimal>,
    
    // Status
    pub status: PaymentIntentStatus,
    
    // Timing
    pub expires_at: DateTime<Utc>,
    pub paid_at: Option<DateTime<Utc>>,
    pub confirmed_at: Option<DateTime<Utc>>,
    
    // Metadata
    pub metadata: serde_json::Value,
    pub callback_url: Option<String>,
    
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, sqlx::Type)]
#[sqlx(type_name = "text")]
#[serde(rename_all = "lowercase")]
pub enum PaymentIntentStatus {
    #[sqlx(rename = "pending")]
    Pending,
    #[sqlx(rename = "paid")]
    Paid,
    #[sqlx(rename = "expired")]
    Expired,
    #[sqlx(rename = "cancelled")]
    Cancelled,
    #[sqlx(rename = "refunded")]
    Refunded,
}

impl std::fmt::Display for PaymentIntentStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PaymentIntentStatus::Pending => write!(f, "pending"),
            PaymentIntentStatus::Paid => write!(f, "paid"),
            PaymentIntentStatus::Expired => write!(f, "expired"),
            PaymentIntentStatus::Cancelled => write!(f, "cancelled"),
            PaymentIntentStatus::Refunded => write!(f, "refunded"),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct CreatePaymentIntentRequest {
    pub merchant_reference: String,
    pub amount_cngn: Decimal,
    pub customer_email: Option<String>,
    pub customer_phone: Option<String>,
    pub expiry_minutes: Option<i64>, // Default: 15 minutes
    pub callback_url: Option<String>,
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
pub struct PaymentIntentResponse {
    pub payment_intent_id: Uuid,
    pub merchant_reference: String,
    pub amount_cngn: Decimal,
    pub destination_address: String,
    pub memo: String,
    pub status: PaymentIntentStatus,
    pub expires_at: DateTime<Utc>,
    pub payment_url: String, // Deep link for mobile wallets
    pub qr_code_data: Option<String>, // Base64 encoded QR code
    pub created_at: DateTime<Utc>,
}

// ============================================================================
// WEBHOOK DELIVERY
// ============================================================================

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct WebhookDelivery {
    pub id: Uuid,
    pub payment_intent_id: Uuid,
    pub merchant_id: Uuid,
    pub webhook_url: String,
    pub event_type: String,
    pub payload: serde_json::Value,
    pub signature: String,
    pub status: WebhookStatus,
    pub http_status_code: Option<i32>,
    pub response_body: Option<String>,
    pub error_message: Option<String>,
    pub retry_count: i32,
    pub next_retry_at: Option<DateTime<Utc>>,
    pub last_attempt_at: Option<DateTime<Utc>>,
    pub delivered_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, sqlx::Type)]
#[sqlx(type_name = "text")]
#[serde(rename_all = "lowercase")]
pub enum WebhookStatus {
    #[sqlx(rename = "pending")]
    Pending,
    #[sqlx(rename = "delivered")]
    Delivered,
    #[sqlx(rename = "failed")]
    Failed,
    #[sqlx(rename = "abandoned")]
    Abandoned,
}

impl std::fmt::Display for WebhookStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WebhookStatus::Pending => write!(f, "pending"),
            WebhookStatus::Delivered => write!(f, "delivered"),
            WebhookStatus::Failed => write!(f, "failed"),
            WebhookStatus::Abandoned => write!(f, "abandoned"),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct WebhookPayload {
    pub event_type: String,
    pub payment_intent_id: Uuid,
    pub merchant_reference: String,
    pub amount_cngn: Decimal,
    pub status: PaymentIntentStatus,
    pub stellar_tx_hash: Option<String>,
    pub paid_at: Option<DateTime<Utc>>,
    pub confirmed_at: Option<DateTime<Utc>>,
    pub metadata: serde_json::Value,
    pub timestamp: DateTime<Utc>,
}

// ============================================================================
// REFUND
// ============================================================================

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct MerchantRefund {
    pub id: Uuid,
    pub payment_intent_id: Uuid,
    pub merchant_id: Uuid,
    pub amount_cngn: Decimal,
    pub reason: Option<String>,
    pub refund_reference: String,
    pub stellar_tx_hash: Option<String>,
    pub status: RefundStatus,
    pub initiated_by: String,
    pub completed_at: Option<DateTime<Utc>>,
    pub metadata: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, sqlx::Type)]
#[sqlx(type_name = "text")]
#[serde(rename_all = "lowercase")]
pub enum RefundStatus {
    #[sqlx(rename = "pending")]
    Pending,
    #[sqlx(rename = "processing")]
    Processing,
    #[sqlx(rename = "completed")]
    Completed,
    #[sqlx(rename = "failed")]
    Failed,
}

impl std::fmt::Display for RefundStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RefundStatus::Pending => write!(f, "pending"),
            RefundStatus::Processing => write!(f, "processing"),
            RefundStatus::Completed => write!(f, "completed"),
            RefundStatus::Failed => write!(f, "failed"),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct CreateRefundRequest {
    pub payment_intent_id: Uuid,
    pub amount_cngn: Option<Decimal>, // Partial refund support
    pub reason: Option<String>,
}

// ============================================================================
// API KEY SCOPE
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MerchantApiKeyScope {
    Full,
    ReadOnly,
    WriteOnly,
    RefundOnly,
}

impl MerchantApiKeyScope {
    pub fn as_str(&self) -> &'static str {
        match self {
            MerchantApiKeyScope::Full => "full",
            MerchantApiKeyScope::ReadOnly => "read_only",
            MerchantApiKeyScope::WriteOnly => "write_only",
            MerchantApiKeyScope::RefundOnly => "refund_only",
        }
    }
    
    pub fn can_create_payment(&self) -> bool {
        matches!(self, MerchantApiKeyScope::Full | MerchantApiKeyScope::WriteOnly)
    }
    
    pub fn can_read_payment(&self) -> bool {
        matches!(self, MerchantApiKeyScope::Full | MerchantApiKeyScope::ReadOnly)
    }
    
    pub fn can_refund(&self) -> bool {
        matches!(self, MerchantApiKeyScope::Full | MerchantApiKeyScope::RefundOnly)
    }
}

// ============================================================================
// ANALYTICS
// ============================================================================

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct MerchantAnalyticsDaily {
    pub id: i64,
    pub merchant_id: Uuid,
    pub date: chrono::NaiveDate,
    pub total_payments: i32,
    pub successful_payments: i32,
    pub failed_payments: i32,
    pub expired_payments: i32,
    pub total_volume_cngn: Decimal,
    pub total_refunds_cngn: Decimal,
    pub net_volume_cngn: Decimal,
    pub avg_confirmation_time_secs: Option<i32>,
    pub webhook_success_rate: Option<Decimal>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
