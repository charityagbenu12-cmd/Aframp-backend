use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedemptionRequest {
    pub id: Uuid,
    pub redemption_id: String,
    pub user_id: Uuid,
    pub wallet_address: String,
    
    // Request details
    pub amount_cngn: f64,
    pub amount_ngn: f64,
    pub exchange_rate: f64,
    
    // Destination bank details
    pub bank_code: String,
    pub bank_name: String,
    pub account_number: String,
    pub account_name: String,
    pub account_name_verified: bool,
    
    // Status tracking
    pub status: String,
    pub previous_status: Option<String>,
    
    // Transaction references
    pub burn_transaction_hash: Option<String>,
    pub batch_id: Option<Uuid>,
    
    // Metadata and audit
    pub kyc_tier: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub metadata: serde_json::Value,
    
    // Timestamps
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedemptionBatch {
    pub id: Uuid,
    pub batch_id: String,
    
    // Batch details
    pub total_requests: i32,
    pub total_amount_cngn: f64,
    pub total_amount_ngn: f64,
    
    // Processing details
    pub batch_type: String,
    pub trigger_reason: Option<String>,
    
    // Status
    pub status: String,
    
    // Transaction references
    pub stellar_transaction_hash: Option<String>,
    pub stellar_ledger: Option<i32>,
    
    // Metadata
    pub metadata: serde_json::Value,
    
    // Timestamps
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub processed_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BurnTransaction {
    pub id: Uuid,
    pub redemption_id: String,
    
    // Transaction details
    pub transaction_hash: Option<String>,
    pub stellar_ledger: Option<i32>,
    pub sequence_number: Option<i64>,
    
    // Burn operation details
    pub burn_type: String,
    pub source_address: String,
    pub destination_address: String,
    pub amount_cngn: f64,
    
    // Transaction status
    pub status: String,
    
    // Fees and timing
    pub fee_paid_stroops: Option<i32>,
    pub fee_xlm: Option<f64>,
    pub timeout_seconds: i32,
    
    // Error handling
    pub error_code: Option<String>,
    pub error_message: Option<String>,
    pub retry_count: i32,
    pub max_retries: i32,
    
    // Transaction XDR
    pub unsigned_envelope_xdr: Option<String>,
    pub signed_envelope_xdr: Option<String>,
    
    // Metadata
    pub memo_text: Option<String>,
    pub memo_hash: Option<String>,
    pub metadata: serde_json::Value,
    
    // Timestamps
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub submitted_at: Option<DateTime<Utc>>,
    pub confirmed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FiatDisbursement {
    pub id: Uuid,
    pub redemption_id: Uuid,
    pub batch_id: Option<Uuid>,
    
    // Disbursement details
    pub amount_ngn: f64,
    pub bank_code: String,
    pub bank_name: String,
    pub account_number: String,
    pub account_name: String,
    
    // Provider details
    pub provider: String,
    pub provider_reference: Option<String>,
    pub provider_status: Option<String>,
    
    // Status tracking
    pub status: String,
    
    // NIBSS specifics
    pub nibss_transaction_id: Option<String>,
    pub nibss_status: Option<String>,
    pub beneficiary_account_credits: bool,
    
    // Fees and timing
    pub provider_fee: f64,
    pub processing_time_seconds: Option<i32>,
    
    // Error handling
    pub error_code: Option<String>,
    pub error_message: Option<String>,
    pub retry_count: i32,
    pub max_retries: i32,
    
    // Receipt and documentation
    pub receipt_url: Option<String>,
    pub receipt_pdf_base64: Option<String>,
    
    // Metadata
    pub idempotency_key: Option<String>,
    pub narration: String,
    pub metadata: serde_json::Value,
    
    // Timestamps
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub processed_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub last_status_check: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettlementAccount {
    pub id: Uuid,
    pub account_name: String,
    pub account_number: String,
    pub bank_code: String,
    pub bank_name: String,
    
    // Account type
    pub account_type: String,
    pub currency: String,
    
    // Balance tracking
    pub current_balance: f64,
    pub available_balance: f64,
    pub pending_debits: f64,
    
    // Health metrics
    pub minimum_balance: f64,
    pub is_healthy: bool,
    pub last_balance_check: Option<DateTime<Utc>>,
    
    // Metadata
    pub metadata: serde_json::Value,
    
    // Timestamps
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedemptionAuditLog {
    pub id: Uuid,
    pub redemption_id: Option<Uuid>,
    pub batch_id: Option<Uuid>,
    pub burn_transaction_id: Option<Uuid>,
    pub disbursement_id: Option<Uuid>,
    
    // Event details
    pub event_type: String,
    pub previous_status: Option<String>,
    pub new_status: Option<String>,
    
    // Event data
    pub event_data: serde_json::Value,
    
    // Context
    pub user_id: Option<Uuid>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    
    // System context
    pub worker_id: Option<String>,
    pub service_name: Option<String>,
    
    // Timestamps
    pub created_at: DateTime<Utc>,
}

// Request/Response DTOs for API layer

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateRedemptionRequest {
    pub amount_cngn: f64,
    pub bank_code: String,
    pub bank_name: String,
    pub account_number: String,
    pub account_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedemptionRequestResponse {
    pub redemption_id: String,
    pub status: String,
    pub amount_cngn: f64,
    pub amount_ngn: f64,
    pub exchange_rate: f64,
    pub bank_details: BankDetails,
    pub created_at: DateTime<Utc>,
    pub estimated_completion_time: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BankDetails {
    pub bank_code: String,
    pub bank_name: String,
    pub account_number: String,
    pub account_name: String,
    pub account_name_verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedemptionStatusResponse {
    pub redemption_id: String,
    pub status: String,
    pub previous_status: Option<String>,
    pub burn_transaction_hash: Option<String>,
    pub disbursement_status: Option<String>,
    pub provider_reference: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchRedemptionRequest {
    pub redemption_ids: Vec<String>,
    pub batch_type: String, // "TIME_BASED" | "COUNT_BASED" | "MANUAL"
    pub trigger_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchRedemptionResponse {
    pub batch_id: String,
    pub total_requests: usize,
    pub total_amount_cngn: f64,
    pub total_amount_ngn: f64,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub estimated_completion_time: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisbursementReceipt {
    pub redemption_id: String,
    pub provider_reference: String,
    pub amount_ngn: f64,
    pub bank_details: BankDetails,
    pub status: String,
    pub completed_at: DateTime<Utc>,
    pub receipt_url: Option<String>,
    pub pdf_base64: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettlementHealthResponse {
    pub accounts: Vec<SettlementAccountHealth>,
    pub overall_health: bool,
    pub total_available_balance: f64,
    pub total_pending_debits: f64,
    pub last_updated: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettlementAccountHealth {
    pub account_name: String,
    pub account_type: String,
    pub current_balance: f64,
    pub available_balance: f64,
    pub pending_debits: f64,
    pub is_healthy: bool,
    pub last_balance_check: Option<DateTime<Utc>>,
}

// Validation and error types

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RedemptionError {
    InvalidAmount,
    InsufficientBalance,
    InvalidBankDetails,
    AccountNameMismatch,
    KycNotVerified,
    DuplicateRequest,
    TransactionFailed(String),
    DisbursementFailed(String),
    ComplianceViolation(String),
    RateLimitExceeded,
    SystemError(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationError {
    pub field: String,
    pub message: String,
    pub code: String,
}

// Configuration types

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedemptionConfig {
    pub min_redemption_amount: f64,
    pub max_redemption_amount: f64,
    pub required_kyc_tier: String,
    pub enable_partial_burns: bool,
    pub enable_batch_processing: bool,
    pub batch_size_threshold: usize,
    pub batch_time_window_minutes: u64,
    pub auto_disbursement_enabled: bool,
    pub supported_providers: Vec<String>,
    pub compliance_checks: ComplianceConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceConfig {
    pub enable_kyc_check: bool,
    pub enable_bank_validation: bool,
    pub enable_sanctions_check: bool,
    pub max_daily_redemption_amount: f64,
    pub max_weekly_redemption_amount: f64,
    pub restricted_countries: Vec<String>,
}

impl Default for RedemptionConfig {
    fn default() -> Self {
        Self {
            min_redemption_amount: 1.0,
            max_redemption_amount: 1_000_000.0,
            required_kyc_tier: "TIER_2".to_string(),
            enable_partial_burns: true,
            enable_batch_processing: true,
            batch_size_threshold: 10,
            batch_time_window_minutes: 5,
            auto_disbursement_enabled: true,
            supported_providers: vec!["flutterwave".to_string(), "paystack".to_string()],
            compliance_checks: ComplianceConfig {
                enable_kyc_check: true,
                enable_bank_validation: true,
                enable_sanctions_check: false,
                max_daily_redemption_amount: 10_000_000.0,
                max_weekly_redemption_amount: 50_000_000.0,
                restricted_countries: vec![],
            },
        }
    }
}
