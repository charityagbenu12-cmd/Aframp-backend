use serde::{Deserialize, Serialize};

/// Request to create an onramp quote
#[derive(Debug, Deserialize)]
pub struct OnrampQuoteRequest {
    pub wallet_address: String,
    pub from_currency: String,
    pub to_currency: String,
    pub amount: String,
    #[serde(default)]
    pub payment_method: Option<String>,
}

/// Provider fee details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderFeeDetail {
    pub amount: String,
    pub percentage: f64,
    pub provider: String,
}

/// Platform fee details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformFeeDetail {
    pub amount: String,
    pub percentage: f64,
}

/// Payment method fee details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentMethodFeeDetail {
    pub amount: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
}

/// Complete fee breakdown
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeBreakdown {
    pub provider_fee: ProviderFeeDetail,
    pub platform_fee: PlatformFeeDetail,
    pub payment_method_fee: PaymentMethodFeeDetail,
    pub total_fees: String,
}

/// Breakdown details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Breakdown {
    pub you_pay: String,
    pub you_receive: String,
    pub effective_rate: f64,
}

/// Trustline status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustlineStatus {
    pub exists: bool,
    pub ready_to_receive: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action_required: Option<String>,
}

/// Trustline requirements
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustlineRequirements {
    pub asset_code: String,
    pub asset_issuer: String,
    pub min_xlm_required: String,
    pub current_xlm_balance: String,
    pub xlm_needed: String,
    pub instructions: String,
    pub help_url: String,
}

/// Validity information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Validity {
    pub expires_at: String,
    pub expires_in_seconds: i64,
}

/// Next steps guidance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NextSteps {
    pub endpoint: String,
    pub method: String,
    pub action: String,
}

/// Response containing the quote details (with trustline)
#[derive(Debug, Serialize)]
pub struct OnrampQuoteResponse {
    pub quote_id: String,
    pub wallet_address: String,
    pub from_currency: String,
    pub to_currency: String,
    pub from_amount: String,
    pub exchange_rate: f64,
    pub gross_amount: String,
    pub fees: FeeBreakdown,
    pub net_amount: String,
    pub breakdown: Breakdown,
    pub trustline_status: TrustlineStatus,
    pub validity: Validity,
    pub next_steps: NextSteps,
    pub created_at: String,
}

/// Response when trustline is missing
#[derive(Debug, Serialize)]
pub struct OnrampQuoteResponseNoTrustline {
    pub quote_id: String,
    pub wallet_address: String,
    pub from_currency: String,
    pub to_currency: String,
    pub from_amount: String,
    pub net_amount: String,
    pub trustline_status: TrustlineStatus,
    pub trustline_requirements: TrustlineRequirements,
    pub next_steps: serde_json::Value,
    pub validity: Validity,
    pub created_at: String,
}

/// Stored quote in Redis
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct StoredQuote {
    pub quote_id: String,
    pub wallet_address: String,
    pub from_currency: String,
    pub to_currency: String,
    pub from_amount: String,
    pub exchange_rate: String,
    pub gross_amount: String,
    pub net_amount: String,
    pub fees: FeeBreakdown,
    pub trustline_exists: bool,
    pub payment_method: Option<String>,
    pub created_at: String,
    pub expires_at: String,
    pub status: String,
}
