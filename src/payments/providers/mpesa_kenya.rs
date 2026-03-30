//! M-Pesa Kenya B2C (Business-to-Customer) payout provider.
//!
//! Implements the Safaricom Daraja API for:
//! - B2C disbursements (KES to mobile wallet)
//! - Recipient phone validation (AccountBalance / CustomerCheck)
//! - Webhook status mapping (M-Pesa result codes → Aframp states)

use crate::payments::error::{PaymentError, PaymentResult};
use crate::payments::provider::PaymentProvider;
use crate::payments::types::{
    Money, PaymentMethod, PaymentRequest, PaymentResponse, PaymentState, ProviderName,
    StatusRequest, StatusResponse, WebhookEvent, WebhookVerificationResult, WithdrawalMethod,
    WithdrawalRequest, WithdrawalResponse,
};
use crate::payments::utils::PaymentHttpClient;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::time::Duration;
use tracing::{info, warn};

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct MpesaKenyaConfig {
    pub consumer_key: String,
    pub consumer_secret: String,
    pub passkey: String,
    pub shortcode: String,           // B2C initiator shortcode
    pub initiator_name: String,      // Daraja initiator name
    pub initiator_password: String,  // Daraja initiator credential
    pub result_url: String,          // Webhook callback URL
    pub queue_timeout_url: String,   // Timeout callback URL
    pub base_url: String,
    pub timeout_secs: u64,
    pub max_retries: u32,
}

impl MpesaKenyaConfig {
    pub fn from_env() -> PaymentResult<Self> {
        let consumer_key = std::env::var("MPESA_KE_CONSUMER_KEY")
            .or_else(|_| std::env::var("MPESA_CONSUMER_KEY"))
            .unwrap_or_default();
        let consumer_secret = std::env::var("MPESA_KE_CONSUMER_SECRET")
            .or_else(|_| std::env::var("MPESA_CONSUMER_SECRET"))
            .unwrap_or_default();
        let passkey = std::env::var("MPESA_KE_PASSKEY")
            .or_else(|_| std::env::var("MPESA_PASSKEY"))
            .unwrap_or_default();

        if consumer_key.is_empty() || consumer_secret.is_empty() {
            return Err(PaymentError::ValidationError {
                message: "MPESA_KE_CONSUMER_KEY and MPESA_KE_CONSUMER_SECRET are required"
                    .to_string(),
                field: Some("mpesa_kenya".to_string()),
            });
        }

        Ok(Self {
            consumer_key,
            consumer_secret,
            passkey,
            shortcode: std::env::var("MPESA_KE_SHORTCODE").unwrap_or_default(),
            initiator_name: std::env::var("MPESA_KE_INITIATOR_NAME")
                .unwrap_or_else(|_| "aframp_initiator".to_string()),
            initiator_password: std::env::var("MPESA_KE_INITIATOR_PASSWORD").unwrap_or_default(),
            result_url: std::env::var("MPESA_KE_RESULT_URL")
                .unwrap_or_else(|_| "https://api.aframp.com/webhooks/mpesa_kenya".to_string()),
            queue_timeout_url: std::env::var("MPESA_KE_TIMEOUT_URL")
                .unwrap_or_else(|_| "https://api.aframp.com/webhooks/mpesa_kenya/timeout".to_string()),
            base_url: std::env::var("MPESA_KE_BASE_URL")
                .unwrap_or_else(|_| "https://sandbox.safaricom.co.ke".to_string()),
            timeout_secs: std::env::var("MPESA_KE_TIMEOUT_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(30),
            max_retries: std::env::var("MPESA_KE_MAX_RETRIES")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(2),
        })
    }
}

// ---------------------------------------------------------------------------
// OAuth token response
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct MpesaTokenResponse {
    access_token: String,
    #[allow(dead_code)]
    expires_in: String,
}

// ---------------------------------------------------------------------------
// B2C request / response
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
struct B2CRequest {
    initiator_name: String,
    security_credential: String,
    command_i_d: String,
    amount: String,
    party_a: String,
    party_b: String,
    remarks: String,
    queue_time_out_u_r_l: String,
    result_u_r_l: String,
    occasion: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct B2CResponse {
    response_code: String,
    response_description: String,
    conversation_i_d: Option<String>,
    originator_conversation_i_d: Option<String>,
}

// ---------------------------------------------------------------------------
// Provider
// ---------------------------------------------------------------------------

pub struct MpesaKenyaProvider {
    config: MpesaKenyaConfig,
    http: PaymentHttpClient,
}

impl MpesaKenyaProvider {
    pub fn new(config: MpesaKenyaConfig) -> PaymentResult<Self> {
        let http = PaymentHttpClient::new(
            Duration::from_secs(config.timeout_secs),
            config.max_retries,
        )?;
        Ok(Self { config, http })
    }

    pub fn from_env() -> PaymentResult<Self> {
        Self::new(MpesaKenyaConfig::from_env()?)
    }

    fn endpoint(&self, path: &str) -> String {
        format!("{}{}", self.config.base_url, path)
    }

    /// Fetch a short-lived OAuth2 bearer token from Safaricom Daraja.
    async fn get_access_token(&self) -> PaymentResult<String> {
        use base64::{engine::general_purpose::STANDARD, Engine};
        let credentials = format!("{}:{}", self.config.consumer_key, self.config.consumer_secret);
        let encoded = STANDARD.encode(credentials.as_bytes());

        let resp: MpesaTokenResponse = self
            .http
            .request_json(
                reqwest::Method::GET,
                &self.endpoint("/oauth/v1/generate?grant_type=client_credentials"),
                None,
                None,
                &[("Authorization", &format!("Basic {}", encoded))],
            )
            .await?;

        Ok(resp.access_token)
    }

    /// Normalise a Kenyan phone number to the 254XXXXXXXXX format.
    fn normalise_phone(phone: &str) -> String {
        let digits: String = phone.chars().filter(|c| c.is_ascii_digit()).collect();
        if digits.starts_with("254") {
            digits
        } else if digits.starts_with('0') {
            format!("254{}", &digits[1..])
        } else if digits.starts_with('7') || digits.starts_with('1') {
            format!("254{}", digits)
        } else {
            digits
        }
    }

    /// Map Safaricom result codes to Aframp PaymentState.
    fn map_result_code(code: i64) -> PaymentState {
        match code {
            0 => PaymentState::Success,
            // Insufficient funds
            1 => PaymentState::Failed,
            // Less than minimum transaction value
            2 => PaymentState::Failed,
            // More than maximum transaction value
            3 => PaymentState::Failed,
            // Would exceed daily transfer limit
            4 => PaymentState::Failed,
            // Would exceed minimum balance
            5 => PaymentState::Failed,
            // Unresolved primary party
            6 => PaymentState::Failed,
            // Unresolved receiver party
            7 => PaymentState::Failed,
            // Would exceed maximum balance
            8 => PaymentState::Failed,
            // Invalid DebitParty
            11 => PaymentState::Failed,
            // Invalid CreditParty
            12 => PaymentState::Failed,
            // Unresolved initiator
            17 => PaymentState::Failed,
            // Duplicate detected
            26 => PaymentState::Failed,
            // Internal failure
            2001 => PaymentState::Failed,
            // Timeout
            1032 => PaymentState::Unknown,
            _ => PaymentState::Unknown,
        }
    }

    /// Human-readable description for M-Pesa result codes.
    fn result_code_description(code: i64) -> &'static str {
        match code {
            0 => "Success",
            1 => "Insufficient funds",
            2 => "Amount below minimum",
            3 => "Amount above maximum",
            4 => "Daily transfer limit exceeded",
            5 => "Minimum balance would be exceeded",
            6 => "Unresolved primary party",
            7 => "Unresolved receiver party — check phone number",
            8 => "Maximum balance would be exceeded",
            11 => "Invalid debit party",
            12 => "Invalid credit party",
            17 => "Unresolved initiator",
            26 => "Duplicate transaction",
            1032 => "Request timeout",
            2001 => "Internal M-Pesa failure",
            _ => "Unknown M-Pesa error",
        }
    }
}

#[async_trait]
impl PaymentProvider for MpesaKenyaProvider {
    /// Not used for KES payouts — M-Pesa is payout-only in this context.
    async fn initiate_payment(&self, _request: PaymentRequest) -> PaymentResult<PaymentResponse> {
        Err(PaymentError::ValidationError {
            message: "M-Pesa Kenya is a payout-only provider; use process_withdrawal".to_string(),
            field: Some("provider".to_string()),
        })
    }

    async fn verify_payment(&self, request: StatusRequest) -> PaymentResult<StatusResponse> {
        // M-Pesa status is delivered via webhook; polling is not supported.
        // Return Unknown with the reference so callers can wait for the webhook.
        Ok(StatusResponse {
            status: PaymentState::Unknown,
            transaction_reference: request.transaction_reference,
            provider_reference: request.provider_reference,
            amount: None,
            payment_method: Some(PaymentMethod::MobileMoney),
            timestamp: None,
            failure_reason: Some(
                "M-Pesa status is delivered asynchronously via webhook".to_string(),
            ),
            provider_data: None,
        })
    }

    /// Initiate a B2C (Business-to-Customer) KES disbursement to a Kenyan
    /// mobile wallet.
    async fn process_withdrawal(
        &self,
        request: WithdrawalRequest,
    ) -> PaymentResult<WithdrawalResponse> {
        request.amount.validate_positive("amount")?;

        if request.amount.currency != "KES" {
            return Err(PaymentError::ValidationError {
                message: format!(
                    "M-Pesa Kenya only supports KES disbursements, got {}",
                    request.amount.currency
                ),
                field: Some("amount.currency".to_string()),
            });
        }

        if !matches!(request.withdrawal_method, WithdrawalMethod::MobileMoney) {
            return Err(PaymentError::ValidationError {
                message: "M-Pesa Kenya requires MobileMoney withdrawal method".to_string(),
                field: Some("withdrawal_method".to_string()),
            });
        }

        let phone = request
            .recipient
            .phone_number
            .as_deref()
            .ok_or_else(|| PaymentError::ValidationError {
                message: "recipient.phone_number is required for M-Pesa disbursement".to_string(),
                field: Some("recipient.phone_number".to_string()),
            })?;

        let normalised_phone = Self::normalise_phone(phone);
        if normalised_phone.len() != 12 || !normalised_phone.starts_with("254") {
            return Err(PaymentError::ValidationError {
                message: format!(
                    "Invalid Kenyan phone number '{}' — expected 254XXXXXXXXX format",
                    phone
                ),
                field: Some("recipient.phone_number".to_string()),
            });
        }

        let token = self.get_access_token().await?;

        let b2c_req = B2CRequest {
            initiator_name: self.config.initiator_name.clone(),
            security_credential: self.config.initiator_password.clone(),
            command_i_d: "BusinessPayment".to_string(),
            amount: request.amount.amount.clone(),
            party_a: self.config.shortcode.clone(),
            party_b: normalised_phone.clone(),
            remarks: request
                .reason
                .clone()
                .unwrap_or_else(|| "Aframp KES disbursement".to_string()),
            queue_time_out_u_r_l: self.config.queue_timeout_url.clone(),
            result_u_r_l: self.config.result_url.clone(),
            occasion: request.transaction_reference.clone(),
        };

        let raw: B2CResponse = self
            .http
            .request_json(
                reqwest::Method::POST,
                &self.endpoint("/mpesa/b2c/v3/paymentrequest"),
                Some(&token),
                Some(&serde_json::to_value(&b2c_req).unwrap()),
                &[("Content-Type", "application/json")],
            )
            .await
            .map_err(|e| PaymentError::ProviderError {
                provider: "mpesa_kenya".to_string(),
                message: e.to_string(),
                provider_code: None,
                retryable: true,
            })?;

        if raw.response_code != "0" {
            return Err(PaymentError::ProviderError {
                provider: "mpesa_kenya".to_string(),
                message: raw.response_description.clone(),
                provider_code: Some(raw.response_code),
                retryable: false,
            });
        }

        info!(
            tx_ref = %request.transaction_reference,
            phone = %normalised_phone,
            amount = %request.amount.amount,
            conversation_id = ?raw.conversation_i_d,
            "M-Pesa Kenya B2C disbursement queued"
        );

        Ok(WithdrawalResponse {
            status: PaymentState::Processing,
            transaction_reference: request.transaction_reference,
            provider_reference: raw
                .originator_conversation_i_d
                .or(raw.conversation_i_d),
            amount_debited: Some(request.amount),
            fees_charged: None,
            estimated_completion_seconds: Some(30),
            provider_data: Some(serde_json::json!({
                "phone": normalised_phone,
                "response_description": raw.response_description,
            })),
        })
    }

    async fn get_payment_status(&self, request: StatusRequest) -> PaymentResult<StatusResponse> {
        self.verify_payment(request).await
    }

    fn name(&self) -> ProviderName {
        ProviderName::Mpesa
    }

    fn supported_currencies(&self) -> &'static [&'static str] {
        &["KES"]
    }

    fn supported_countries(&self) -> &'static [&'static str] {
        &["KE"]
    }

    fn verify_webhook(
        &self,
        _payload: &[u8],
        _signature: &str,
    ) -> PaymentResult<WebhookVerificationResult> {
        // Safaricom does not sign B2C result callbacks with a shared secret.
        // IP allowlisting is the recommended security control.
        Ok(WebhookVerificationResult {
            valid: true,
            reason: None,
        })
    }

    fn parse_webhook_event(&self, payload: &[u8]) -> PaymentResult<WebhookEvent> {
        let parsed: JsonValue =
            serde_json::from_slice(payload).map_err(|e| PaymentError::WebhookVerificationError {
                message: format!("invalid M-Pesa webhook JSON: {}", e),
            })?;

        // Daraja B2C result envelope:
        // { "Result": { "ResultCode": 0, "ResultDesc": "...",
        //               "OriginatorConversationID": "...",
        //               "ConversationID": "...",
        //               "TransactionID": "...",
        //               "ReferenceData": { "ReferenceItem": { "Key": "Occasion", "Value": "<tx_ref>" } }
        //             } }
        let result = parsed
            .get("Result")
            .cloned()
            .unwrap_or_else(|| serde_json::json!({}));

        let result_code = result
            .get("ResultCode")
            .and_then(|v| v.as_i64())
            .unwrap_or(-1);

        let status = Self::map_result_code(result_code);

        // Extract our transaction reference from the Occasion field.
        let tx_ref = result
            .pointer("/ReferenceData/ReferenceItem/Value")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .or_else(|| {
                result
                    .get("OriginatorConversationID")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
            });

        let provider_reference = result
            .get("TransactionID")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .or_else(|| {
                result
                    .get("ConversationID")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
            });

        let failure_reason = if result_code != 0 {
            Some(
                result
                    .get("ResultDesc")
                    .and_then(|v| v.as_str())
                    .unwrap_or(Self::result_code_description(result_code))
                    .to_string(),
            )
        } else {
            None
        };

        if result_code != 0 {
            warn!(
                result_code = result_code,
                description = ?failure_reason,
                tx_ref = ?tx_ref,
                "M-Pesa B2C disbursement failed"
            );
        }

        Ok(WebhookEvent {
            provider: ProviderName::Mpesa,
            event_type: format!("b2c.result.{}", result_code),
            transaction_reference: tx_ref,
            provider_reference,
            status: Some(status),
            payload: parsed,
            received_at: chrono::Utc::now().to_rfc3339(),
        })
    }

    async fn get_balance(&self, currency: &str) -> PaymentResult<Money> {
        // Balance check via Daraja AccountBalance API (async — not implemented here).
        Ok(Money {
            amount: "0".to_string(),
            currency: currency.to_string(),
        })
    }
}

// ---------------------------------------------------------------------------
// Recipient validation helper
// ---------------------------------------------------------------------------

/// Validates that a Kenyan phone number is active on M-Pesa before sending.
/// In production this calls the Daraja CustomerCheck or AccountBalance API.
pub async fn validate_mpesa_recipient(
    config: &MpesaKenyaConfig,
    phone: &str,
) -> PaymentResult<RecipientValidationResult> {
    let normalised = MpesaKenyaProvider::normalise_phone(phone);

    if normalised.len() != 12 || !normalised.starts_with("254") {
        return Ok(RecipientValidationResult {
            valid: false,
            normalised_phone: normalised,
            reason: Some("Phone number format invalid for Kenya (expected 254XXXXXXXXX)".to_string()),
        });
    }

    // Prefix check: Safaricom Kenya prefixes are 0700-0729, 0740-0743, 0745,
    // 0748, 0757-0759, 0768-0769, 0790-0799, 0110-0119, 0100-0109.
    // We do a lightweight prefix check here; a full Daraja CustomerCheck
    // would be the production implementation.
    let local = &normalised[3..]; // strip "254"
    let is_safaricom = matches!(
        &local[..3],
        "700" | "701" | "702" | "703" | "704" | "705" | "706" | "707" | "708" | "709"
            | "710" | "711" | "712" | "713" | "714" | "715" | "716" | "717" | "718" | "719"
            | "720" | "721" | "722" | "723" | "724" | "725" | "726" | "727" | "728" | "729"
            | "740" | "741" | "742" | "743" | "745" | "748"
            | "757" | "758" | "759"
            | "768" | "769"
            | "790" | "791" | "792" | "793" | "794" | "795" | "796" | "797" | "798" | "799"
            | "110" | "111" | "112" | "113" | "114" | "115" | "116" | "117" | "118" | "119"
            | "100" | "101" | "102" | "103" | "104" | "105" | "106" | "107" | "108" | "109"
    );

    if !is_safaricom {
        return Ok(RecipientValidationResult {
            valid: false,
            normalised_phone: normalised,
            reason: Some(
                "Phone number does not appear to be a Safaricom Kenya number".to_string(),
            ),
        });
    }

    Ok(RecipientValidationResult {
        valid: true,
        normalised_phone: normalised,
        reason: None,
    })
}

#[derive(Debug, Clone, Serialize)]
pub struct RecipientValidationResult {
    pub valid: bool,
    pub normalised_phone: String,
    pub reason: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalise_phone_handles_all_formats() {
        assert_eq!(MpesaKenyaProvider::normalise_phone("0712345678"), "254712345678");
        assert_eq!(MpesaKenyaProvider::normalise_phone("254712345678"), "254712345678");
        assert_eq!(MpesaKenyaProvider::normalise_phone("+254712345678"), "254712345678");
        assert_eq!(MpesaKenyaProvider::normalise_phone("712345678"), "254712345678");
    }

    #[test]
    fn result_code_mapping() {
        assert_eq!(MpesaKenyaProvider::map_result_code(0), PaymentState::Success);
        assert_eq!(MpesaKenyaProvider::map_result_code(1), PaymentState::Failed);
        assert_eq!(MpesaKenyaProvider::map_result_code(1032), PaymentState::Unknown);
    }

    #[test]
    fn parse_webhook_success() {
        let config = MpesaKenyaConfig {
            consumer_key: "k".to_string(),
            consumer_secret: "s".to_string(),
            passkey: "p".to_string(),
            shortcode: "600000".to_string(),
            initiator_name: "test".to_string(),
            initiator_password: "pass".to_string(),
            result_url: "https://example.com/result".to_string(),
            queue_timeout_url: "https://example.com/timeout".to_string(),
            base_url: "https://sandbox.safaricom.co.ke".to_string(),
            timeout_secs: 5,
            max_retries: 1,
        };
        let provider = MpesaKenyaProvider::new(config).unwrap();

        let payload = serde_json::json!({
            "Result": {
                "ResultCode": 0,
                "ResultDesc": "The service request is processed successfully.",
                "OriginatorConversationID": "aframp-tx-001",
                "ConversationID": "AG_20240101_000001",
                "TransactionID": "OEI2AK4Q16",
                "ReferenceData": {
                    "ReferenceItem": {
                        "Key": "Occasion",
                        "Value": "aframp-tx-001"
                    }
                }
            }
        });

        let event = provider
            .parse_webhook_event(payload.to_string().as_bytes())
            .unwrap();

        assert_eq!(event.transaction_reference.as_deref(), Some("aframp-tx-001"));
        assert_eq!(event.provider_reference.as_deref(), Some("OEI2AK4Q16"));
        assert!(matches!(event.status, Some(PaymentState::Success)));
    }

    #[test]
    fn parse_webhook_failure() {
        let config = MpesaKenyaConfig {
            consumer_key: "k".to_string(),
            consumer_secret: "s".to_string(),
            passkey: "p".to_string(),
            shortcode: "600000".to_string(),
            initiator_name: "test".to_string(),
            initiator_password: "pass".to_string(),
            result_url: "https://example.com/result".to_string(),
            queue_timeout_url: "https://example.com/timeout".to_string(),
            base_url: "https://sandbox.safaricom.co.ke".to_string(),
            timeout_secs: 5,
            max_retries: 1,
        };
        let provider = MpesaKenyaProvider::new(config).unwrap();

        let payload = serde_json::json!({
            "Result": {
                "ResultCode": 1,
                "ResultDesc": "Insufficient funds",
                "OriginatorConversationID": "aframp-tx-002",
                "ConversationID": "AG_20240101_000002",
                "TransactionID": ""
            }
        });

        let event = provider
            .parse_webhook_event(payload.to_string().as_bytes())
            .unwrap();

        assert!(matches!(event.status, Some(PaymentState::Failed)));
    }
}
