use crate::database::models::redemption::{FiatDisbursement, RedemptionRequest};
use crate::database::repositories::redemption_repository::RedemptionRepository;
use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info, instrument, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisbursementProvider {
    pub name: String,
    pub base_url: String,
    pub api_key: String,
    pub secret_key: String,
    pub is_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisbursementRequest {
    pub amount: f64,
    pub currency: String,
    pub bank_code: String,
    pub account_number: String,
    pub account_name: String,
    pub narration: String,
    pub reference: String, // redemption_id
    pub callback_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkDisbursementRequest {
    pub transfers: Vec<DisbursementRequest>,
    pub batch_reference: String,
    pub callback_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisbursementResponse {
    pub status: String,
    pub reference: String,
    pub provider_reference: String,
    pub message: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionStatusResponse {
    pub status: String,
    pub reference: String,
    pub provider_reference: String,
    pub amount: f64,
    pub currency: String,
    pub recipient: RecipientInfo,
    pub created_at: String,
    pub completed_at: Option<String>,
    pub failure_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecipientInfo {
    pub bank_code: String,
    pub account_number: String,
    pub account_name: String,
    pub bank_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BankValidationRequest {
    pub bank_code: String,
    pub account_number: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BankValidationResponse {
    pub account_name: String,
    pub bank_name: String,
    pub is_valid: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisbursementServiceConfig {
    pub default_provider: String,
    pub timeout_seconds: u64,
    pub max_retries: u32,
    pub retry_delay_seconds: u64,
    pub enable_bulk_disbursements: bool,
    pub bulk_batch_size: usize,
    pub status_check_interval_seconds: u64,
    pub receipt_generation_enabled: bool,
}

impl Default for DisbursementServiceConfig {
    fn default() -> Self {
        Self {
            default_provider: "flutterwave".to_string(),
            timeout_seconds: 30,
            max_retries: 3,
            retry_delay_seconds: 5,
            enable_bulk_disbursements: true,
            bulk_batch_size: 100,
            status_check_interval_seconds: 60,
            receipt_generation_enabled: true,
        }
    }
}

#[async_trait]
pub trait DisbursementService: Send + Sync {
    async fn validate_bank_account(&self, bank_code: &str, account_number: &str) -> Result<BankValidationResponse, DisbursementError>;
    
    async fn initiate_disbursement(&self, redemption_request: &RedemptionRequest) -> Result<String, DisbursementError>;
    
    async fn initiate_bulk_disbursement(&self, redemption_requests: &[RedemptionRequest]) -> Result<Vec<String>, DisbursementError>;
    
    async fn check_disbursement_status(&self, provider_reference: &str) -> Result<TransactionStatusResponse, DisbursementError>;
    
    async fn retry_failed_disbursement(&self, redemption_id: &str) -> Result<bool, DisbursementError>;
    
    async fn generate_receipt(&self, redemption_id: &str) -> Result<String, DisbursementError>;
}

pub struct FlutterwaveDisbursementService {
    client: Client,
    provider: DisbursementProvider,
    repository: Arc<dyn RedemptionRepository>,
    config: DisbursementServiceConfig,
}

impl FlutterwaveDisbursementService {
    pub fn new(
        provider: DisbursementProvider,
        repository: Arc<dyn RedemptionRepository>,
        config: DisbursementServiceConfig,
    ) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(config.timeout_seconds))
            .build()
            .expect("Failed to create HTTP client");

        Self {
            client,
            provider,
            repository,
            config,
        }
    }

    fn get_auth_headers(&self) -> HashMap<String, String> {
        let mut headers = HashMap::new();
        headers.insert("Authorization".to_string(), format!("Bearer {}", self.provider.api_key));
        headers.insert("Content-Type".to_string(), "application/json".to_string());
        headers
    }

    async fn make_request<T: Serialize + ?Sized>(
        &self,
        method: reqwest::Method,
        endpoint: &str,
        payload: Option<&T>,
    ) -> Result<serde_json::Value, DisbursementError> {
        let url = format!("{}/{}", self.provider.base_url, endpoint);
        let mut request = self.client.request(method, &url);

        for (key, value) in self.get_auth_headers() {
            request = request.header(&key, &value);
        }

        if let Some(payload) = payload {
            request = request.json(payload);
        }

        let response = request
            .send()
            .await
            .map_err(|e| DisbursementError::NetworkError(e.to_string()))?;

        if response.status().is_success() {
            let json: serde_json::Value = response
                .json()
                .await
                .map_err(|e| DisbursementError::DeserializationError(e.to_string()))?;
            Ok(json)
        } else {
            let status = response.status();
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            Err(DisbursementError::ProviderError(format!(
                "HTTP {}: {}",
                status, error_text
            )))
        }
    }

    fn build_narration(&self, redemption_id: &str) -> String {
        format!("cNGN Redemption - {}", redemption_id)
    }

    async fn create_disbursement_record(
        &self,
        redemption_request: &RedemptionRequest,
        provider_reference: &str,
    ) -> Result<(), DisbursementError> {
        let disbursement = FiatDisbursement {
            id: uuid::Uuid::new_v4(),
            redemption_id: redemption_request.id,
            batch_id: redemption_request.batch_id,
            amount_ngn: redemption_request.amount_ngn,
            bank_code: redemption_request.bank_code.clone(),
            bank_name: redemption_request.bank_name.clone(),
            account_number: redemption_request.account_number.clone(),
            account_name: redemption_request.account_name.clone(),
            provider: self.provider.name.clone(),
            provider_reference: Some(provider_reference.to_string()),
            provider_status: Some("PENDING".to_string()),
            status: "PENDING".to_string(),
            nibss_transaction_id: None,
            nibss_status: None,
            beneficiary_account_credits: false,
            provider_fee: 0.0,
            processing_time_seconds: None,
            error_code: None,
            error_message: None,
            retry_count: 0,
            max_retries: self.config.max_retries as i32,
            receipt_url: None,
            receipt_pdf_base64: None,
            idempotency_key: Some(redemption_request.redemption_id.clone()),
            narration: self.build_narration(&redemption_request.redemption_id),
            metadata: serde_json::json!({
                "provider": self.provider.name,
                "initiated_at": chrono::Utc::now(),
            }),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            processed_at: None,
            completed_at: None,
            last_status_check: None,
        };

        self.repository
            .create_fiat_disbursement(&disbursement)
            .await
            .map_err(|e| DisbursementError::DatabaseError(e.to_string()))?;

        Ok(())
    }
}

#[async_trait]
impl DisbursementService for FlutterwaveDisbursementService {
    #[instrument(skip(self), fields(bank_code = %bank_code, account_number = %account_number))]
    async fn validate_bank_account(&self, bank_code: &str, account_number: &str) -> Result<BankValidationResponse, DisbursementError> {
        let request = BankValidationRequest {
            bank_code: bank_code.to_string(),
            account_number: account_number.to_string(),
        };

        let response = self
            .make_request(reqwest::Method::POST, "accounts/resolve", Some(&request))
            .await?;

        if response["status"].as_str() == Some("success") {
            let data = &response["data"];
            Ok(BankValidationResponse {
                account_name: data["account_name"].as_str().unwrap_or("").to_string(),
                bank_name: data["bank_name"].as_str().unwrap_or("").to_string(),
                is_valid: true,
            })
        } else {
            Ok(BankValidationResponse {
                account_name: "".to_string(),
                bank_name: "".to_string(),
                is_valid: false,
            })
        }
    }

    #[instrument(skip(self), fields(redemption_id = %redemption_request.redemption_id))]
    async fn initiate_disbursement(&self, redemption_request: &RedemptionRequest) -> Result<String, DisbursementError> {
        // Check if disbursement already exists (idempotency)
        if let Ok(existing) = self.repository.get_fiat_disbursement(&redemption_request.id).await {
            if let Some(provider_reference) = &existing.provider_reference {
                info!(
                    redemption_id = %redemption_request.redemption_id,
                    provider_reference = %provider_reference,
                    "Disbursement already exists"
                );
                return Ok(provider_reference.clone());
            }
        }

        let request = DisbursementRequest {
            amount: redemption_request.amount_ngn,
            currency: "NGN".to_string(),
            bank_code: redemption_request.bank_code.clone(),
            account_number: redemption_request.account_number.clone(),
            account_name: redemption_request.account_name.clone(),
            narration: self.build_narration(&redemption_request.redemption_id),
            reference: redemption_request.redemption_id.clone(),
            callback_url: Some(format!("{}/webhooks/disbursement", std::env::var("BASE_URL").unwrap_or_else(|_| "https://api.aframp.com".to_string()))),
        };

        let response = self
            .make_request(reqwest::Method::POST, "transfers", Some(&request))
            .await?;

        if response["status"].as_str() == Some("success") {
            let data = &response["data"];
            let provider_reference = data["reference"].as_str().unwrap_or("").to_string();

            // Create disbursement record
            self.create_disbursement_record(redemption_request, &provider_reference).await?;

            // Update redemption status
            self.repository
                .update_redemption_status(&redemption_request.redemption_id, "FIAT_DISBURSEMENT_PENDING")
                .await
                .map_err(|e| DisbursementError::DatabaseError(e.to_string()))?;

            info!(
                redemption_id = %redemption_request.redemption_id,
                provider_reference = %provider_reference,
                "Disbursement initiated successfully"
            );

            Ok(provider_reference)
        } else {
            let error_message = response["message"].as_str().unwrap_or("Unknown error");
            error!(
                redemption_id = %redemption_request.redemption_id,
                error = %error_message,
                "Failed to initiate disbursement"
            );
            Err(DisbursementError::ProviderError(error_message.to_string()))
        }
    }

    #[instrument(skip(self), fields(request_count = %redemption_requests.len()))]
    async fn initiate_bulk_disbursement(&self, redemption_requests: &[RedemptionRequest]) -> Result<Vec<String>, DisbursementError> {
        if !self.config.enable_bulk_disbursements {
            return Err(DisbursementError::ConfigurationError("Bulk disbursements are disabled".to_string()));
        }

        if redemption_requests.len() > self.config.bulk_batch_size {
            return Err(DisbursementError::ConfigurationError(format!(
                "Batch size {} exceeds maximum {}",
                redemption_requests.len(),
                self.config.bulk_batch_size
            )));
        }

        let transfers: Vec<DisbursementRequest> = redemption_requests
            .iter()
            .map(|req| DisbursementRequest {
                amount: req.amount_ngn,
                currency: "NGN".to_string(),
                bank_code: req.bank_code.clone(),
                account_number: req.account_number.clone(),
                account_name: req.account_name.clone(),
                narration: self.build_narration(&req.redemption_id),
                reference: req.redemption_id.clone(),
                callback_url: Some(format!("{}/webhooks/disbursement", std::env::var("BASE_URL").unwrap_or_else(|_| "https://api.aframp.com".to_string()))),
            })
            .collect();

        let batch_reference = format!("BATCH_{}", uuid::Uuid::new_v4());
        let request = BulkDisbursementRequest {
            transfers,
            batch_reference: batch_reference.clone(),
            callback_url: Some(format!("{}/webhooks/bulk-disbursement", std::env::var("BASE_URL").unwrap_or_else(|_| "https://api.aframp.com".to_string()))),
        };

        let response = self
            .make_request(reqwest::Method::POST, "bulk-transfers", Some(&request))
            .await?;

        if response["status"].as_str() == Some("success") {
            let data = response["data"].as_array().unwrap_or(&vec![]);
            let mut provider_references = Vec::new();

            for (i, item) in data.iter().enumerate() {
                if let Some(redemption_request) = redemption_requests.get(i) {
                    if let Some(provider_reference) = item["reference"].as_str() {
                        // Create individual disbursement records
                        self.create_disbursement_record(redemption_request, provider_reference).await?;
                        provider_references.push(provider_reference.to_string());
                    }
                }
            }

            Ok(provider_references)
        } else {
            let error_message = response["message"].as_str().unwrap_or("Unknown error");
            Err(DisbursementError::ProviderError(error_message.to_string()))
        }
    }

    #[instrument(skip(self), fields(provider_reference = %provider_reference))]
    async fn check_disbursement_status(&self, provider_reference: &str) -> Result<TransactionStatusResponse, DisbursementError> {
        let response = self
            .make_request(reqwest::Method::GET, &format!("transfers/{}", provider_reference), None::<()>)
            .await?;

        if response["status"].as_str() == Some("success") {
            let data = &response["data"];
            
            let recipient = RecipientInfo {
                bank_code: data["bank_code"].as_str().unwrap_or("").to_string(),
                account_number: data["account_number"].as_str().unwrap_or("").to_string(),
                account_name: data["account_name"].as_str().unwrap_or("").to_string(),
                bank_name: data["bank_name"].as_str().unwrap_or("").to_string(),
            };

            Ok(TransactionStatusResponse {
                status: data["status"].as_str().unwrap_or("").to_string(),
                reference: data["reference"].as_str().unwrap_or("").to_string(),
                provider_reference: provider_reference.to_string(),
                amount: data["amount"].as_f64().unwrap_or(0.0),
                currency: data["currency"].as_str().unwrap_or("").to_string(),
                recipient,
                created_at: data["created_at"].as_str().unwrap_or("").to_string(),
                completed_at: data["completed_at"].as_str().map(|s| s.to_string()),
                failure_reason: data["failure_reason"].as_str().map(|s| s.to_string()),
            })
        } else {
            Err(DisbursementError::ProviderError("Failed to get transaction status".to_string()))
        }
    }

    #[instrument(skip(self), fields(redemption_id = %redemption_id))]
    async fn retry_failed_disbursement(&self, redemption_id: &str) -> Result<bool, DisbursementError> {
        // Get the redemption request
        let redemption_request = self.repository.get_redemption_request(redemption_id).await
            .map_err(|e| DisbursementError::DatabaseError(e.to_string()))?;

        // Get the existing disbursement
        let disbursement = self.repository.get_fiat_disbursement(&redemption_request.id).await
            .map_err(|e| DisbursementError::DatabaseError(e.to_string()))?;

        if disbursement.retry_count >= disbursement.max_retries {
            error!(
                redemption_id = %redemption_id,
                retry_count = %disbursement.retry_count,
                max_retries = %disbursement.max_retries,
                "Max retries exceeded for disbursement"
            );
            return Ok(false);
        }

        // Increment retry count
        // This would need to be implemented in the repository
        // self.repository.increment_disbursement_retry_count(redemption_id).await?;

        // Retry the disbursement
        match self.initiate_disbursement(&redemption_request).await {
            Ok(provider_reference) => {
                info!(
                    redemption_id = %redemption_id,
                    provider_reference = %provider_reference,
                    "Disbursement retry successful"
                );
                Ok(true)
            }
            Err(e) => {
                error!(
                    redemption_id = %redemption_id,
                    error = %e,
                    "Disbursement retry failed"
                );
                Err(e)
            }
        }
    }

    #[instrument(skip(self), fields(redemption_id = %redemption_id))]
    async fn generate_receipt(&self, redemption_id: &str) -> Result<String, DisbursementError> {
        if !self.config.receipt_generation_enabled {
            return Err(DisbursementError::ConfigurationError("Receipt generation is disabled".to_string()));
        }

        // Get redemption and disbursement details
        let redemption_request = self.repository.get_redemption_request(redemption_id).await
            .map_err(|e| DisbursementError::DatabaseError(e.to_string()))?;

        let disbursement = self.repository.get_fiat_disbursement(&redemption_request.id).await
            .map_err(|e| DisbursementError::DatabaseError(e.to_string()))?;

        // Generate PDF receipt (simplified - in production, use a proper PDF library)
        let receipt_data = serde_json::json!({
            "redemption_id": redemption_request.redemption_id,
            "amount_ngn": redemption_request.amount_ngn,
            "amount_cngn": redemption_request.amount_cngn,
            "exchange_rate": redemption_request.exchange_rate,
            "bank_details": {
                "bank_name": redemption_request.bank_name,
                "account_number": redemption_request.account_number,
                "account_name": redemption_request.account_name,
            },
            "disbursement": {
                "provider": disbursement.provider,
                "provider_reference": disbursement.provider_reference,
                "status": disbursement.status,
                "completed_at": disbursement.completed_at,
            },
            "created_at": redemption_request.created_at,
        });

        // In production, this would generate an actual PDF
        let receipt_json = serde_json::to_string(&receipt_data)
            .map_err(|e| DisbursementError::SerializationError(e.to_string()))?;

        // Store receipt (simplified - store as JSON, in production store as PDF)
        // self.repository.store_disbursement_receipt(redemption_id, &receipt_pdf_base64).await?;

        Ok(receipt_json)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DisbursementError {
    #[error("Network error: {0}")]
    NetworkError(String),
    
    #[error("Provider error: {0}")]
    ProviderError(String),
    
    #[error("Database error: {0}")]
    DatabaseError(String),
    
    #[error("Configuration error: {0}")]
    ConfigurationError(String),
    
    #[error("Serialization error: {0}")]
    SerializationError(String),
    
    #[error("Deserialization error: {0}")]
    DeserializationError(String),
    
    #[error("Validation error: {0}")]
    ValidationError(String),
    
    #[error("Idempotency error: {0}")]
    IdempotencyError(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_disbursement_service_config_default() {
        let config = DisbursementServiceConfig::default();
        assert_eq!(config.default_provider, "flutterwave");
        assert_eq!(config.timeout_seconds, 30);
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.retry_delay_seconds, 5);
        assert!(config.enable_bulk_disbursements);
        assert_eq!(config.bulk_batch_size, 100);
        assert_eq!(config.status_check_interval_seconds, 60);
        assert!(config.receipt_generation_enabled);
    }

    #[test]
    fn test_build_narration() {
        let service = FlutterwaveDisbursementService {
            client: Client::new(),
            provider: DisbursementProvider {
                name: "flutterwave".to_string(),
                base_url: "https://api.flutterwave.com".to_string(),
                api_key: "test_key".to_string(),
                secret_key: "test_secret".to_string(),
                is_enabled: true,
            },
            repository: Arc::new(crate::database::repositories::redemption_repository::PostgresRedemptionRepository::new(
                Arc::new(sqlx::PgPool::connect("postgresql://test").await.unwrap())
            )),
            config: DisbursementServiceConfig::default(),
        };

        let narration = service.build_narration("RED-12345");
        assert_eq!(narration, "cNGN Redemption - RED-12345");
    }
}
