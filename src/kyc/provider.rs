use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;
use bigdecimal::BigDecimal;

use crate::database::kyc_repository::{KycTier, KycStatus, DocumentType};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KycSessionRequest {
    pub consumer_id: Uuid,
    pub target_tier: KycTier,
    pub callback_url: String,
    pub redirect_url: Option<String>,
    pub language: Option<String>,
    pub metadata: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KycSessionResponse {
    pub session_id: String,
    pub session_url: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub provider_session_id: String,
    pub status: KycStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentSubmissionRequest {
    pub session_id: String,
    pub document_type: DocumentType,
    pub front_image_base64: String,
    pub back_image_base64: Option<String>,
    pub document_number: Option<String>,
    pub issuing_country: Option<String>,
    pub expiry_date: Option<DateTime<Utc>>,
    pub metadata: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentSubmissionResponse {
    pub document_id: String,
    pub provider_document_id: String,
    pub status: KycStatus,
    pub extraction_data: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelfieSubmissionRequest {
    pub session_id: String,
    pub selfie_image_base64: String,
    pub liveness_check: bool,
    pub match_with_document: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelfieSubmissionResponse {
    pub selfie_id: String,
    pub provider_selfie_id: String,
    pub status: KycStatus,
    pub liveness_score: Option<f64>,
    pub face_match_score: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KycStatusResponse {
    pub session_id: String,
    pub status: KycStatus,
    pub tier: Option<KycTier>,
    pub decision: Option<KycDecision>,
    pub risk_score: Option<i32>,
    pub risk_flags: Option<Vec<String>>,
    pub completed_steps: Vec<String>,
    pub pending_steps: Vec<String>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KycDecision {
    pub decision: KycStatus,
    pub reason: String,
    pub tier: Option<KycTier>,
    pub reviewer_notes: Option<String>,
    pub provider_reference: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderWebhookPayload {
    pub provider: String,
    pub event_type: String,
    pub session_id: String,
    pub consumer_id: Uuid,
    pub status: KycStatus,
    pub decision: Option<KycDecision>,
    pub risk_score: Option<i32>,
    pub risk_flags: Option<Vec<String>>,
    pub timestamp: DateTime<Utc>,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderConfig {
    pub name: String,
    pub api_key: String,
    pub api_secret: String,
    pub webhook_secret: String,
    pub base_url: String,
    pub timeout_seconds: u64,
    pub retry_attempts: u32,
    pub document_type_mappings: HashMap<DocumentType, String>,
}

#[async_trait]
pub trait KycProvider: Send + Sync {
    fn name(&self) -> &str;
    fn config(&self) -> &ProviderConfig;
    
    async fn create_session(&self, request: KycSessionRequest) -> Result<KycSessionResponse, KycProviderError>;
    
    async fn submit_document(&self, request: DocumentSubmissionRequest) -> Result<DocumentSubmissionResponse, KycProviderError>;
    
    async fn submit_selfie(&self, request: SelfieSubmissionRequest) -> Result<SelfieSubmissionResponse, KycProviderError>;
    
    async fn check_status(&self, session_id: &str) -> Result<KycStatusResponse, KycProviderError>;
    
    async fn verify_webhook_signature(&self, payload: &str, signature: &str) -> Result<bool, KycProviderError>;
    
    fn map_document_type(&self, document_type: DocumentType) -> Result<String, KycProviderError>;
    
    fn map_provider_status(&self, provider_status: &str) -> Result<KycStatus, KycProviderError>;
    
    fn map_provider_tier(&self, provider_tier: &str) -> Result<Option<KycTier>, KycProviderError>;
}

#[derive(Debug, thiserror::Error)]
pub enum KycProviderError {
    #[error("API request failed: {0}")]
    ApiError(String),
    
    #[error("Authentication failed: {0}")]
    AuthenticationError(String),
    
    #[error("Invalid request: {0}")]
    InvalidRequest(String),
    
    #[error("Document processing failed: {0}")]
    DocumentProcessingError(String),
    
    #[error("Session not found: {0}")]
    SessionNotFound(String),
    
    #[error("Rate limit exceeded")]
    RateLimitExceeded,
    
    #[error("Service unavailable: {0}")]
    ServiceUnavailable(String),
    
    #[error("Invalid response: {0}")]
    InvalidResponse(String),
    
    #[error("Webhook signature verification failed")]
    WebhookSignatureError,
    
    #[error("Configuration error: {0}")]
    ConfigurationError(String),
    
    #[error("Network error: {0}")]
    NetworkError(#[from] reqwest::Error),
    
    #[error("JSON serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
}

// Smile Identity Provider Implementation
pub struct SmileIdentityProvider {
    config: ProviderConfig,
    client: reqwest::Client,
}

impl SmileIdentityProvider {
    pub fn new(config: ProviderConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(config.timeout_seconds))
            .build()
            .expect("Failed to create HTTP client");
            
        Self { config, client }
    }
    
    fn create_signature(&self, payload: &str) -> String {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        
        type HmacSha256 = Hmac<Sha256>;
        
        let mut mac = HmacSha256::new_from_slice(self.config.api_secret.as_bytes())
            .expect("Invalid key length");
        mac.update(payload.as_bytes());
        
        hex::encode(mac.finalize().into_bytes())
    }
}

#[async_trait]
impl KycProvider for SmileIdentityProvider {
    fn name(&self) -> &str {
        "smile_identity"
    }
    
    fn config(&self) -> &ProviderConfig {
        &self.config
    }
    
    async fn create_session(&self, request: KycSessionRequest) -> Result<KycSessionResponse, KycProviderError> {
        let url = format!("{}/api/v1/verification/session", self.config.base_url);
        
        let mut payload = serde_json::json!({
            "partner_id": self.config.api_key,
            "callback_url": request.callback_url,
            "user_id": request.consumer_id.to_string(),
            "language": request.language.unwrap_or_else(|| "en".to_string()),
            "metadata": request.metadata
        });
        
        if let Some(redirect_url) = request.redirect_url {
            payload["redirect_url"] = serde_json::Value::String(redirect_url);
        }
        
        let response = self.client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.config.api_key))
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .await?;
            
        if response.status().is_success() {
            let result: serde_json::Value = response.json().await?;
            
            Ok(KycSessionResponse {
                session_id: result["session_id"].as_str().unwrap().to_string(),
                session_url: result["session_url"].as_str().map(|s| s.to_string()),
                expires_at: DateTime::parse_from_rfc3339(result["expires_at"].as_str().unwrap())
                    .unwrap()
                    .with_timezone(&Utc),
                provider_session_id: result["provider_session_id"].as_str().unwrap().to_string(),
                status: KycStatus::Pending,
            })
        } else {
            let error_text = response.text().await.unwrap_or_default();
            Err(KycProviderError::ApiError(error_text))
        }
    }
    
    async fn submit_document(&self, request: DocumentSubmissionRequest) -> Result<DocumentSubmissionResponse, KycProviderError> {
        let url = format!("{}/api/v1/verification/document", self.config.base_url);
        
        let provider_doc_type = self.map_document_type(request.document_type)?;
        
        let mut payload = serde_json::json!({
            "session_id": request.session_id,
            "document_type": provider_doc_type,
            "front_image": request.front_image_base64,
            "metadata": request.metadata
        });
        
        if let Some(back_image) = request.back_image_base64 {
            payload["back_image"] = serde_json::Value::String(back_image);
        }
        
        if let Some(doc_number) = request.document_number {
            payload["document_number"] = serde_json::Value::String(doc_number);
        }
        
        if let Some(country) = request.issuing_country {
            payload["issuing_country"] = serde_json::Value::String(country);
        }
        
        let response = self.client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.config.api_key))
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .await?;
            
        if response.status().is_success() {
            let result: serde_json::Value = response.json().await?;
            
            Ok(DocumentSubmissionResponse {
                document_id: result["document_id"].as_str().unwrap().to_string(),
                provider_document_id: result["provider_document_id"].as_str().unwrap().to_string(),
                status: self.map_provider_status(result["status"].as_str().unwrap())?,
                extraction_data: result.get("extraction_data").cloned(),
            })
        } else {
            let error_text = response.text().await.unwrap_or_default();
            Err(KycProviderError::ApiError(error_text))
        }
    }
    
    async fn submit_selfie(&self, request: SelfieSubmissionRequest) -> Result<SelfieSubmissionResponse, KycProviderError> {
        let url = format!("{}/api/v1/verification/selfie", self.config.base_url);
        
        let payload = serde_json::json!({
            "session_id": request.session_id,
            "selfie_image": request.selfie_image_base64,
            "liveness_check": request.liveness_check,
            "match_with_document": request.match_with_document
        });
        
        let response = self.client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.config.api_key))
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .await?;
            
        if response.status().is_success() {
            let result: serde_json::Value = response.json().await?;
            
            Ok(SelfieSubmissionResponse {
                selfie_id: result["selfie_id"].as_str().unwrap().to_string(),
                provider_selfie_id: result["provider_selfie_id"].as_str().unwrap().to_string(),
                status: self.map_provider_status(result["status"].as_str().unwrap())?,
                liveness_score: result["liveness_score"].as_f64(),
                face_match_score: result["face_match_score"].as_f64(),
            })
        } else {
            let error_text = response.text().await.unwrap_or_default();
            Err(KycProviderError::ApiError(error_text))
        }
    }
    
    async fn check_status(&self, session_id: &str) -> Result<KycStatusResponse, KycProviderError> {
        let url = format!("{}/api/v1/verification/status/{}", self.config.base_url, session_id);
        
        let response = self.client
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.config.api_key))
            .send()
            .await?;
            
        if response.status().is_success() {
            let result: serde_json::Value = response.json().await?;
            
            let completed_steps: Vec<String> = result["completed_steps"]
                .as_array()
                .unwrap_or(&serde_json::Value::Array(vec![]))
                .iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect();
                
            let pending_steps: Vec<String> = result["pending_steps"]
                .as_array()
                .unwrap_or(&serde_json::Value::Array(vec![]))
                .iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect();
            
            let decision = if let Some(decision_data) = result.get("decision") {
                Some(KycDecision {
                    decision: self.map_provider_status(decision_data["decision"].as_str().unwrap())?,
                    reason: decision_data["reason"].as_str().unwrap().to_string(),
                    tier: decision_data["tier"].as_str()
                        .and_then(|t| self.map_provider_tier(t).ok())
                        .flatten(),
                    reviewer_notes: decision_data["reviewer_notes"].as_str().map(|s| s.to_string()),
                    provider_reference: decision_data["reference"].as_str().unwrap().to_string(),
                })
            } else {
                None
            };
            
            Ok(KycStatusResponse {
                session_id: session_id.to_string(),
                status: self.map_provider_status(result["status"].as_str().unwrap())?,
                tier: result["tier"].as_str()
                    .and_then(|t| self.map_provider_tier(t).ok())
                    .flatten(),
                decision,
                risk_score: result["risk_score"].as_i64().map(|i| i as i32),
                risk_flags: result["risk_flags"].as_array()
                    .map(|arr| arr.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect()),
                completed_steps,
                pending_steps,
                expires_at: DateTime::parse_from_rfc3339(result["expires_at"].as_str().unwrap())
                    .unwrap()
                    .with_timezone(&Utc),
            })
        } else {
            let error_text = response.text().await.unwrap_or_default();
            Err(KycProviderError::ApiError(error_text))
        }
    }
    
    async fn verify_webhook_signature(&self, payload: &str, signature: &str) -> Result<bool, KycProviderError> {
        let expected_signature = self.create_signature(payload);
        Ok(hmac::compare::compare(&expected_signature.as_bytes(), signature.as_bytes()).is_ok())
    }
    
    fn map_document_type(&self, document_type: DocumentType) -> Result<String, KycProviderError> {
        let mapping = self.config.document_type_mappings
            .get(&document_type)
            .cloned()
            .unwrap_or_else(|| match document_type {
                DocumentType::NationalId => "ID_CARD".to_string(),
                DocumentType::Passport => "PASSPORT".to_string(),
                DocumentType::DriversLicense => "DRIVERS_LICENSE".to_string(),
                DocumentType::UtilityBill => "UTILITY_BILL".to_string(),
                DocumentType::BankStatement => "BANK_STATEMENT".to_string(),
                DocumentType::GovernmentLetter => "GOVERNMENT_LETTER".to_string(),
                DocumentType::SourceOfFunds => "SOURCE_OF_FUNDS".to_string(),
                DocumentType::BusinessRegistration => "BUSINESS_REGISTRATION".to_string(),
            });
            
        Ok(mapping)
    }
    
    fn map_provider_status(&self, provider_status: &str) -> Result<KycStatus, KycProviderError> {
        match provider_status.to_lowercase().as_str() {
            "pending" | "processing" | "uploaded" => Ok(KycStatus::Pending),
            "approved" | "verified" | "completed" => Ok(KycStatus::Approved),
            "rejected" | "failed" | "declined" => Ok(KycStatus::Rejected),
            "manual_review" | "review_required" => Ok(KycStatus::ManualReview),
            "expired" | "timeout" => Ok(KycStatus::Expired),
            _ => Err(KycProviderError::InvalidResponse(format!("Unknown provider status: {}", provider_status))),
        }
    }
    
    fn map_provider_tier(&self, provider_tier: &str) -> Result<Option<KycTier>, KycProviderError> {
        let tier = match provider_tier.to_lowercase().as_str() {
            "basic" | "tier1" => Some(KycTier::Basic),
            "standard" | "tier2" => Some(KycTier::Standard),
            "enhanced" | "tier3" => Some(KycTier::Enhanced),
            "unverified" | "tier0" => Some(KycTier::Unverified),
            _ => None,
        };
        Ok(tier)
    }
}

// Provider Factory
pub struct KycProviderFactory;

impl KycProviderFactory {
    pub fn create_provider(config: ProviderConfig) -> Result<Box<dyn KycProvider>, KycProviderError> {
        match config.name.to_lowercase().as_str() {
            "smile_identity" | "smileidentity" => {
                Ok(Box::new(SmileIdentityProvider::new(config)))
            },
            "onfido" => {
                // TODO: Implement Onfido provider
                Err(KycProviderError::ConfigurationError("Onfido provider not yet implemented".to_string()))
            },
            "sumsub" => {
                // TODO: Implement Sumsub provider
                Err(KycProviderError::ConfigurationError("Sumsub provider not yet implemented".to_string()))
            },
            _ => Err(KycProviderError::ConfigurationError(format!("Unknown provider: {}", config.name))),
        }
    }
}
