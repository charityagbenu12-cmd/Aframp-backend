use chrono::{DateTime, Utc, Duration};
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;
use bigdecimal::BigDecimal;
use tracing::{info, warn, error};

use crate::database::kyc_repository::{
    KycRepository, KycRecord, KycDocument, KycEvent, KycTier, KycStatus,
    DocumentType, KycEventType, ManualReviewQueue, EnhancedDueDiligenceCase,
    EddStatus, KycDecision
};
use crate::kyc::provider::{
    KycProvider, KycProviderFactory, KycProviderError, ProviderConfig,
    KycSessionRequest, KycSessionResponse, DocumentSubmissionRequest,
    DocumentSubmissionResponse, SelfieSubmissionRequest, SelfieSubmissionResponse,
    KycStatusResponse, ProviderWebhookPayload
};
use crate::kyc::tier_requirements::{
    KycTierRequirements, TransactionLimitEnforcer, VolumeTracker
};
use crate::cache::RedisManager;

#[derive(Clone)]
pub struct KycService {
    repository: Arc<KycRepository>,
    redis: Arc<RedisManager>,
    providers: HashMap<String, Arc<dyn KycProvider>>,
    default_provider: String,
}

impl KycService {
    pub fn new(
        repository: Arc<KycRepository>,
        redis: Arc<RedisManager>,
        provider_configs: Vec<ProviderConfig>,
        default_provider: String,
    ) -> Result<Self, KycServiceError> {
        let mut providers = HashMap::new();
        
        for config in provider_configs {
            let provider = KycProviderFactory::create_provider(config.clone())?;
            providers.insert(config.name.clone(), provider);
            info!("KYC provider {} initialized", config.name);
        }
        
        if !providers.contains_key(&default_provider) {
            return Err(KycServiceError::ConfigurationError(
                format!("Default provider {} not found", default_provider)
            ));
        }
        
        Ok(Self {
            repository,
            redis,
            providers,
            default_provider,
        })
    }
    
    pub async fn initiate_kyc_session(
        &self,
        consumer_id: Uuid,
        target_tier: KycTier,
        callback_url: String,
        redirect_url: Option<String>,
        language: Option<String>,
    ) -> Result<KycSessionResponse, KycServiceError> {
        info!("Initiating KYC session for consumer {} targeting tier {:?}", consumer_id, target_tier);
        
        // Check if consumer already has an active KYC session
        let existing_record = self.repository.get_kyc_record_by_consumer(consumer_id).await?;
        if let Some(record) = existing_record {
            if record.status == KycStatus::Pending && 
               record.expires_at.map_or(false, |exp| exp > Utc::now()) {
                return Err(KycServiceError::SessionAlreadyActive);
            }
        }
        
        // Create new KYC record
        let kyc_record = self.repository.create_kyc_record(consumer_id, target_tier).await?;
        
        // Create session with provider
        let provider = self.get_provider(&self.default_provider)?;
        let session_request = KycSessionRequest {
            consumer_id,
            target_tier,
            callback_url,
            redirect_url,
            language,
            metadata: HashMap::new(),
        };
        
        let session_response = provider.create_session(session_request).await?;
        
        // Update KYC record with session info
        let updated_record = sqlx::query!(
            r#"
            UPDATE kyc_records 
            SET verification_provider = $1, verification_session_id = $2, 
                expires_at = $3, updated_at = $4
            WHERE id = $5
            RETURNING *
            "#,
            self.default_provider,
            session_response.provider_session_id,
            session_response.expires_at,
            Utc::now(),
            kyc_record.id
        )
        .fetch_one(&self.repository.pool)
        .await
        .map_err(|e| KycServiceError::DatabaseError(e.to_string()))?;
        
        // Log the event
        self.repository.create_event(
            consumer_id,
            Some(kyc_record.id),
            KycEventType::SessionInitiated,
            Some(format!("Session created with provider: {}", self.default_provider)),
            Some(serde_json::to_string(&session_response).unwrap_or_default()),
            Some(serde_json::json!({
                "provider": self.default_provider,
                "target_tier": format!("{:?}", target_tier),
                "session_id": session_response.session_id
            }))
        ).await.map_err(|e| KycServiceError::DatabaseError(e.to_string()))?;
        
        // Cache session info for quick lookup
        let cache_key = format!("kyc_session:{}", session_response.session_id);
        let session_data = serde_json::json!({
            "consumer_id": consumer_id,
            "kyc_record_id": kyc_record.id,
            "provider": self.default_provider,
            "expires_at": session_response.expires_at.to_rfc3339()
        });
        
        if let Err(e) = self.redis.setex(&cache_key, &session_data.to_string(), 3600).await {
            warn!("Failed to cache KYC session: {}", e);
        }
        
        info!("KYC session {} initiated for consumer {}", session_response.session_id, consumer_id);
        Ok(session_response)
    }
    
    pub async fn submit_document(
        &self,
        session_id: &str,
        document_type: DocumentType,
        front_image_base64: String,
        back_image_base64: Option<String>,
        document_number: Option<String>,
        issuing_country: Option<String>,
        expiry_date: Option<DateTime<Utc>>,
    ) -> Result<DocumentSubmissionResponse, KycServiceError> {
        info!("Submitting document for session {}", session_id);
        
        // Get session info from cache or database
        let session_info = self.get_session_info(session_id).await?;
        
        // Validate session is still active
        if session_info.expires_at < Utc::now() {
            return Err(KycServiceError::SessionExpired);
        }
        
        // Get provider
        let provider = self.get_provider(&session_info.provider)?;
        
        // Submit document to provider
        let submission_request = DocumentSubmissionRequest {
            session_id: session_id.to_string(),
            document_type,
            front_image_base64,
            back_image_base64,
            document_number,
            issuing_country,
            expiry_date,
            metadata: HashMap::new(),
        };
        
        let submission_response = provider.submit_document(submission_request).await?;
        
        // Store document in database
        self.repository.create_document(
            session_info.kyc_record_id,
            document_type,
            document_number,
            issuing_country,
            expiry_date,
            Some(format!("doc_{}", submission_response.document_id)),
            back_image_base64.map(|_| format!("doc_{}_back", submission_response.document_id)),
            None,
        ).await.map_err(|e| KycServiceError::DatabaseError(e.to_string()))?;
        
        // Log the event
        self.repository.create_event(
            session_info.consumer_id,
            Some(session_info.kyc_record_id),
            KycEventType::DocumentSubmitted,
            Some(format!("Document submitted: {:?}", document_type)),
            Some(serde_json::to_string(&submission_response).unwrap_or_default()),
            Some(serde_json::json!({
                "document_type": format!("{:?}", document_type),
                "document_id": submission_response.document_id
            }))
        ).await.map_err(|e| KycServiceError::DatabaseError(e.to_string()))?;
        
        Ok(submission_response)
    }
    
    pub async fn submit_selfie(
        &self,
        session_id: &str,
        selfie_image_base64: String,
        liveness_check: bool,
        match_with_document: bool,
    ) -> Result<SelfieSubmissionResponse, KycServiceError> {
        info!("Submitting selfie for session {}", session_id);
        
        // Get session info
        let session_info = self.get_session_info(session_id).await?;
        
        // Validate session is still active
        if session_info.expires_at < Utc::now() {
            return Err(KycServiceError::SessionExpired);
        }
        
        // Get provider
        let provider = self.get_provider(&session_info.provider)?;
        
        // Submit selfie to provider
        let submission_request = SelfieSubmissionRequest {
            session_id: session_id.to_string(),
            selfie_image_base64,
            liveness_check,
            match_with_document,
        };
        
        let submission_response = provider.submit_selfie(submission_request).await?;
        
        // Update document record with selfie reference
        sqlx::query!(
            r#"
            UPDATE kyc_documents 
            SET selfie_image_reference = $1, updated_at = $2
            WHERE kyc_record_id = $3 AND document_type = ANY($4)
            "#,
            Some(format!("selfie_{}", submission_response.selfie_id)),
            Utc::now(),
            session_info.kyc_record_id,
            vec![DocumentType::NationalId as DocumentType, DocumentType::Passport as DocumentType, DocumentType::DriversLicense as DocumentType]
        )
        .execute(&self.repository.pool)
        .await
        .map_err(|e| KycServiceError::DatabaseError(e.to_string()))?;
        
        // Log the event
        self.repository.create_event(
            session_info.consumer_id,
            Some(session_info.kyc_record_id),
            KycEventType::SelfieSubmitted,
            Some("Selfie submitted for liveness check".to_string()),
            Some(serde_json::to_string(&submission_response).unwrap_or_default()),
            Some(serde_json::json!({
                "selfie_id": submission_response.selfie_id,
                "liveness_check": liveness_check,
                "face_match_score": submission_response.face_match_score
            }))
        ).await.map_err(|e| KycServiceError::DatabaseError(e.to_string()))?;
        
        Ok(submission_response)
    }
    
    pub async fn get_kyc_status(&self, consumer_id: Uuid) -> Result<KycStatusResponse, KycServiceError> {
        info!("Getting KYC status for consumer {}", consumer_id);
        
        // Get latest KYC record
        let kyc_record = self.repository.get_kyc_record_by_consumer(consumer_id)
            .await?
            .ok_or(KycServiceError::KycRecordNotFound)?;
        
        // If we have a provider session ID, check with provider
        if let (Some(provider), Some(session_id)) = (&kyc_record.verification_provider, &kyc_record.verification_session_id) {
            let provider_obj = self.get_provider(provider)?;
            
            match provider_obj.check_status(session_id).await {
                Ok(status_response) => {
                    // Update local status if different
                    if status_response.status != kyc_record.status {
                        self.update_kyc_status_from_provider(
                            kyc_record.id,
                            &status_response,
                            consumer_id,
                        ).await?;
                    }
                    
                    return Ok(status_response);
                },
                Err(KycProviderError::SessionNotFound(_)) => {
                    // Session not found on provider, might be expired
                    warn!("Provider session {} not found for consumer {}", session_id, consumer_id);
                },
                Err(e) => {
                    error!("Failed to check status with provider {}: {}", provider, e);
                    // Continue with local status
                }
            }
        }
        
        // Return local status
        Ok(KycStatusResponse {
            session_id: kyc_record.verification_session_id.unwrap_or_default(),
            status: kyc_record.status,
            tier: Some(kyc_record.effective_tier),
            decision: None, // TODO: Load from decisions table
            risk_score: None,
            risk_flags: None,
            completed_steps: vec![],
            pending_steps: vec![],
            expires_at: kyc_record.expires_at.unwrap_or_else(|| Utc::now() + Duration::days(30)),
        })
    }
    
    pub async fn get_transaction_limits(&self, consumer_id: Uuid) -> Result<crate::kyc::tier_requirements::RemainingLimits, KycServiceError> {
        info!("Getting transaction limits for consumer {}", consumer_id);
        
        // Get current KYC record
        let kyc_record = self.repository.get_kyc_record_by_consumer(consumer_id)
            .await?
            .ok_or(KycServiceError::KycRecordNotFound)?;
        
        // Get current volumes
        let volume_tracker = VolumeTracker::new(consumer_id);
        let (daily_used, monthly_used) = volume_tracker.get_current_volumes(&self.repository.pool).await
            .map_err(|e| KycServiceError::DatabaseError(e.to_string()))?;
        
        // Calculate remaining limits
        let enforcer = TransactionLimitEnforcer::new(kyc_record.effective_tier);
        let remaining = enforcer.get_remaining_limits(daily_used, monthly_used);
        
        Ok(remaining)
    }
    
    pub async fn handle_webhook(&self, payload: ProviderWebhookPayload) -> Result<(), KycServiceError> {
        info!("Handling webhook from provider {} for session {}", payload.provider, payload.session_id);
        
        // Verify webhook signature
        let provider = self.get_provider(&payload.provider)?;
        let payload_str = serde_json::to_string(&payload)?;
        
        if !provider.verify_webhook_signature(&payload_str, &payload.signature).await? {
            return Err(KycServiceError::WebhookSignatureInvalid);
        }
        
        // Get KYC record
        let kyc_record = self.repository.get_kyc_record_by_consumer(payload.consumer_id)
            .await?
            .ok_or(KycServiceError::KycRecordNotFound)?;
        
        // Log provider callback
        self.repository.create_event(
            payload.consumer_id,
            Some(kyc_record.id),
            KycEventType::ProviderCallback,
            Some(format!("Webhook received from {}", payload.provider)),
            Some(payload_str),
            Some(serde_json::json!({
                "event_type": payload.event_type,
                "status": format!("{:?}", payload.status)
            }))
        ).await.map_err(|e| KycServiceError::DatabaseError(e.to_string()))?;
        
        // Process the decision
        if let Some(decision) = payload.decision {
            self.process_kyc_decision(
                kyc_record.id,
                payload.consumer_id,
                decision,
                payload.risk_score,
                payload.risk_flags,
            ).await?;
        } else {
            // Just update status
            self.update_kyc_status_from_provider_simple(
                kyc_record.id,
                payload.status,
                payload.consumer_id,
            ).await?;
        }
        
        Ok(())
    }
    
    async fn process_kyc_decision(
        &self,
        kyc_record_id: Uuid,
        consumer_id: Uuid,
        decision: KycDecision,
        risk_score: Option<i32>,
        risk_flags: Option<Vec<String>>,
    ) -> Result<(), KycServiceError> {
        match decision.decision {
            KycStatus::Approved => {
                // Update KYC tier and status
                let new_tier = decision.tier.unwrap_or(KycTier::Basic);
                self.repository.update_kyc_tier(kyc_record_id, new_tier).await
                    .map_err(|e| KycServiceError::DatabaseError(e.to_string()))?;
                
                self.repository.update_kyc_status(
                    kyc_record_id,
                    KycStatus::Approved,
                    Some(decision.reason),
                    None,
                ).await.map_err(|e| KycServiceError::DatabaseError(e.to_string()))?;
                
                // Log decision
                self.repository.create_event(
                    consumer_id,
                    Some(kyc_record_id),
                    KycEventType::DecisionMade,
                    Some(format!("KYC approved: {}", decision.reason)),
                    Some(serde_json::to_string(&decision).unwrap_or_default()),
                    Some(serde_json::json!({
                        "decision": "approved",
                        "tier": format!("{:?}", new_tier),
                        "risk_score": risk_score
                    }))
                ).await.map_err(|e| KycServiceError::DatabaseError(e.to_string()))?;
            },
            KycStatus::Rejected => {
                self.repository.update_kyc_status(
                    kyc_record_id,
                    KycStatus::Rejected,
                    Some(decision.reason),
                    None,
                ).await.map_err(|e| KycServiceError::DatabaseError(e.to_string()))?;
                
                // Set resubmission allowed date based on tier
                let kyc_record = self.repository.get_kyc_record_by_consumer(consumer_id).await?
                    .ok_or(KycServiceError::KycRecordNotFound)?;
                
                let tier_def = KycTierRequirements::get_tier_definition(kyc_record.tier);
                let resubmission_date = Utc::now() + Duration::days(tier_def.cooling_off_period_days as i64);
                
                sqlx::query!(
                    "UPDATE kyc_records SET resubmission_allowed_at = $1 WHERE id = $2",
                    resubmission_date,
                    kyc_record_id
                )
                .execute(&self.repository.pool)
                .await
                .map_err(|e| KycServiceError::DatabaseError(e.to_string()))?;
                
                // Log decision
                self.repository.create_event(
                    consumer_id,
                    Some(kyc_record_id),
                    KycEventType::DecisionMade,
                    Some(format!("KYC rejected: {}", decision.reason)),
                    Some(serde_json::to_string(&decision).unwrap_or_default()),
                    Some(serde_json::json!({
                        "decision": "rejected",
                        "resubmission_allowed": resubmission_date.to_rfc3339()
                    }))
                ).await.map_err(|e| KycServiceError::DatabaseError(e.to_string()))?;
            },
            KycStatus::ManualReview => {
                // Add to manual review queue
                self.repository.add_to_manual_review_queue(
                    kyc_record_id,
                    consumer_id,
                    decision.reason,
                    risk_score,
                    risk_flags,
                ).await.map_err(|e| KycServiceError::DatabaseError(e.to_string()))?;
                
                // Update status
                self.repository.update_kyc_status(
                    kyc_record_id,
                    KycStatus::ManualReview,
                    Some(decision.reason),
                    None,
                ).await.map_err(|e| KycServiceError::DatabaseError(e.to_string()))?;
                
                // Log event
                self.repository.create_event(
                    consumer_id,
                    Some(kyc_record_id),
                    KycEventType::ManualReviewAssigned,
                    Some(format!("Added to manual review: {}", decision.reason)),
                    Some(serde_json::to_string(&decision).unwrap_or_default()),
                    Some(serde_json::json!({
                        "risk_score": risk_score,
                        "risk_flags": risk_flags
                    }))
                ).await.map_err(|e| KycServiceError::DatabaseError(e.to_string()))?;
            },
            _ => {
                return Err(KycServiceError::InvalidDecision(decision.decision));
            }
        }
        
        Ok(())
    }
    
    async fn get_session_info(&self, session_id: &str) -> Result<SessionInfo, KycServiceError> {
        // Try cache first
        let cache_key = format!("kyc_session:{}", session_id);
        if let Ok(cached_data) = self.redis.get(&cache_key).await {
            if let Ok(session_data) = serde_json::from_str::<serde_json::Value>(&cached_data) {
                return Ok(SessionInfo {
                    consumer_id: Uuid::parse_str(session_data["consumer_id"].as_str().unwrap()).unwrap(),
                    kyc_record_id: Uuid::parse_str(session_data["kyc_record_id"].as_str().unwrap()).unwrap(),
                    provider: session_data["provider"].as_str().unwrap().to_string(),
                    expires_at: DateTime::parse_from_rfc3339(session_data["expires_at"].as_str().unwrap())
                        .unwrap().with_timezone(&Utc),
                });
            }
        }
        
        // Fallback to database
        let record = sqlx::query!(
            r#"
            SELECT kr.id, kr.consumer_id, kr.verification_provider, kr.expires_at
            FROM kyc_records kr
            WHERE kr.verification_session_id = $1
            ORDER BY kr.created_at DESC
            LIMIT 1
            "#,
            session_id
        )
        .fetch_optional(&self.repository.pool)
        .await
        .map_err(|e| KycServiceError::DatabaseError(e.to_string()))?
        .ok_or(KycServiceError::SessionNotFound)?;
        
        let session_info = SessionInfo {
            consumer_id: record.consumer_id,
            kyc_record_id: record.id,
            provider: record.verification_provider.unwrap_or_default(),
            expires_at: record.expires_at.unwrap_or_else(|| Utc::now() + Duration::days(30)),
        };
        
        // Update cache
        let session_data = serde_json::json!({
            "consumer_id": session_info.consumer_id,
            "kyc_record_id": session_info.kyc_record_id,
            "provider": session_info.provider,
            "expires_at": session_info.expires_at.to_rfc3339()
        });
        
        if let Err(e) = self.redis.setex(&cache_key, &session_data.to_string(), 3600).await {
            warn!("Failed to cache KYC session: {}", e);
        }
        
        Ok(session_info)
    }
    
    fn get_provider(&self, provider_name: &str) -> Result<Arc<dyn KycProvider>, KycServiceError> {
        self.providers.get(provider_name)
            .cloned()
            .ok_or_else(|| KycServiceError::ProviderNotFound(provider_name.to_string()))
    }
    
    async fn update_kyc_status_from_provider(
        &self,
        kyc_record_id: Uuid,
        status_response: &KycStatusResponse,
        consumer_id: Uuid,
    ) -> Result<(), KycServiceError> {
        // Update basic status
        self.repository.update_kyc_status(
            kyc_record_id,
            status_response.status,
            None,
            None,
        ).await.map_err(|e| KycServiceError::DatabaseError(e.to_string()))?;
        
        // Update tier if provided
        if let Some(tier) = status_response.tier {
            self.repository.update_kyc_tier(kyc_record_id, tier).await
                .map_err(|e| KycServiceError::DatabaseError(e.to_string()))?;
        }
        
        // Log status update
        self.repository.create_event(
            consumer_id,
            Some(kyc_record_id),
            KycEventType::StatusUpdated,
            Some(format!("Status updated to {:?}", status_response.status)),
            Some(serde_json::to_string(status_response).unwrap_or_default()),
            None,
        ).await.map_err(|e| KycServiceError::DatabaseError(e.to_string()))?;
        
        Ok(())
    }
    
    async fn update_kyc_status_from_provider_simple(
        &self,
        kyc_record_id: Uuid,
        status: KycStatus,
        consumer_id: Uuid,
    ) -> Result<(), KycServiceError> {
        self.repository.update_kyc_status(
            kyc_record_id,
            status,
            None,
            None,
        ).await.map_err(|e| KycServiceError::DatabaseError(e.to_string()))?;
        
        // Log status update
        self.repository.create_event(
            consumer_id,
            Some(kyc_record_id),
            KycEventType::StatusUpdated,
            Some(format!("Status updated to {:?}", status)),
            None,
            None,
        ).await.map_err(|e| KycServiceError::DatabaseError(e.to_string()))?;
        
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct SessionInfo {
    consumer_id: Uuid,
    kyc_record_id: Uuid,
    provider: String,
    expires_at: DateTime<Utc>,
}

#[derive(Debug, thiserror::Error)]
pub enum KycServiceError {
    #[error("Database error: {0}")]
    DatabaseError(String),
    
    #[error("Provider error: {0}")]
    ProviderError(#[from] KycProviderError),
    
    #[error("Session already active")]
    SessionAlreadyActive,
    
    #[error("Session not found")]
    SessionNotFound,
    
    #[error("Session expired")]
    SessionExpired,
    
    #[error("KYC record not found")]
    KycRecordNotFound,
    
    #[error("Provider not found: {0}")]
    ProviderNotFound(String),
    
    #[error("Configuration error: {0}")]
    ConfigurationError(String),
    
    #[error("Invalid decision: {0:?}")]
    InvalidDecision(KycStatus),
    
    #[error("Webhook signature invalid")]
    WebhookSignatureInvalid,
    
    #[error("Redis error: {0}")]
    RedisError(String),
}

impl From<redis::RedisError> for KycServiceError {
    fn from(error: redis::RedisError) -> Self {
        KycServiceError::RedisError(error.to_string())
    }
}
