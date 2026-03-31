use crate::chains::stellar::client::StellarClient;
use crate::chains::stellar::errors::StellarError;
use crate::database::models::redemption::{
    CreateRedemptionRequest, RedemptionConfig, RedemptionError, RedemptionRequest,
    RedemptionRequestResponse, RedemptionStatusResponse,
};
use crate::database::repositories::redemption_repository::RedemptionRepository;
use crate::services::disbursement_service::{BankValidationResponse, DisbursementService};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{error, info, instrument, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedemptionAuthorizationServiceConfig {
    pub min_redemption_amount: f64,
    pub max_redemption_amount: f64,
    pub required_kyc_tier: String,
    pub enable_kyc_check: bool,
    pub enable_bank_validation: bool,
    pub enable_balance_check: bool,
    pub enable_duplicate_check: bool,
    pub max_daily_redemption_amount: f64,
    pub max_weekly_redemption_amount: f64,
    pub rate_limit_per_hour: u32,
}

impl Default for RedemptionAuthorizationServiceConfig {
    fn default() -> Self {
        Self {
            min_redemption_amount: 1.0,
            max_redemption_amount: 1_000_000.0,
            required_kyc_tier: "TIER_2".to_string(),
            enable_kyc_check: true,
            enable_bank_validation: true,
            enable_balance_check: true,
            enable_duplicate_check: true,
            max_daily_redemption_amount: 10_000_000.0,
            max_weekly_redemption_amount: 50_000_000.0,
            rate_limit_per_hour: 10,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationResult {
    pub is_authorized: bool,
    pub errors: Vec<ValidationError>,
    pub warnings: Vec<String>,
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationError {
    pub field: String,
    pub message: String,
    pub code: String,
    pub severity: String, // "ERROR" | "WARNING"
}

#[async_trait]
pub trait RedemptionAuthorizationService: Send + Sync {
    async fn authorize_redemption_request(
        &self,
        user_id: &str,
        request: &CreateRedemptionRequest,
        context: &RequestContext,
    ) -> Result<AuthorizationResult, RedemptionError>;

    async fn validate_kyc_status(&self, user_id: &str) -> Result<bool, RedemptionError>;
    
    async fn validate_bank_account(&self, bank_code: &str, account_number: &str) -> Result<BankValidationResponse, RedemptionError>;
    
    async fn validate_wallet_balance(&self, wallet_address: &str, amount_cngn: f64) -> Result<bool, RedemptionError>;
    
    async fn check_duplicate_requests(&self, user_id: &str, request: &CreateRedemptionRequest) -> Result<bool, RedemptionError>;
    
    async fn check_rate_limits(&self, user_id: &str) -> Result<bool, RedemptionError>;
    
    async fn check_daily_limits(&self, user_id: &str, amount: f64) -> Result<bool, RedemptionError>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestContext {
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub request_id: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

pub struct StellarRedemptionAuthorizationService {
    repository: Arc<dyn RedemptionRepository>,
    stellar_client: StellarClient,
    disbursement_service: Arc<dyn DisbursementService>,
    config: RedemptionAuthorizationServiceConfig,
}

impl StellarRedemptionAuthorizationService {
    pub fn new(
        repository: Arc<dyn RedemptionRepository>,
        stellar_client: StellarClient,
        disbursement_service: Arc<dyn DisbursementService>,
        config: RedemptionAuthorizationServiceConfig,
    ) -> Self {
        Self {
            repository,
            stellar_client,
            disbursement_service,
            config,
        }
    }

    fn generate_redemption_id(&self) -> String {
        format!("RED-{}", uuid::Uuid::new_v4().to_string().to_uppercase()[..8].to_string())
    }

    async fn get_exchange_rate(&self) -> Result<f64, RedemptionError> {
        // In production, this would fetch from an exchange rate service
        // For now, return a mock rate
        Ok(750.0) // 1 cNGN = 750 NGN
    }

    async fn get_user_kyc_tier(&self, user_id: &str) -> Result<Option<String>, RedemptionError> {
        // This would integrate with the identity service
        // For now, return mock data
        if user_id == "mock-user-tier-2" {
            Ok(Some("TIER_2".to_string()))
        } else if user_id == "mock-user-tier-1" {
            Ok(Some("TIER_1".to_string()))
        } else {
            Ok(Some("TIER_2".to_string())) // Default to TIER_2 for testing
        }
    }

    async fn get_user_redemption_volume(&self, user_id: &str, period: &str) -> Result<f64, RedemptionError> {
        // This would calculate the user's redemption volume for the specified period
        // For now, return mock data
        match period {
            "daily" => Ok(1_000_000.0),
            "weekly" => Ok(5_000_000.0),
            _ => Ok(0.0),
        }
    }

    async fn get_user_request_count(&self, user_id: &str, hours: u32) -> Result<u32, RedemptionError> {
        // This would count the user's requests in the last N hours
        // For now, return mock data
        Ok(2)
    }
}

#[async_trait]
impl RedemptionAuthorizationService for StellarRedemptionAuthorizationService {
    #[instrument(skip(self), fields(user_id = %user_id, amount_cngn = %request.amount_cngn))]
    async fn authorize_redemption_request(
        &self,
        user_id: &str,
        request: &CreateRedemptionRequest,
        context: &RequestContext,
    ) -> Result<AuthorizationResult, RedemptionError> {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        let mut metadata = serde_json::json!({});

        // 1. Basic amount validation
        if request.amount_cngn < self.config.min_redemption_amount {
            errors.push(ValidationError {
                field: "amount_cngn".to_string(),
                message: format!("Amount {} is below minimum {}", request.amount_cngn, self.config.min_redemption_amount),
                code: "MIN_AMOUNT_VIOLATION".to_string(),
                severity: "ERROR".to_string(),
            });
        }

        if request.amount_cngn > self.config.max_redemption_amount {
            errors.push(ValidationError {
                field: "amount_cngn".to_string(),
                message: format!("Amount {} exceeds maximum {}", request.amount_cngn, self.config.max_redemption_amount),
                code: "MAX_AMOUNT_VIOLATION".to_string(),
                severity: "ERROR".to_string(),
            });
        }

        // 2. KYC validation
        let kyc_valid = if self.config.enable_kyc_check {
            match self.validate_kyc_status(user_id).await {
                Ok(valid) => {
                    if !valid {
                        errors.push(ValidationError {
                            field: "kyc_status".to_string(),
                            message: "KYC verification required or incomplete".to_string(),
                            code: "KYC_REQUIRED".to_string(),
                            severity: "ERROR".to_string(),
                        });
                    }
                    valid
                }
                Err(e) => {
                    errors.push(ValidationError {
                        field: "kyc_status".to_string(),
                        message: format!("KYC check failed: {}", e),
                        code: "KYC_CHECK_ERROR".to_string(),
                        severity: "ERROR".to_string(),
                    });
                    false
                }
            }
        } else {
            true
        };

        // 3. Bank account validation
        let bank_valid = if self.config.enable_bank_validation {
            match self.validate_bank_account(&request.bank_code, &request.account_number).await {
                Ok(validation) => {
                    if !validation.is_valid {
                        errors.push(ValidationError {
                            field: "bank_account".to_string(),
                            message: "Invalid bank account details".to_string(),
                            code: "INVALID_BANK_ACCOUNT".to_string(),
                            severity: "ERROR".to_string(),
                        });
                    }
                    validation.is_valid
                }
                Err(e) => {
                    errors.push(ValidationError {
                        field: "bank_account".to_string(),
                        message: format!("Bank validation failed: {}", e),
                        code: "BANK_VALIDATION_ERROR".to_string(),
                        severity: "ERROR".to_string(),
                    });
                    false
                }
            }
        } else {
            true
        };

        // 4. Rate limiting
        let rate_limit_ok = if self.config.rate_limit_per_hour > 0 {
            match self.check_rate_limits(user_id).await {
                Ok(ok) => {
                    if !ok {
                        errors.push(ValidationError {
                            field: "rate_limit".to_string(),
                            message: format!("Rate limit exceeded: {} requests per hour", self.config.rate_limit_per_hour),
                            code: "RATE_LIMIT_EXCEEDED".to_string(),
                            severity: "ERROR".to_string(),
                        });
                    }
                    ok
                }
                Err(e) => {
                    warnings.push(format!("Rate limit check failed: {}", e));
                    true // Don't block on rate limit errors
                }
            }
        } else {
            true
        };

        // 5. Daily limits
        let daily_limit_ok = match self.check_daily_limits(user_id, request.amount_cngn).await {
            Ok(ok) => {
                if !ok {
                    errors.push(ValidationError {
                        field: "daily_limit".to_string(),
                        message: format!("Daily limit exceeded: {}", self.config.max_daily_redemption_amount),
                        code: "DAILY_LIMIT_EXCEEDED".to_string(),
                        severity: "ERROR".to_string(),
                    });
                }
                ok
            }
            Err(e) => {
                warnings.push(format!("Daily limit check failed: {}", e));
                true // Don't block on limit check errors
            }
        };

        // 6. Duplicate check
        let duplicate_ok = if self.config.enable_duplicate_check {
            match self.check_duplicate_requests(user_id, request).await {
                Ok(is_duplicate) => {
                    if is_duplicate {
                        errors.push(ValidationError {
                            field: "duplicate_request".to_string(),
                            message: "Duplicate redemption request detected".to_string(),
                            code: "DUPLICATE_REQUEST".to_string(),
                            severity: "ERROR".to_string(),
                        });
                    }
                    !is_duplicate
                }
                Err(e) => {
                    warnings.push(format!("Duplicate check failed: {}", e));
                    true // Don't block on duplicate check errors
                }
            }
        } else {
            true
        };

        // Determine authorization result
        let is_authorized = errors.is_empty() 
            && kyc_valid 
            && bank_valid 
            && rate_limit_ok 
            && daily_limit_ok 
            && duplicate_ok;

        // Add metadata
        metadata["validation_checks"] = serde_json::json!({
            "kyc_check_enabled": self.config.enable_kyc_check,
            "kyc_valid": kyc_valid,
            "bank_validation_enabled": self.config.enable_bank_validation,
            "bank_valid": bank_valid,
            "rate_limit_check": rate_limit_ok,
            "daily_limit_check": daily_limit_ok,
            "duplicate_check": duplicate_ok,
        });

        metadata["request_context"] = serde_json::json!({
            "ip_address": context.ip_address,
            "request_id": context.request_id,
            "timestamp": context.timestamp,
        });

        if is_authorized {
            info!(
                user_id = %user_id,
                amount_cngn = %request.amount_cngn,
                "Redemption request authorized"
            );
        } else {
            warn!(
                user_id = %user_id,
                amount_cngn = %request.amount_cngn,
                error_count = %errors.len(),
                "Redemption request authorization failed"
            );
        }

        Ok(AuthorizationResult {
            is_authorized,
            errors,
            warnings,
            metadata,
        })
    }

    #[instrument(skip(self), fields(user_id = %user_id))]
    async fn validate_kyc_status(&self, user_id: &str) -> Result<bool, RedemptionError> {
        let kyc_tier = self.get_user_kyc_tier(user_id).await?;
        
        match kyc_tier {
            Some(tier) => {
                let is_valid = match tier.as_str() {
                    "TIER_2" | "TIER_3" => true,
                    "TIER_1" => false,
                    _ => false,
                };

                info!(
                    user_id = %user_id,
                    kyc_tier = %tier,
                    is_valid = %is_valid,
                    required_tier = %self.config.required_kyc_tier,
                    "KYC validation completed"
                );

                Ok(is_valid)
            }
            None => {
                warn!(user_id = %user_id, "No KYC tier found for user");
                Ok(false)
            }
        }
    }

    #[instrument(skip(self), fields(bank_code = %bank_code, account_number = %account_number))]
    async fn validate_bank_account(&self, bank_code: &str, account_number: &str) -> Result<BankValidationResponse, RedemptionError> {
        self.disbursement_service
            .validate_bank_account(bank_code, account_number)
            .await
            .map_err(|e| RedemptionError::ValidationError(format!("Bank validation failed: {}", e)))
    }

    #[instrument(skip(self), fields(wallet_address = %wallet_address, amount_cngn = %amount_cngn))]
    async fn validate_wallet_balance(&self, wallet_address: &str, amount_cngn: f64) -> Result<bool, RedemptionError> {
        match self.stellar_client.get_asset_balance(wallet_address, "cNGN", None).await {
            Ok(Some(balance_str)) => {
                match balance_str.parse::<f64>() {
                    Ok(balance) => {
                        let has_sufficient_balance = balance >= amount_cngn;
                        info!(
                            wallet_address = %wallet_address,
                            balance = %balance,
                            required = %amount_cngn,
                            has_sufficient_balance = %has_sufficient_balance,
                            "Wallet balance validation completed"
                        );
                        Ok(has_sufficient_balance)
                    }
                    Err(e) => {
                        error!(
                            wallet_address = %wallet_address,
                            balance = %balance_str,
                            error = %e,
                            "Failed to parse wallet balance"
                        );
                        Err(RedemptionError::ValidationError(format!("Invalid balance format: {}", e)))
                    }
                }
            }
            Ok(None) => {
                warn!(wallet_address = %wallet_address, "No cNGN balance found");
                Ok(false)
            }
            Err(e) => {
                error!(
                    wallet_address = %wallet_address,
                    error = %e,
                    "Failed to get wallet balance"
                );
                Err(RedemptionError::SystemError(format!("Balance check failed: {}", e)))
            }
        }
    }

    #[instrument(skip(self), fields(user_id = %user_id))]
    async fn check_duplicate_requests(&self, user_id: &str, request: &CreateRedemptionRequest) -> Result<bool, RedemptionError> {
        let user_uuid = uuid::Uuid::parse_str(user_id)
            .map_err(|_| RedemptionError::ValidationError("Invalid user ID format".to_string()))?;

        let bank_account = format!("{}-{}", request.bank_code, request.account_number);
        
        // This would need to be implemented in the repository
        // let is_duplicate = self.repository.check_duplicate_redemption(&user_uuid, request.amount_cngn, &bank_account).await?;
        
        // For now, return false (no duplicate)
        Ok(false)
    }

    #[instrument(skip(self), fields(user_id = %user_id))]
    async fn check_rate_limits(&self, user_id: &str) -> Result<bool, RedemptionError> {
        let request_count = self.get_user_request_count(user_id, 1).await?;
        let within_limit = request_count < self.config.rate_limit_per_hour;
        
        info!(
            user_id = %user_id,
            request_count = %request_count,
            limit = %self.config.rate_limit_per_hour,
            within_limit = %within_limit,
            "Rate limit check completed"
        );
        
        Ok(within_limit)
    }

    #[instrument(skip(self), fields(user_id = %user_id, amount = %amount))]
    async fn check_daily_limits(&self, user_id: &str, amount: f64) -> Result<bool, RedemptionError> {
        let daily_volume = self.get_user_redemption_volume(user_id, "daily").await?;
        let new_total = daily_volume + amount;
        let within_limit = new_total <= self.config.max_daily_redemption_amount;
        
        info!(
            user_id = %user_id,
            current_daily_volume = %daily_volume,
            request_amount = %amount,
            new_total = %new_total,
            limit = %self.config.max_daily_redemption_amount,
            within_limit = %within_limit,
            "Daily limit check completed"
        );
        
        Ok(within_limit)
    }
}

#[async_trait]
pub trait RedemptionRequestService: Send + Sync {
    async fn submit_redemption_request(
        &self,
        user_id: &str,
        request: CreateRedemptionRequest,
        context: RequestContext,
    ) -> Result<RedemptionRequestResponse, RedemptionError>;

    async fn get_redemption_status(&self, redemption_id: &str, user_id: &str) -> Result<RedemptionStatusResponse, RedemptionError>;

    async fn cancel_redemption_request(&self, redemption_id: &str, user_id: &str) -> Result<bool, RedemptionError>;

    async fn get_user_redemption_history(&self, user_id: &str, limit: Option<i32>) -> Result<Vec<RedemptionStatusResponse>, RedemptionError>;
}

pub struct StellarRedemptionRequestService {
    authorization_service: Arc<dyn RedemptionAuthorizationService>,
    repository: Arc<dyn RedemptionRepository>,
    config: RedemptionConfig,
}

impl StellarRedemptionRequestService {
    pub fn new(
        authorization_service: Arc<dyn RedemptionAuthorizationService>,
        repository: Arc<dyn RedemptionRepository>,
        config: RedemptionConfig,
    ) -> Self {
        Self {
            authorization_service,
            repository,
            config,
        }
    }

    async fn create_redemption_request_record(
        &self,
        user_id: &str,
        request: CreateRedemptionRequest,
        exchange_rate: f64,
        context: &RequestContext,
    ) -> Result<RedemptionRequest, RedemptionError> {
        let user_uuid = uuid::Uuid::parse_str(user_id)
            .map_err(|_| RedemptionError::ValidationError("Invalid user ID format".to_string()))?;

        let redemption_id = format!("RED-{}", uuid::Uuid::new_v4().to_string().to_uppercase()[..8].to_string());
        let amount_ngn = request.amount_cngn * exchange_rate;

        let redemption_request = RedemptionRequest {
            id: uuid::Uuid::new_v4(),
            redemption_id: redemption_id.clone(),
            user_id: user_uuid,
            wallet_address: "".to_string(), // This would come from user's wallet
            amount_cngn: request.amount_cngn,
            amount_ngn,
            exchange_rate,
            bank_code: request.bank_code,
            bank_name: request.bank_name,
            account_number: request.account_number,
            account_name: request.account_name,
            account_name_verified: false, // Would be validated during authorization
            status: "REDEMPTION_REQUESTED".to_string(),
            previous_status: None,
            burn_transaction_hash: None,
            batch_id: None,
            kyc_tier: None,
            ip_address: context.ip_address,
            user_agent: context.user_agent,
            metadata: serde_json::json!({
                "request_context": context,
                "config": self.config,
            }),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            completed_at: None,
        };

        self.repository
            .create_redemption_request(&redemption_request)
            .await
            .map_err(|e| RedemptionError::SystemError(format!("Failed to create redemption request: {}", e)))?;

        Ok(redemption_request)
    }

    fn estimate_completion_time(&self, current_status: &str) -> Option<chrono::DateTime<chrono::Utc>> {
        let now = chrono::Utc::now();
        let estimated_minutes = match current_status {
            "REDEMPTION_REQUESTED" => Some(15),
            "KYC_VERIFICATION" => Some(10),
            "BALANCE_VERIFICATION" => Some(5),
            "BANK_VALIDATION" => Some(5),
            "TOKENS_LOCKED" => Some(10),
            "BURNING_IN_PROGRESS" => Some(5),
            "BURNED_CONFIRMED" => Some(15),
            "FIAT_DISBURSEMENT_PENDING" => Some(30),
            _ => None,
        };

        estimated_minutes.map(|minutes| now + chrono::Duration::minutes(minutes))
    }
}

#[async_trait]
impl RedemptionRequestService for StellarRedemptionRequestService {
    #[instrument(skip(self), fields(user_id = %user_id, amount_cngn = %request.amount_cngn))]
    async fn submit_redemption_request(
        &self,
        user_id: &str,
        request: CreateRedemptionRequest,
        context: RequestContext,
    ) -> Result<RedemptionRequestResponse, RedemptionError> {
        // Step 1: Authorize the request
        let authorization_result = self
            .authorization_service
            .authorize_redemption_request(user_id, &request, &context)
            .await?;

        if !authorization_result.is_authorized {
            let error_messages: Vec<String> = authorization_result
                .errors
                .iter()
                .map(|e| e.message.clone())
                .collect();
            
            return Err(RedemptionError::ValidationError(format!(
                "Authorization failed: {}",
                error_messages.join("; ")
            )));
        }

        // Step 2: Get exchange rate
        let exchange_rate = self.authorization_service.get_exchange_rate().await?;

        // Step 3: Create redemption request record
        let redemption_request = self
            .create_redemption_request_record(user_id, request, exchange_rate, &context)
            .await?;

        // Step 4: Log the request
        info!(
            redemption_id = %redemption_request.redemption_id,
            user_id = %user_id,
            amount_cngn = %redemption_request.amount_cngn,
            amount_ngn = %redemption_request.amount_ngn,
            "Redemption request submitted successfully"
        );

        // Step 5: Return response
        let estimated_completion = self.estimate_completion_time(&redemption_request.status);

        Ok(RedemptionRequestResponse {
            redemption_id: redemption_request.redemption_id,
            status: redemption_request.status,
            amount_cngn: redemption_request.amount_cngn,
            amount_ngn: redemption_request.amount_ngn,
            exchange_rate: redemption_request.exchange_rate,
            bank_details: crate::database::models::redemption::BankDetails {
                bank_code: redemption_request.bank_code,
                bank_name: redemption_request.bank_name,
                account_number: redemption_request.account_number,
                account_name: redemption_request.account_name,
                account_name_verified: redemption_request.account_name_verified,
            },
            created_at: redemption_request.created_at,
            estimated_completion_time: estimated_completion,
        })
    }

    #[instrument(skip(self), fields(redemption_id = %redemption_id, user_id = %user_id))]
    async fn get_redemption_status(&self, redemption_id: &str, user_id: &str) -> Result<RedemptionStatusResponse, RedemptionError> {
        let redemption_request = self
            .repository
            .get_redemption_request(redemption_id)
            .await
            .map_err(|e| RedemptionError::SystemError(format!("Failed to get redemption request: {}", e)))?;

        // Verify user ownership
        if redemption_request.user_id.to_string() != user_id {
            return Err(RedemptionError::ValidationError("Unauthorized access to redemption request".to_string()));
        }

        // Get disbursement status if available
        let disbursement_status = if let Ok(disbursement) = self.repository.get_fiat_disbursement(&redemption_request.id).await {
            Some(disbursement.status)
        } else {
            None
        };

        let provider_reference = if let Ok(disbursement) = self.repository.get_fiat_disbursement(&redemption_request.id).await {
            disbursement.provider_reference
        } else {
            None
        };

        Ok(RedemptionStatusResponse {
            redemption_id: redemption_request.redemption_id,
            status: redemption_request.status,
            previous_status: redemption_request.previous_status,
            burn_transaction_hash: redemption_request.burn_transaction_hash,
            disbursement_status,
            provider_reference,
            created_at: redemption_request.created_at,
            updated_at: redemption_request.updated_at,
            completed_at: redemption_request.completed_at,
            error_message: None, // Would be populated from burn transaction errors
        })
    }

    #[instrument(skip(self), fields(redemption_id = %redemption_id, user_id = %user_id))]
    async fn cancel_redemption_request(&self, redemption_id: &str, user_id: &str) -> Result<bool, RedemptionError> {
        let redemption_request = self
            .repository
            .get_redemption_request(redemption_id)
            .await
            .map_err(|e| RedemptionError::SystemError(format!("Failed to get redemption request: {}", e)))?;

        // Verify user ownership
        if redemption_request.user_id.to_string() != user_id {
            return Err(RedemptionError::ValidationError("Unauthorized access to redemption request".to_string()));
        }

        // Check if request can be cancelled (only if not yet processed)
        match redemption_request.status.as_str() {
            "REDEMPTION_REQUESTED" | "KYC_VERIFICATION" | "BALANCE_VERIFICATION" | "BANK_VALIDATION" => {
                self.repository
                    .update_redemption_status(redemption_id, "CANCELLED")
                    .await
                    .map_err(|e| RedemptionError::SystemError(format!("Failed to cancel redemption request: {}", e)))?;

                info!(
                    redemption_id = %redemption_id,
                    user_id = %user_id,
                    "Redemption request cancelled successfully"
                );

                Ok(true)
            }
            _ => {
                warn!(
                    redemption_id = %redemption_id,
                    status = %redemption_request.status,
                    "Cannot cancel redemption request - already processed"
                );
                Err(RedemptionError::ValidationError("Cannot cancel redemption request - already processed".to_string()))
            }
        }
    }

    #[instrument(skip(self), fields(user_id = %user_id))]
    async fn get_user_redemption_history(&self, user_id: &str, limit: Option<i32>) -> Result<Vec<RedemptionStatusResponse>, RedemptionError> {
        let user_uuid = uuid::Uuid::parse_str(user_id)
            .map_err(|_| RedemptionError::ValidationError("Invalid user ID format".to_string()))?;

        let redemption_requests = self
            .repository
            .get_user_redemption_requests(&user_uuid, limit.map(|l| l as i64))
            .await
            .map_err(|e| RedemptionError::SystemError(format!("Failed to get user redemption history: {}", e)))?;

        let mut history = Vec::new();

        for request in redemption_requests {
            let disbursement_status = if let Ok(disbursement) = self.repository.get_fiat_disbursement(&request.id).await {
                Some(disbursement.status)
            } else {
                None
            };

            let provider_reference = if let Ok(disbursement) = self.repository.get_fiat_disbursement(&request.id).await {
                disbursement.provider_reference
            } else {
                None
            };

            history.push(RedemptionStatusResponse {
                redemption_id: request.redemption_id,
                status: request.status,
                previous_status: request.previous_status,
                burn_transaction_hash: request.burn_transaction_hash,
                disbursement_status,
                provider_reference,
                created_at: request.created_at,
                updated_at: request.updated_at,
                completed_at: request.completed_at,
                error_message: None,
            });
        }

        Ok(history)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_authorization_service_config_default() {
        let config = RedemptionAuthorizationServiceConfig::default();
        assert_eq!(config.min_redemption_amount, 1.0);
        assert_eq!(config.max_redemption_amount, 1_000_000.0);
        assert_eq!(config.required_kyc_tier, "TIER_2");
        assert!(config.enable_kyc_check);
        assert!(config.enable_bank_validation);
        assert!(config.enable_balance_check);
        assert!(config.enable_duplicate_check);
        assert_eq!(config.max_daily_redemption_amount, 10_000_000.0);
        assert_eq!(config.max_weekly_redemption_amount, 50_000_000.0);
        assert_eq!(config.rate_limit_per_hour, 10);
    }

    #[test]
    fn test_request_context_creation() {
        let context = RequestContext {
            ip_address: Some("192.168.1.1".to_string()),
            user_agent: Some("Mozilla/5.0".to_string()),
            request_id: "req-123".to_string(),
            timestamp: chrono::Utc::now(),
        };
        
        assert_eq!(context.request_id, "req-123");
        assert!(context.ip_address.is_some());
        assert!(context.user_agent.is_some());
    }
}
