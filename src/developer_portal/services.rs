use super::models::*;
use super::repositories::{DeveloperAccountRepository, DeveloperApplicationRepository, ApiKeyRepository};
use crate::database::error::DatabaseError;
use crate::error::AppError;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use argon2::password_hash::{rand_core::OsRng, SaltString};
use chrono::{DateTime, Duration, Utc};
use rand::Rng;
use serde_json::json;
use std::sync::Arc;
use tracing::{error, info, warn};
use uuid::Uuid;

const EMAIL_VERIFICATION_TOKEN_LENGTH: usize = 32;
const EMAIL_VERIFICATION_EXPIRY_HOURS: i64 = 24;
const BLOCKED_COUNTRIES: &[&str] = &["XX", "ZZ"]; // Add actual blocked country codes

#[derive(Clone)]
pub struct DeveloperService {
    pub developer_account_repo: DeveloperAccountRepository,
    pub application_repo: DeveloperApplicationRepository,
    pub api_key_repo: ApiKeyRepository,
}

impl DeveloperService {
    pub fn new(
        developer_account_repo: DeveloperAccountRepository,
        application_repo: DeveloperApplicationRepository,
        api_key_repo: ApiKeyRepository,
    ) -> Self {
        Self {
            developer_account_repo,
            application_repo,
            api_key_repo,
        }
    }

    pub async fn register_developer(
        &self,
        request: CreateDeveloperAccountRequest,
    ) -> Result<DeveloperAccount, DeveloperPortalError> {
        // Check if email is already registered
        if let Some(_) = self.developer_account_repo.find_by_email(&request.email).await? {
            return Err(DeveloperPortalError::EmailAlreadyRegistered);
        }

        // Check geo-restrictions
        if BLOCKED_COUNTRIES.contains(&request.country.as_str()) {
            return Err(DeveloperPortalError::GeoRestrictedCountry);
        }

        // Generate email verification token
        let verification_token = self.generate_verification_token();
        let verification_expires_at = Utc::now() + Duration::hours(EMAIL_VERIFICATION_EXPIRY_HOURS);

        // Create developer account
        let account = self
            .developer_account_repo
            .create(request, Some(verification_token.clone()), Some(verification_expires_at))
            .await?;

        // TODO: Send verification email
        info!(
            "Developer account created: {} - verification token: {}",
            account.email, verification_token
        );

        Ok(account)
    }

    pub async fn verify_email(&self, token: &str) -> Result<DeveloperAccount, DeveloperPortalError> {
        // Find account by verification token
        let account = self
            .developer_account_repo
            .find_by_verification_token(token)
            .await?
            .ok_or(DeveloperPortalError::InvalidEmailVerificationToken)?;

        // Check if token has expired
        if let Some(expires_at) = account.email_verification_expires_at {
            if expires_at < Utc::now() {
                return Err(DeveloperPortalError::EmailVerificationTokenExpired);
            }
        } else {
            return Err(DeveloperPortalError::InvalidEmailVerificationToken);
        }

        // Verify email and grant sandbox access
        let verified_account = self
            .developer_account_repo
            .verify_email(account.id)
            .await?;

        info!("Email verified for developer account: {}", verified_account.email);

        Ok(verified_account)
    }

    pub async fn submit_identity_verification(
        &self,
        account_id: Uuid,
        request: IdentityVerificationRequest,
    ) -> Result<DeveloperAccount, DeveloperPortalError> {
        // Check if account exists and is verified
        let account = self
            .developer_account_repo
            .find_by_id(account_id)
            .await?
            .ok_or(DeveloperPortalError::AccountNotFound)?;

        if !account.email_verified {
            return Err(DeveloperPortalError::AccountNotFound);
        }

        // Check if identity verification is already submitted
        if account.identity_verification_status != "unverified" {
            return Err(DeveloperPortalError::IdentityVerificationAlreadySubmitted);
        }

        // Submit identity verification
        let updated_account = self
            .developer_account_repo
            .update_identity_verification(account_id, request)
            .await?;

        // TODO: Integrate with KYC provider
        info!("Identity verification submitted for account: {}", account.email);

        Ok(updated_account)
    }

    pub async fn approve_identity_verification(&self, account_id: Uuid) -> Result<DeveloperAccount, DeveloperPortalError> {
        let account = self
            .developer_account_repo
            .approve_identity_verification(account_id)
            .await?;

        info!("Identity verification approved for account: {}", account.email);

        Ok(account)
    }

    pub async fn reject_identity_verification(&self, account_id: Uuid) -> Result<DeveloperAccount, DeveloperPortalError> {
        let account = self
            .developer_account_repo
            .reject_identity_verification(account_id)
            .await?;

        warn!("Identity verification rejected for account: {}", account.email);

        Ok(account)
    }

    pub async fn create_application(
        &self,
        developer_account_id: Uuid,
        request: CreateApplicationRequest,
    ) -> Result<DeveloperApplication, DeveloperPortalError> {
        // Check if developer account exists and is active
        let account = self
            .developer_account_repo
            .find_by_id(developer_account_id)
            .await?
            .ok_or(DeveloperPortalError::AccountNotFound)?;

        if account.status_code != "verified" && account.status_code != "active" {
            return Err(DeveloperPortalError::AccountNotFound);
        }

        // Check application limit
        let tier = self
            .developer_account_repo
            .get_access_tier(&account.access_tier_code)
            .await?
            .ok_or(DeveloperPortalError::AccessTierNotFound)?;

        let current_app_count = self
            .developer_account_repo
            .get_application_count(developer_account_id)
            .await?;

        if current_app_count >= tier.max_applications as i64 {
            return Err(DeveloperPortalError::MaximumApplicationsLimitReached);
        }

        // Create application
        let application = self
            .application_repo
            .create(developer_account_id, request)
            .await?;

        info!(
            "Application created: {} for developer: {}",
            application.name, account.email
        );

        Ok(application)
    }

    pub async fn get_applications(
        &self,
        developer_account_id: Uuid,
    ) -> Result<Vec<DeveloperApplication>, DeveloperPortalError> {
        let applications = self
            .application_repo
            .find_by_developer_account(developer_account_id)
            .await?;

        Ok(applications)
    }

    pub async fn get_application(
        &self,
        application_id: Uuid,
    ) -> Result<DeveloperApplication, DeveloperPortalError> {
        let application = self
            .application_repo
            .find_by_id(application_id)
            .await?
            .ok_or(DeveloperPortalError::ApplicationNotFound)?;

        Ok(application)
    }

    pub async fn update_application(
        &self,
        application_id: Uuid,
        request: UpdateApplicationRequest,
    ) -> Result<DeveloperApplication, DeveloperPortalError> {
        let application = self
            .application_repo
            .update(application_id, request)
            .await?;

        info!("Application updated: {}", application.name);

        Ok(application)
    }

    pub async fn delete_application(&self, application_id: Uuid) -> Result<(), DeveloperPortalError> {
        // Revoke all API keys for this application
        let application = self
            .application_repo
            .find_by_id(application_id)
            .await?
            .ok_or(DeveloperPortalError::ApplicationNotFound)?;

        // Revoke sandbox credentials
        self.api_key_repo
            .revoke_by_application(application_id, "sandbox")
            .await?;

        // Revoke production credentials
        self.api_key_repo
            .revoke_by_application(application_id, "production")
            .await?;

        // Soft delete application
        self.application_repo.soft_delete(application_id).await?;

        info!("Application deleted: {}", application.name);

        Ok(())
    }

    pub async fn create_api_key(
        &self,
        application_id: Uuid,
        request: CreateApiKeyRequest,
    ) -> Result<(ApiKey, String), DeveloperPortalError> {
        // Validate environment
        if request.environment != "sandbox" && request.environment != "production" {
            return Err(DeveloperPortalError::InvalidEnvironment);
        }

        // Check if application exists
        let application = self
            .application_repo
            .find_by_id(application_id)
            .await?
            .ok_or(DeveloperPortalError::ApplicationNotFound)?;

        // Check if production access is allowed
        if request.environment == "production" {
            let account = self
                .developer_account_repo
                .find_by_id(application.developer_account_id)
                .await?
                .ok_or(DeveloperPortalError::AccountNotFound)?;

            if account.access_tier_code == "sandbox" {
                return Err(DeveloperPortalError::IdentityVerificationRequired);
            }
        }

        // Generate API key
        let raw_key = self.generate_api_key();
        let key_prefix = &raw_key[..8];
        let key_hash = self.hash_api_key(&raw_key)?;

        // Create API key record
        let api_key = self
            .api_key_repo
            .create(application_id, request, key_prefix, &key_hash)
            .await?;

        info!(
            "API key created: {} for application: {}",
            api_key.key_name, application.name
        );

        Ok((api_key, raw_key))
    }

    pub async fn get_api_keys(&self, application_id: Uuid) -> Result<Vec<ApiKey>, DeveloperPortalError> {
        let api_keys = self.api_key_repo.find_by_application(application_id).await?;
        Ok(api_keys)
    }

    pub async fn revoke_api_key(&self, api_key_id: Uuid) -> Result<(), DeveloperPortalError> {
        self.api_key_repo.revoke(api_key_id).await?;
        info!("API key revoked: {}", api_key_id);
        Ok(())
    }

    pub async fn validate_api_key(&self, raw_key: &str) -> Result<Option<ApiKey>, DeveloperPortalError> {
        let key_hash = self.hash_api_key(raw_key)?;
        let api_key = self.api_key_repo.find_by_key_hash(&key_hash).await?;

        if let Some(ref key) = api_key {
            // Check if key has expired
            if let Some(expires_at) = key.expires_at {
                if expires_at < Utc::now() {
                    return Ok(None);
                }
            }
        }

        Ok(api_key)
    }

    pub async fn update_api_key_usage(&self, api_key_id: Uuid) -> Result<(), DeveloperPortalError> {
        self.api_key_repo.update_usage(api_key_id).await?;
        Ok(())
    }

    pub async fn suspend_account(&self, account_id: Uuid, reason: &str) -> Result<DeveloperAccount, DeveloperPortalError> {
        let account = self
            .developer_account_repo
            .suspend(account_id, reason)
            .await?;

        // Revoke all API keys for this account's applications
        let applications = self
            .application_repo
            .find_by_developer_account(account_id)
            .await?;

        for application in applications {
            self.api_key_repo
                .revoke_by_application(application.id, "sandbox")
                .await?;
            self.api_key_repo
                .revoke_by_application(application.id, "production")
                .await?;
        }

        warn!("Account suspended: {} - reason: {}", account.email, reason);

        Ok(account)
    }

    pub async fn reinstate_account(&self, account_id: Uuid) -> Result<DeveloperAccount, DeveloperPortalError> {
        let account = self
            .developer_account_repo
            .reinstate(account_id)
            .await?;

        info!("Account reinstated: {}", account.email);

        Ok(account)
    }

    pub async fn upgrade_to_standard_tier(&self, account_id: Uuid) -> Result<DeveloperAccount, DeveloperPortalError> {
        let account = self
            .developer_account_repo
            .upgrade_to_standard_tier(account_id)
            .await?;

        info!("Account upgraded to standard tier: {}", account.email);

        Ok(account)
    }

    pub async fn upgrade_to_partner_tier(&self, account_id: Uuid) -> Result<DeveloperAccount, DeveloperPortalError> {
        let account = self
            .developer_account_repo
            .upgrade_to_partner_tier(account_id)
            .await?;

        info!("Account upgraded to partner tier: {}", account.email);

        Ok(account)
    }

    pub async fn get_developer_account(&self, account_id: Uuid) -> Result<DeveloperAccount, DeveloperPortalError> {
        let account = self
            .developer_account_repo
            .find_by_id(account_id)
            .await?
            .ok_or(DeveloperPortalError::AccountNotFound)?;

        Ok(account)
    }

    pub async fn update_developer_account(
        &self,
        account_id: Uuid,
        request: UpdateDeveloperAccountRequest,
    ) -> Result<DeveloperAccount, DeveloperPortalError> {
        let account = self
            .developer_account_repo
            .update(account_id, request)
            .await?;

        info!("Developer account updated: {}", account.email);

        Ok(account)
    }

    pub async fn list_developer_accounts_for_admin(
        &self,
        page: i64,
        per_page: i64,
    ) -> Result<AdminDeveloperAccountList, DeveloperPortalError> {
        let accounts = self
            .developer_account_repo
            .list_for_admin(page, per_page)
            .await?;

        Ok(accounts)
    }

    /// Returns aggregated usage statistics for an application over a configurable time window.
    pub async fn get_usage_statistics(
        &self,
        application_id: Uuid,
        time_range: Option<&str>,
        start_date: Option<DateTime<Utc>>,
        end_date: Option<DateTime<Utc>>,
        environment: Option<&str>,
    ) -> Result<ApplicationUsageSummary, DeveloperPortalError> {
        let application = self
            .application_repo
            .find_by_id(application_id)
            .await?
            .ok_or(DeveloperPortalError::ApplicationNotFound)?;

        let (start, end) = self.resolve_time_range(time_range, start_date, end_date);

        let metrics = self
            .application_repo
            .get_usage_metrics(application_id, start, end, environment)
            .await?;

        let endpoint_breakdown = self
            .application_repo
            .get_endpoint_breakdown(application_id, start, end, environment)
            .await?;

        let time_series_data = self
            .application_repo
            .get_time_series(application_id, start, end, environment, time_range)
            .await?;

        Ok(ApplicationUsageSummary {
            application_id,
            application_name: application.name,
            environment: environment.unwrap_or("all").to_string(),
            metrics,
            endpoint_breakdown,
            time_series_data,
        })
    }

    fn resolve_time_range(
        &self,
        time_range: Option<&str>,
        start_date: Option<DateTime<Utc>>,
        end_date: Option<DateTime<Utc>>,
    ) -> (DateTime<Utc>, DateTime<Utc>) {
        let now = Utc::now();
        match time_range {
            Some("daily") => (now - Duration::days(1), now),
            Some("weekly") => (now - Duration::days(7), now),
            Some("monthly") => (now - Duration::days(30), now),
            _ => (
                start_date.unwrap_or(now - Duration::days(30)),
                end_date.unwrap_or(now),
            ),
        }
    }

    fn generate_verification_token(&self) -> String {
        let mut rng = rand::thread_rng();
        (0..EMAIL_VERIFICATION_TOKEN_LENGTH)
            .map(|_| {
                let chars = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
                chars[rng.gen_range(0..chars.len())] as char
            })
            .collect()
    }

    fn generate_api_key(&self) -> String {
        let mut rng = rand::thread_rng();
        let prefix = "ak_";
        let key_part: String = (0..32)
            .map(|_| {
                let chars = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
                chars[rng.gen_range(0..chars.len())] as char
            })
            .collect();

        format!("{}{}", prefix, key_part)
    }

    fn hash_api_key(&self, api_key: &str) -> Result<String, DeveloperPortalError> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        
        let password_hash = argon2
            .hash_password(api_key.as_bytes(), &salt)
            .map_err(|e| DeveloperPortalError::Crypto(e.to_string()))?;

        Ok(password_hash.to_string())
    }

    pub fn verify_api_key_hash(&self, api_key: &str, hash: &str) -> Result<bool, DeveloperPortalError> {
        let parsed_hash = PasswordHash::new(hash)
            .map_err(|e| DeveloperPortalError::Crypto(e.to_string()))?;

        let argon2 = Argon2::default();
        
        match argon2.verify_password(api_key.as_bytes(), &parsed_hash) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}

/// Converts developer portal errors into the global AppError type so `?` works in handlers.
impl From<DeveloperPortalError> for AppError {
    fn from(err: DeveloperPortalError) -> Self {
        use crate::error::{AppErrorKind, DomainError, InfrastructureError, ValidationError};

        let kind = match err {
            DeveloperPortalError::EmailAlreadyRegistered => {
                // Use generic message to prevent email enumeration
                AppErrorKind::Domain(DomainError::DuplicateTransaction {
                    transaction_id: "email_registration".to_string(),
                })
            }
            DeveloperPortalError::AccountNotFound
            | DeveloperPortalError::ApplicationNotFound
            | DeveloperPortalError::ApiKeyNotFound
            | DeveloperPortalError::OAuthClientNotFound
            | DeveloperPortalError::WebhookConfigurationNotFound
            | DeveloperPortalError::ProductionAccessRequestNotFound => {
                AppErrorKind::Domain(DomainError::TransactionNotFound {
                    transaction_id: err.to_string(),
                })
            }
            DeveloperPortalError::InvalidEmailVerificationToken
            | DeveloperPortalError::EmailVerificationTokenExpired => {
                AppErrorKind::Validation(ValidationError::InvalidAmount {
                    amount: "token".to_string(),
                    reason: err.to_string(),
                })
            }
            DeveloperPortalError::GeoRestrictedCountry => {
                AppErrorKind::Validation(ValidationError::InvalidAmount {
                    amount: "country".to_string(),
                    reason: "Registration from this country is not supported".to_string(),
                })
            }
            DeveloperPortalError::MaximumApplicationsLimitReached => {
                AppErrorKind::Validation(ValidationError::OutOfRange {
                    field: "applications".to_string(),
                    min: None,
                    max: Some("tier limit".to_string()),
                })
            }
            DeveloperPortalError::IdentityVerificationRequired
            | DeveloperPortalError::IdentityVerificationAlreadySubmitted => {
                AppErrorKind::Validation(ValidationError::MissingField {
                    field: "identity_verification".to_string(),
                })
            }
            DeveloperPortalError::AccountSuspended => {
                AppErrorKind::Validation(ValidationError::MissingField {
                    field: "account_status".to_string(),
                })
            }
            DeveloperPortalError::ProductionAccessRequestAlreadyPending => {
                AppErrorKind::Domain(DomainError::DuplicateTransaction {
                    transaction_id: "production_access_request".to_string(),
                })
            }
            DeveloperPortalError::Database(e) => {
                AppErrorKind::Infrastructure(InfrastructureError::Database {
                    message: e.to_string(),
                    is_retryable: true,
                })
            }
            DeveloperPortalError::Serialization(e) => {
                AppErrorKind::Infrastructure(InfrastructureError::Configuration {
                    message: e.to_string(),
                })
            }
            _ => AppErrorKind::Infrastructure(InfrastructureError::Configuration {
                message: err.to_string(),
            }),
        };

        AppError::new(kind)
    }
}
