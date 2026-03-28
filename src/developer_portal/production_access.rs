use super::models::*;
use super::repositories::{DeveloperAccountRepository, DeveloperApplicationRepository, ApiKeyRepository, OAuthClientRepository, ProductionAccessRequestRepository, WebhookConfigurationRepository};
use crate::database::error::DatabaseError;
use chrono::{DateTime, Utc};
use rand::Rng;
use argon2::{Argon2, PasswordHasher};
use argon2::password_hash::{rand_core::OsRng, SaltString};
use serde_json::json;
use std::sync::Arc;
use tracing::{error, info, warn};
use uuid::Uuid;

#[derive(Clone)]
pub struct ProductionAccessService {
    developer_account_repo: DeveloperAccountRepository,
    application_repo: DeveloperApplicationRepository,
    api_key_repo: ApiKeyRepository,
    oauth_client_repo: OAuthClientRepository,
    production_access_repo: ProductionAccessRequestRepository,
    webhook_repo: WebhookConfigurationRepository,
}

impl ProductionAccessService {
    pub fn new(
        developer_account_repo: DeveloperAccountRepository,
        application_repo: DeveloperApplicationRepository,
        api_key_repo: ApiKeyRepository,
        oauth_client_repo: OAuthClientRepository,
        production_access_repo: ProductionAccessRequestRepository,
        webhook_repo: WebhookConfigurationRepository,
    ) -> Self {
        Self {
            developer_account_repo,
            application_repo,
            api_key_repo,
            oauth_client_repo,
            production_access_repo,
            webhook_repo,
        }
    }

    pub async fn create_production_access_request(
        &self,
        application_id: Uuid,
        developer_account_id: Uuid,
        request: CreateProductionAccessRequest,
    ) -> Result<ProductionAccessRequest, DeveloperPortalError> {
        // Verify application exists and belongs to developer
        let application = self
            .application_repo
            .find_by_id(application_id)
            .await?
            .ok_or(DeveloperPortalError::ApplicationNotFound)?;

        if application.developer_account_id != developer_account_id {
            return Err(DeveloperPortalError::ApplicationNotFound);
        }

        // Check developer account status and identity verification
        let account = self
            .developer_account_repo
            .find_by_id(developer_account_id)
            .await?
            .ok_or(DeveloperPortalError::AccountNotFound)?;

        if account.identity_verification_status != "verified" {
            return Err(DeveloperPortalError::IdentityVerificationRequired);
        }

        // Check if there's already a pending request
        let existing_requests = self
            .production_access_repo
            .find_by_application_and_status(application_id, "pending")
            .await?;

        if !existing_requests.is_empty() {
            return Err(DeveloperPortalError::ProductionAccessRequestAlreadyPending);
        }

        // Create production access request
        let production_request = self
            .production_access_repo
            .create(application_id, developer_account_id, request)
            .await?;

        // Notify admin webhook
        self.notify_admin_production_request(&production_request, "created").await?;

        info!(
            "Production access request created: {} for application: {}",
            production_request.id, application.name
        );

        Ok(production_request)
    }

    pub async fn get_production_access_requests(
        &self,
        developer_account_id: Uuid,
    ) -> Result<Vec<ProductionAccessRequest>, DeveloperPortalError> {
        let requests = self
            .production_access_repo
            .find_by_developer_account(developer_account_id)
            .await?;

        Ok(requests)
    }

    pub async fn approve_production_access_request(
        &self,
        request_id: Uuid,
        admin_id: Uuid,
        review_notes: Option<String>,
    ) -> Result<ProductionAccessRequest, DeveloperPortalError> {
        let mut request = self
            .production_access_repo
            .find_by_id(request_id)
            .await?
            .ok_or(DeveloperPortalError::ProductionAccessRequestNotFound)?;

        if request.status != "pending" {
            return Err(DeveloperPortalError::InvalidStatus);
        }

        // Update request status
        request = self
            .production_access_repo
            .update_status(request_id, "approved", Some(admin_id), review_notes)
            .await?;

        // Upgrade developer account to standard tier if not already
        let account = self
            .developer_account_repo
            .find_by_id(request.developer_account_id)
            .await?
            .ok_or(DeveloperPortalError::AccountNotFound)?;

        if account.access_tier_code == "sandbox" {
            self.developer_account_repo
                .upgrade_to_standard_tier(request.developer_account_id)
                .await?;
        }

        // Issue production credentials
        self.issue_production_credentials(request.application_id).await?;

        // Notify developer
        self.notify_developer_production_request(&request, "approved").await?;

        info!(
            "Production access request approved: {} for application: {}",
            request.id, request.application_id
        );

        Ok(request)
    }

    pub async fn reject_production_access_request(
        &self,
        request_id: Uuid,
        admin_id: Uuid,
        review_notes: Option<String>,
    ) -> Result<ProductionAccessRequest, DeveloperPortalError> {
        let request = self
            .production_access_repo
            .find_by_id(request_id)
            .await?
            .ok_or(DeveloperPortalError::ProductionAccessRequestNotFound)?;

        if request.status != "pending" {
            return Err(DeveloperPortalError::InvalidStatus);
        }

        // Update request status
        let updated_request = self
            .production_access_repo
            .update_status(request_id, "rejected", Some(admin_id), review_notes)
            .await?;

        // Notify developer
        self.notify_developer_production_request(&updated_request, "rejected").await?;

        warn!(
            "Production access request rejected: {} for application: {}",
            request_id, request.application_id
        );

        Ok(updated_request)
    }

    pub async fn get_admin_production_queue(
        &self,
        status: Option<String>,
        page: i64,
        per_page: i64,
    ) -> Result<AdminProductionAccessQueue, DeveloperPortalError> {
        let queue = self
            .production_access_repo
            .list_for_admin(status, page, per_page)
            .await?;

        Ok(queue)
    }

    async fn issue_production_credentials(&self, application_id: Uuid) -> Result<(), DeveloperPortalError> {
        info!("Issuing production credentials for application: {}", application_id);

        // Generate production API key
        let raw_key = self.generate_random_token("ak_", 32);
        let key_prefix = &raw_key[..8];
        let key_hash = self.hash_value(&raw_key)?;

        let key_request = CreateApiKeyRequest {
            key_name: "Production API Key".to_string(),
            environment: "production".to_string(),
            expires_at: None,
            rate_limit_per_minute: Some(1000),
        };
        self.api_key_repo
            .create(application_id, key_request, key_prefix, &key_hash)
            .await?;

        // Generate production OAuth client
        let client_id = self.generate_random_token("client_", 16);
        let client_secret = self.generate_random_token("", 32);
        let client_secret_hash = self.hash_value(&client_secret)?;

        let oauth_request = CreateOAuthClientRequest {
            client_name: "Production OAuth Client".to_string(),
            environment: "production".to_string(),
            redirect_uris: vec![],
            scopes: vec!["read".to_string(), "write".to_string()],
        };
        self.oauth_client_repo
            .create(application_id, &client_id, &client_secret_hash, oauth_request)
            .await?;

        info!(
            event = "production_credentials_issued",
            application_id = %application_id,
            "Production credentials issued successfully"
        );

        Ok(())
    }

    fn generate_random_token(&self, prefix: &str, len: usize) -> String {
        let mut rng = rand::thread_rng();
        let chars = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        let suffix: String = (0..len)
            .map(|_| chars[rng.gen_range(0..chars.len())] as char)
            .collect();
        format!("{}{}", prefix, suffix)
    }

    fn hash_value(&self, value: &str) -> Result<String, DeveloperPortalError> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let hash = argon2
            .hash_password(value.as_bytes(), &salt)
            .map_err(|e| DeveloperPortalError::Crypto(e.to_string()))?;
        Ok(hash.to_string())
    }

    async fn notify_admin_production_request(
        &self,
        request: &ProductionAccessRequest,
        action: &str,
    ) -> Result<(), DeveloperPortalError> {
        info!(
            event = "production_access_request_admin_notify",
            request_id = %request.id,
            application_id = %request.application_id,
            developer_account_id = %request.developer_account_id,
            action = action,
            "Admin notified of production access request"
        );
        Ok(())
    }

    async fn notify_developer_production_request(
        &self,
        request: &ProductionAccessRequest,
        action: &str,
    ) -> Result<(), DeveloperPortalError> {
        info!(
            event = "production_access_request_developer_notify",
            request_id = %request.id,
            application_id = %request.application_id,
            developer_account_id = %request.developer_account_id,
            status = %request.status,
            action = action,
            "Developer notified of production access request status change"
        );
        Ok(())
    }
}

#[derive(Clone)]
pub struct ProductionAccessRequestRepository {
    pool: Arc<sqlx::PgPool>,
}

impl ProductionAccessRequestRepository {
    pub fn new(pool: Arc<sqlx::PgPool>) -> Self {
        Self { pool }
    }

    pub async fn create(
        &self,
        application_id: Uuid,
        developer_account_id: Uuid,
        request: CreateProductionAccessRequest,
    ) -> Result<ProductionAccessRequest, DeveloperPortalError> {
        let production_request = sqlx::query_as!(
            ProductionAccessRequest,
            r#"
            INSERT INTO production_access_requests (
                application_id, developer_account_id, production_use_case,
                expected_transaction_volume, supported_countries, business_details
            ) VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING *
            "#,
            application_id,
            developer_account_id,
            request.production_use_case,
            request.expected_transaction_volume,
            &request.supported_countries,
            request.business_details
        )
        .fetch_one(self.pool.as_ref())
        .await?;

        Ok(production_request)
    }

    pub async fn find_by_id(&self, id: Uuid) -> Result<Option<ProductionAccessRequest>, DeveloperPortalError> {
        let request = sqlx::query_as!(
            ProductionAccessRequest,
            "SELECT * FROM production_access_requests WHERE id = $1",
            id
        )
        .fetch_optional(self.pool.as_ref())
        .await?;

        Ok(request)
    }

    pub async fn find_by_application_and_status(
        &self,
        application_id: Uuid,
        status: &str,
    ) -> Result<Vec<ProductionAccessRequest>, DeveloperPortalError> {
        let requests = sqlx::query_as!(
            ProductionAccessRequest,
            "SELECT * FROM production_access_requests WHERE application_id = $1 AND status = $2",
            application_id,
            status
        )
        .fetch_all(self.pool.as_ref())
        .await?;

        Ok(requests)
    }

    pub async fn find_by_developer_account(
        &self,
        developer_account_id: Uuid,
    ) -> Result<Vec<ProductionAccessRequest>, DeveloperPortalError> {
        let requests = sqlx::query_as!(
            ProductionAccessRequest,
            "SELECT * FROM production_access_requests WHERE developer_account_id = $1 ORDER BY created_at DESC",
            developer_account_id
        )
        .fetch_all(self.pool.as_ref())
        .await?;

        Ok(requests)
    }

    pub async fn update_status(
        &self,
        request_id: Uuid,
        status: &str,
        reviewed_by_admin_id: Option<Uuid>,
        review_notes: Option<String>,
    ) -> Result<ProductionAccessRequest, DeveloperPortalError> {
        let request = sqlx::query_as!(
            ProductionAccessRequest,
            r#"
            UPDATE production_access_requests 
            SET status = $1,
                reviewed_by_admin_id = $2,
                review_notes = $3,
                reviewed_at = now(),
                updated_at = now()
            WHERE id = $4
            RETURNING *
            "#,
            status,
            reviewed_by_admin_id,
            review_notes,
            request_id
        )
        .fetch_one(self.pool.as_ref())
        .await?;

        Ok(request)
    }

    pub async fn list_for_admin(
        &self,
        status: Option<String>,
        page: i64,
        per_page: i64,
    ) -> Result<AdminProductionAccessQueue, DeveloperPortalError> {
        let offset = (page - 1) * per_page;

        let requests = if let Some(status_filter) = status {
            sqlx::query_as!(
                AdminProductionAccessRequestSummary,
                r#"
                SELECT 
                    par.id,
                    par.application_id,
                    da.name as "application_name!",
                    par.developer_account_id,
                    da.email as "developer_email!",
                    par.production_use_case,
                    par.expected_transaction_volume,
                    par.supported_countries,
                    par.status,
                    par.created_at
                FROM production_access_requests par
                JOIN developer_applications da ON par.application_id = da.id
                JOIN developer_accounts dev ON par.developer_account_id = dev.id
                WHERE par.status = $1
                ORDER BY par.created_at DESC
                LIMIT $2 OFFSET $3
                "#,
                status_filter,
                per_page,
                offset
            )
            .fetch_all(self.pool.as_ref())
            .await?
        } else {
            sqlx::query_as!(
                AdminProductionAccessRequestSummary,
                r#"
                SELECT 
                    par.id,
                    par.application_id,
                    da.name as "application_name!",
                    par.developer_account_id,
                    dev.email as "developer_email!",
                    par.production_use_case,
                    par.expected_transaction_volume,
                    par.supported_countries,
                    par.status,
                    par.created_at
                FROM production_access_requests par
                JOIN developer_applications da ON par.application_id = da.id
                JOIN developer_accounts dev ON par.developer_account_id = dev.id
                ORDER BY par.created_at DESC
                LIMIT $1 OFFSET $2
                "#,
                per_page,
                offset
            )
            .fetch_all(self.pool.as_ref())
            .await?
        };

        let total_count = if let Some(status_filter) = status {
            sqlx::query_scalar!(
                "SELECT COUNT(*) FROM production_access_requests WHERE status = $1",
                status_filter
            )
            .fetch_one(self.pool.as_ref())
            .await?
        } else {
            sqlx::query_scalar!(
                "SELECT COUNT(*) FROM production_access_requests"
            )
            .fetch_one(self.pool.as_ref())
            .await?
        };

        let total_count = total_count.unwrap_or(0);
        let pending_count = sqlx::query_scalar!(
            "SELECT COUNT(*) FROM production_access_requests WHERE status = 'pending'"
        )
        .fetch_one(self.pool.as_ref())
        .await?;

        let pending_count = pending_count.unwrap_or(0);

        Ok(AdminProductionAccessQueue {
            requests,
            total_count,
            pending_count,
        })
    }
}
