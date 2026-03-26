use super::models::*;
use super::repositories::{DeveloperApplicationRepository, ApiKeyRepository, OAuthClientRepository, WebhookConfigurationRepository};
use crate::database::error::DatabaseError;
use chrono::Utc;
use rand::Rng;
use serde_json::json;
use std::sync::Arc;
use tracing::{error, info, warn};
use uuid::Uuid;

#[derive(Clone)]
pub struct SandboxService {
    application_repo: DeveloperApplicationRepository,
    api_key_repo: ApiKeyRepository,
    oauth_client_repo: OAuthClientRepository,
    webhook_repo: WebhookConfigurationRepository,
}

impl SandboxService {
    pub fn new(
        application_repo: DeveloperApplicationRepository,
        api_key_repo: ApiKeyRepository,
        oauth_client_repo: OAuthClientRepository,
        webhook_repo: WebhookConfigurationRepository,
    ) -> Self {
        Self {
            application_repo,
            api_key_repo,
            oauth_client_repo,
            webhook_repo,
        }
    }

    pub async fn provision_sandbox_environment(
        &self,
        application_id: Uuid,
    ) -> Result<SandboxEnvironment, DeveloperPortalError> {
        let application = self
            .application_repo
            .find_by_id(application_id)
            .await?
            .ok_or(DeveloperPortalError::ApplicationNotFound)?;

        // Generate Stellar testnet wallet
        let (wallet_address, wallet_secret) = self.generate_stellar_testnet_wallet()?;

        // Update application with sandbox wallet
        self.application_repo
            .update_sandbox_wallet(application_id, &wallet_address, &wallet_secret)
            .await?;

        // Create sandbox API keys
        let sandbox_api_keys = self.create_sandbox_api_keys(application_id).await?;

        // Create sandbox OAuth clients
        let sandbox_oauth_clients = self.create_sandbox_oauth_clients(application_id).await?;

        let sandbox_env = SandboxEnvironment {
            wallet_address,
            wallet_secret,
            network: "testnet".to_string(),
            initial_balance: "10000.0000000".to_string(), // 10,000 XLM testnet
            api_keys: sandbox_api_keys,
            oauth_clients: sandbox_oauth_clients,
        };

        info!(
            "Sandbox environment provisioned for application: {}",
            application.name
        );

        Ok(sandbox_env)
    }

    pub async fn reset_sandbox_environment(
        &self,
        application_id: Uuid,
    ) -> Result<SandboxEnvironment, DeveloperPortalError> {
        let application = self
            .application_repo
            .find_by_id(application_id)
            .await?
            .ok_or(DeveloperPortalError::ApplicationNotFound)?;

        // Revoke all existing sandbox credentials
        self.revoke_sandbox_credentials(application_id).await?;

        // Clear existing sandbox wallet
        self.application_repo.clear_sandbox_wallet(application_id).await?;

        // Provision fresh sandbox environment
        let new_env = self.provision_sandbox_environment(application_id).await?;

        info!(
            "Sandbox environment reset for application: {}",
            application.name
        );

        Ok(new_env)
    }

    pub async fn get_sandbox_environment(
        &self,
        application_id: Uuid,
    ) -> Result<Option<SandboxEnvironment>, DeveloperPortalError> {
        let application = self
            .application_repo
            .find_by_id(application_id)
            .await?;

        if let Some(app) = application {
            if let (Some(wallet_address), Some(wallet_secret)) = 
                (app.sandbox_wallet_address, app.sandbox_wallet_secret) {
                
                // Get sandbox API keys
                let api_keys = self
                    .api_key_repo
                    .find_by_application_and_environment(application_id, "sandbox")
                    .await?;

                let sandbox_api_keys = api_keys.into_iter().map(|key| SandboxApiKey {
                    key_id: key.id,
                    key_name: key.key_name,
                    api_key: format!("{}_{}", key.key_prefix, self.generate_api_key_suffix()), // In real implementation, store full key
                    rate_limit_per_minute: key.rate_limit_per_minute,
                }).collect();

                // Get sandbox OAuth clients
                let oauth_clients = self
                    .get_sandbox_oauth_clients(application_id)
                    .await?;

                Ok(Some(SandboxEnvironment {
                    wallet_address,
                    wallet_secret,
                    network: "testnet".to_string(),
                    initial_balance: "10000.0000000".to_string(),
                    api_keys: sandbox_api_keys,
                    oauth_clients,
                }))
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    async fn revoke_sandbox_credentials(&self, application_id: Uuid) -> Result<(), DeveloperPortalError> {
        // Revoke sandbox API keys
        self.api_key_repo
            .revoke_by_application(application_id, "sandbox")
            .await?;

        // Revoke sandbox OAuth clients
        self.revoke_sandbox_oauth_clients(application_id).await?;

        Ok(())
    }

    async fn create_sandbox_api_keys(
        &self,
        application_id: Uuid,
    ) -> Result<Vec<SandboxApiKey>, DeveloperPortalError> {
        let mut api_keys = Vec::new();

        // Create default sandbox API key
        let default_key_request = CreateApiKeyRequest {
            key_name: "Default Sandbox Key".to_string(),
            environment: "sandbox".to_string(),
            expires_at: None,
            rate_limit_per_minute: Some(50),
        };

        let (api_key, raw_key) = self
            .create_api_key_internal(application_id, default_key_request)
            .await?;

        api_keys.push(SandboxApiKey {
            key_id: api_key.id,
            key_name: api_key.key_name,
            api_key: raw_key,
            rate_limit_per_minute: api_key.rate_limit_per_minute,
        });

        // Create read-only sandbox API key
        let readonly_key_request = CreateApiKeyRequest {
            key_name: "Read-only Sandbox Key".to_string(),
            environment: "sandbox".to_string(),
            expires_at: None,
            rate_limit_per_minute: Some(100),
        };

        let (api_key, raw_key) = self
            .create_api_key_internal(application_id, readonly_key_request)
            .await?;

        api_keys.push(SandboxApiKey {
            key_id: api_key.id,
            key_name: api_key.key_name,
            api_key: raw_key,
            rate_limit_per_minute: api_key.rate_limit_per_minute,
        });

        Ok(api_keys)
    }

    async fn create_sandbox_oauth_clients(
        &self,
        application_id: Uuid,
    ) -> Result<Vec<SandboxOAuthClient>, DeveloperPortalError> {
        let mut oauth_clients = Vec::new();

        // Create default sandbox OAuth client
        let default_client_request = CreateOAuthClientRequest {
            client_name: "Default Sandbox Client".to_string(),
            environment: "sandbox".to_string(),
            redirect_uris: vec![
                "http://localhost:3000/callback".to_string(),
                "http://localhost:8080/callback".to_string(),
            ],
            scopes: vec![
                "read".to_string(),
                "write".to_string(),
                "sandbox".to_string(),
            ],
        };

        let (client, client_secret) = self
            .create_oauth_client_internal(application_id, default_client_request)
            .await?;

        oauth_clients.push(SandboxOAuthClient {
            client_id: client.client_id,
            client_name: client.client_name,
            client_secret,
            redirect_uris: client.redirect_uris,
            scopes: client.scopes,
        });

        Ok(oauth_clients)
    }

    async fn create_api_key_internal(
        &self,
        application_id: Uuid,
        request: CreateApiKeyRequest,
    ) -> Result<(ApiKey, String), DeveloperPortalError> {
        // Generate API key
        let raw_key = self.generate_api_key();
        let key_prefix = &raw_key[..8];
        let key_hash = self.hash_api_key(&raw_key)?;

        // Create API key record
        let api_key = self
            .api_key_repo
            .create(application_id, request, key_prefix, &key_hash)
            .await?;

        Ok((api_key, raw_key))
    }

    async fn create_oauth_client_internal(
        &self,
        application_id: Uuid,
        request: CreateOAuthClientRequest,
    ) -> Result<(OAuthClient, String), DeveloperPortalError> {
        // Generate OAuth client credentials
        let client_id = self.generate_oauth_client_id();
        let client_secret = self.generate_oauth_client_secret();
        let client_secret_hash = self.hash_client_secret(&client_secret)?;

        // Create OAuth client record
        let client = self
            .create_oauth_client(application_id, &client_id, &client_secret_hash, request)
            .await?;

        Ok((client, client_secret))
    }

    fn generate_stellar_testnet_wallet(&self) -> Result<(String, String), DeveloperPortalError> {
        // In a real implementation, this would integrate with Stellar SDK
        // For now, generate mock testnet credentials
        let mut rng = rand::thread_rng();
        
        // Generate a mock Stellar address (56 characters for testnet)
        let address: String = (0..56)
            .map(|_| {
                let chars = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
                chars[rng.gen_range(0..chars.len())] as char
            })
            .collect();

        // Generate a mock secret key (56 characters starting with S for testnet)
        let secret = format!("S{}", (0..55)
            .map(|_| {
                let chars = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
                chars[rng.gen_range(0..chars.len())] as char
            })
            .collect::<String>());

        Ok((address, secret))
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

    fn generate_api_key_suffix(&self) -> String {
        let mut rng = rand::thread_rng();
        (0..24)
            .map(|_| {
                let chars = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
                chars[rng.gen_range(0..chars.len())] as char
            })
            .collect()
    }

    fn generate_oauth_client_id(&self) -> String {
        let mut rng = rand::thread_rng();
        let prefix = "client_";
        let id_part: String = (0..16)
            .map(|_| {
                let chars = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
                chars[rng.gen_range(0..chars.len())] as char
            })
            .collect();

        format!("{}{}", prefix, id_part)
    }

    fn generate_oauth_client_secret(&self) -> String {
        let mut rng = rand::thread_rng();
        (0..32)
            .map(|_| {
                let chars = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
                chars[rng.gen_range(0..chars.len())] as char
            })
            .collect()
    }

    fn hash_api_key(&self, api_key: &str) -> Result<String, DeveloperPortalError> {
        use argon2::{Argon2, PasswordHash, PasswordHasher};
        use argon2::password_hash::{rand_core::OsRng, SaltString};

        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        
        let password_hash = argon2
            .hash_password(api_key.as_bytes(), &salt)
            .map_err(|e| DeveloperPortalError::Crypto(e.to_string()))?;

        Ok(password_hash.to_string())
    }

    fn hash_client_secret(&self, client_secret: &str) -> Result<String, DeveloperPortalError> {
        use argon2::{Argon2, PasswordHash, PasswordHasher};
        use argon2::password_hash::{rand_core::OsRng, SaltString};

        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        
        let password_hash = argon2
            .hash_password(client_secret.as_bytes(), &salt)
            .map_err(|e| DeveloperPortalError::Crypto(e.to_string()))?;

        Ok(password_hash.to_string())
    }

    async fn create_oauth_client(
        &self,
        application_id: Uuid,
        client_id: &str,
        client_secret_hash: &str,
        request: CreateOAuthClientRequest,
    ) -> Result<OAuthClient, DeveloperPortalError> {
        self.oauth_client_repo
            .create(application_id, client_id, client_secret_hash, request)
            .await
    }

    async fn get_sandbox_oauth_clients(
        &self,
        application_id: Uuid,
    ) -> Result<Vec<SandboxOAuthClient>, DeveloperPortalError> {
        let clients = self
            .oauth_client_repo
            .find_by_application_and_environment(application_id, "sandbox")
            .await?;

        let sandbox_clients = clients
            .into_iter()
            .map(|c| SandboxOAuthClient {
                client_id: c.client_id,
                client_name: c.client_name,
                // Secret is not stored in plain-text — callers receive it only at creation time
                client_secret: "[redacted]".to_string(),
                redirect_uris: c.redirect_uris,
                scopes: c.scopes,
            })
            .collect();

        Ok(sandbox_clients)
    }

    async fn revoke_sandbox_oauth_clients(&self, application_id: Uuid) -> Result<(), DeveloperPortalError> {
        self.oauth_client_repo
            .revoke_by_application_and_environment(application_id, "sandbox")
            .await
    }
}

// Extension trait for ApiKeyRepository to support environment filtering
pub trait ApiKeyRepositoryExt {
    async fn find_by_application_and_environment(
        &self,
        application_id: Uuid,
        environment: &str,
    ) -> Result<Vec<ApiKey>, DeveloperPortalError>;
}

impl ApiKeyRepositoryExt for super::repositories::ApiKeyRepository {
    async fn find_by_application_and_environment(
        &self,
        application_id: Uuid,
        environment: &str,
    ) -> Result<Vec<ApiKey>, DeveloperPortalError> {
        let api_keys = sqlx::query_as!(
            ApiKey,
            "SELECT * FROM api_keys WHERE application_id = $1 AND environment = $2 ORDER BY created_at DESC",
            application_id,
            environment
        )
        .fetch_all(self.pool.as_ref())
        .await?;

        Ok(api_keys)
    }
}
