//! Merchant API Key Management Service
//! Handles creation and management of merchant-scoped API keys

use crate::api_keys::generator::{generate_api_key, GeneratedKey, KeyEnvironment};
use crate::api_keys::repository::ApiKeyRepository;
use crate::database::error::DatabaseError;
use crate::merchant_gateway::models::MerchantApiKeyScope;
use chrono::{DateTime, Duration, Utc};
use sqlx::PgPool;
use std::sync::Arc;
use tracing::{info, instrument};
use uuid::Uuid;

// ============================================================================
// MERCHANT API KEY SERVICE
// ============================================================================

pub struct MerchantApiKeyService {
    api_key_repo: Arc<ApiKeyRepository>,
    pool: PgPool,
}

impl MerchantApiKeyService {
    pub fn new(pool: PgPool) -> Self {
        Self {
            api_key_repo: Arc::new(ApiKeyRepository::new(pool.clone())),
            pool,
        }
    }

    /// Generate a new API key for a merchant
    #[instrument(skip(self))]
    pub async fn create_merchant_api_key(
        &self,
        merchant_id: Uuid,
        environment: KeyEnvironment,
        scope: MerchantApiKeyScope,
        description: Option<&str>,
        expires_in_days: Option<i64>,
    ) -> Result<GeneratedKey, DatabaseError> {
        // Generate cryptographically secure API key
        let generated = generate_api_key(environment.clone())
            .map_err(|e| DatabaseError::new(crate::database::error::DatabaseErrorKind::Unknown {
                message: e,
            }))?;

        // Calculate expiry
        let expires_at = expires_in_days.map(|days| Utc::now() + Duration::days(days));

        // Store in database with merchant association
        let api_key = self
            .api_key_repo
            .create(
                merchant_id,
                &generated.key_hash,
                &generated.key_prefix,
                &generated.key_id_prefix,
                environment.as_str(),
                description,
                Some("merchant_portal"),
                expires_at,
            )
            .await?;

        // Associate merchant_id and scope
        sqlx::query(
            r#"
            UPDATE api_keys
            SET merchant_id = $2, key_scope = $3
            WHERE id = $1
            "#,
        )
        .bind(api_key.id)
        .bind(merchant_id)
        .bind(scope.as_str())
        .execute(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?;

        info!(
            api_key_id = %api_key.id,
            merchant_id = %merchant_id,
            environment = %environment.as_str(),
            scope = %scope.as_str(),
            "Merchant API key created"
        );

        Ok(generated)
    }

    /// Revoke a merchant API key
    #[instrument(skip(self))]
    pub async fn revoke_merchant_api_key(
        &self,
        merchant_id: Uuid,
        api_key_id: Uuid,
    ) -> Result<(), DatabaseError> {
        self.api_key_repo.revoke(api_key_id, merchant_id).await?;

        info!(
            api_key_id = %api_key_id,
            merchant_id = %merchant_id,
            "Merchant API key revoked"
        );

        Ok(())
    }

    /// List all API keys for a merchant
    #[instrument(skip(self))]
    pub async fn list_merchant_api_keys(
        &self,
        merchant_id: Uuid,
    ) -> Result<Vec<MerchantApiKeyInfo>, DatabaseError> {
        let keys = self.api_key_repo.list_for_consumer(merchant_id).await?;

        let info: Vec<MerchantApiKeyInfo> = keys
            .into_iter()
            .map(|key| MerchantApiKeyInfo {
                id: key.id,
                key_prefix: key.key_prefix,
                description: key.description,
                environment: key.environment,
                status: key.status,
                expires_at: key.expires_at,
                last_used_at: key.last_used_at,
                created_at: key.created_at,
            })
            .collect();

        Ok(info)
    }
}

// ============================================================================
// RESPONSE TYPES
// ============================================================================

#[derive(Debug, serde::Serialize)]
pub struct MerchantApiKeyInfo {
    pub id: Uuid,
    pub key_prefix: String,
    pub description: Option<String>,
    pub environment: String,
    pub status: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}
