//! Service identity registration and management

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2,
};
use chrono::Utc;
use rand::Rng;
use sqlx::PgPool;
use std::sync::Arc;
use tracing::{error, info, warn};
use uuid::Uuid;

use super::types::{ServiceAuthError, ServiceAuthResult, ServiceIdentityInfo, ServiceStatus};
use crate::oauth::types::{ClientType, GrantType};

// ── Service token lifetime ───────────────────────────────────────────────────

pub const SERVICE_TOKEN_TTL_SECS: u64 = 900; // 15 minutes

// ── Service identity ─────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ServiceIdentity {
    pub id: Uuid,
    pub service_name: String,
    pub client_id: String,
    pub client_secret: String, // Only available at creation time
    pub allowed_scopes: Vec<String>,
    pub allowed_targets: Vec<String>,
}

// ── Service registration request ─────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ServiceRegistration {
    pub service_name: String,
    pub allowed_scopes: Vec<String>,
    pub allowed_targets: Vec<String>,
}

// ── Service registry ─────────────────────────────────────────────────────────

pub struct ServiceRegistry {
    pool: Arc<PgPool>,
}

impl ServiceRegistry {
    pub fn new(pool: Arc<PgPool>) -> Self {
        Self { pool }
    }

    /// Register a new service identity
    pub async fn register_service(
        &self,
        registration: ServiceRegistration,
    ) -> ServiceAuthResult<ServiceIdentity> {
        // Generate client credentials
        let client_id = format!("service_{}", registration.service_name);
        let client_secret = Self::generate_client_secret();
        let secret_hash = Self::hash_secret(&client_secret)?;

        // Ensure microservice:internal scope is included
        let mut scopes = registration.allowed_scopes.clone();
        if !scopes.contains(&"microservice:internal".to_string()) {
            scopes.push("microservice:internal".to_string());
        }

        let id = Uuid::new_v4();
        let now = Utc::now();

        // Insert into oauth_clients table
        sqlx::query!(
            r#"
            INSERT INTO oauth_clients (
                id, client_id, client_secret_hash, client_name, client_type,
                allowed_grant_types, allowed_scopes, redirect_uris, status,
                created_by, created_at, updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $11)
            "#,
            id,
            &client_id,
            Some(&secret_hash),
            &registration.service_name,
            ClientType::Confidential.to_string(),
            &vec![GrantType::ClientCredentials.as_str()],
            &scopes,
            &Vec::<String>::new(),
            ServiceStatus::Active.to_string(),
            Some("system"),
            now,
        )
        .execute(&*self.pool)
        .await
        .map_err(|e| {
            error!("Failed to register service {}: {}", registration.service_name, e);
            ServiceAuthError::DatabaseError(e.to_string())
        })?;

        info!(
            service_name = %registration.service_name,
            client_id = %client_id,
            "Service identity registered"
        );

        Ok(ServiceIdentity {
            id,
            service_name: registration.service_name,
            client_id,
            client_secret,
            allowed_scopes: scopes,
            allowed_targets: registration.allowed_targets,
        })
    }

    /// Get service identity by service name
    pub async fn get_service(&self, service_name: &str) -> ServiceAuthResult<ServiceIdentityInfo> {
        let client_id = format!("service_{}", service_name);

        let row = sqlx::query!(
            r#"
            SELECT client_id, client_name, allowed_scopes, status
            FROM oauth_clients
            WHERE client_id = $1 AND client_type = 'confidential'
            "#,
            &client_id
        )
        .fetch_optional(&*self.pool)
        .await
        .map_err(|e| ServiceAuthError::DatabaseError(e.to_string()))?;

        let row = row.ok_or_else(|| {
            ServiceAuthError::ServiceNotRegistered(service_name.to_string())
        })?;

        let status = match row.status.as_str() {
            "active" => ServiceStatus::Active,
            "suspended" => ServiceStatus::Suspended,
            "revoked" => ServiceStatus::Revoked,
            _ => ServiceStatus::Suspended,
        };

        Ok(ServiceIdentityInfo {
            service_name: row.client_name,
            client_id: row.client_id,
            allowed_scopes: row.allowed_scopes,
            allowed_targets: Vec::new(), // TODO: Load from allowlist
            status,
        })
    }

    /// List all registered services
    pub async fn list_services(&self) -> ServiceAuthResult<Vec<ServiceIdentityInfo>> {
        let rows = sqlx::query!(
            r#"
            SELECT client_id, client_name, allowed_scopes, status
            FROM oauth_clients
            WHERE client_type = 'confidential'
              AND client_id LIKE 'service_%'
            ORDER BY client_name
            "#
        )
        .fetch_all(&*self.pool)
        .await
        .map_err(|e| ServiceAuthError::DatabaseError(e.to_string()))?;

        Ok(rows
            .into_iter()
            .map(|row| {
                let status = match row.status.as_str() {
                    "active" => ServiceStatus::Active,
                    "suspended" => ServiceStatus::Suspended,
                    "revoked" => ServiceStatus::Revoked,
                    _ => ServiceStatus::Suspended,
                };

                ServiceIdentityInfo {
                    service_name: row.client_name,
                    client_id: row.client_id,
                    allowed_scopes: row.allowed_scopes,
                    allowed_targets: Vec::new(),
                    status,
                }
            })
            .collect())
    }

    /// Rotate service client secret with grace period
    pub async fn rotate_secret(
        &self,
        service_name: &str,
        grace_period_secs: i64,
    ) -> ServiceAuthResult<String> {
        let client_id = format!("service_{}", service_name);

        // Get current service
        let service = sqlx::query!(
            r#"
            SELECT id, client_secret_hash
            FROM oauth_clients
            WHERE client_id = $1 AND client_type = 'confidential'
            "#,
            &client_id
        )
        .fetch_optional(&*self.pool)
        .await
        .map_err(|e| ServiceAuthError::DatabaseError(e.to_string()))?
        .ok_or_else(|| ServiceAuthError::ServiceNotRegistered(service_name.to_string()))?;

        let old_secret_hash = service
            .client_secret_hash
            .ok_or_else(|| ServiceAuthError::Internal("Service has no secret".to_string()))?;

        // Generate new secret
        let new_secret = Self::generate_client_secret();
        let new_secret_hash = Self::hash_secret(&new_secret)?;

        let now = Utc::now();
        let grace_period_ends = now + chrono::Duration::seconds(grace_period_secs);

        // Start transaction
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| ServiceAuthError::DatabaseError(e.to_string()))?;

        // Record rotation
        sqlx::query!(
            r#"
            INSERT INTO service_secret_rotation (
                service_id, old_secret_hash, new_secret_hash,
                grace_period_ends, rotation_completed
            )
            VALUES ($1, $2, $3, $4, FALSE)
            "#,
            service.id,
            &old_secret_hash,
            &new_secret_hash,
            grace_period_ends,
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| ServiceAuthError::DatabaseError(e.to_string()))?;

        // Update client secret
        sqlx::query!(
            r#"
            UPDATE oauth_clients
            SET client_secret_hash = $1, updated_at = $2
            WHERE id = $3
            "#,
            &new_secret_hash,
            now,
            service.id,
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| ServiceAuthError::DatabaseError(e.to_string()))?;

        tx.commit()
            .await
            .map_err(|e| ServiceAuthError::DatabaseError(e.to_string()))?;

        info!(
            service_name = %service_name,
            grace_period_secs = %grace_period_secs,
            "Service secret rotated"
        );

        Ok(new_secret)
    }

    /// Complete secret rotation (mark old secret as invalid)
    pub async fn complete_rotation(&self, service_name: &str) -> ServiceAuthResult<()> {
        let client_id = format!("service_{}", service_name);

        let service_id = sqlx::query_scalar!(
            "SELECT id FROM oauth_clients WHERE client_id = $1",
            &client_id
        )
        .fetch_optional(&*self.pool)
        .await
        .map_err(|e| ServiceAuthError::DatabaseError(e.to_string()))?
        .ok_or_else(|| ServiceAuthError::ServiceNotRegistered(service_name.to_string()))?;

        sqlx::query!(
            r#"
            UPDATE service_secret_rotation
            SET rotation_completed = TRUE, completed_at = $1
            WHERE service_id = $2 AND NOT rotation_completed
            "#,
            Utc::now(),
            service_id,
        )
        .execute(&*self.pool)
        .await
        .map_err(|e| ServiceAuthError::DatabaseError(e.to_string()))?;

        info!(service_name = %service_name, "Secret rotation completed");

        Ok(())
    }

    // ── Helper methods ───────────────────────────────────────────────────────

    fn generate_client_secret() -> String {
        let mut rng = rand::thread_rng();
        let bytes: [u8; 32] = rng.gen();
        format!("svc_secret_{}", hex::encode(bytes))
    }

    fn hash_secret(secret: &str) -> ServiceAuthResult<String> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();

        argon2
            .hash_password(secret.as_bytes(), &salt)
            .map(|hash| hash.to_string())
            .map_err(|e| ServiceAuthError::Internal(format!("Failed to hash secret: {}", e)))
    }
}
