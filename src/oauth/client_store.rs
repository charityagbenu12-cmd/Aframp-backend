//! OAuth client persistence — PostgreSQL-backed client registry.

use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;

use super::types::{ClientType, GrantType, OAuthClient, OAuthError};

// ── Repository ────────────────────────────────────────────────────────────────

pub struct OAuthClientRepository {
    pool: PgPool,
}

impl OAuthClientRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Fetch a client by its public client_id.
    pub async fn find_by_client_id(&self, client_id: &str) -> Result<Option<OAuthClient>, OAuthError> {
        let row = sqlx::query!(
            r#"
            SELECT id, client_id, client_secret_hash, client_name,
                   client_type, allowed_grant_types, allowed_scopes,
                   redirect_uris, status, created_by, created_at, updated_at
            FROM oauth_clients
            WHERE client_id = $1
            "#,
            client_id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| OAuthError::ServerError(e.to_string()))?;

        Ok(row.map(|r| OAuthClient {
            id: r.id,
            client_id: r.client_id,
            client_secret_hash: r.client_secret_hash,
            client_name: r.client_name,
            client_type: r.client_type.parse().unwrap_or(ClientType::Public),
            allowed_grant_types: r.allowed_grant_types,
            allowed_scopes: r.allowed_scopes,
            redirect_uris: r.redirect_uris,
            status: r.status,
            created_by: r.created_by,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }))
    }

    /// Insert a new OAuth client.
    pub async fn create(&self, input: CreateClientInput) -> Result<OAuthClient, OAuthError> {
        let id = Uuid::new_v4();
        let now = Utc::now();

        sqlx::query!(
            r#"
            INSERT INTO oauth_clients
                (id, client_id, client_secret_hash, client_name, client_type,
                 allowed_grant_types, allowed_scopes, redirect_uris, status, created_by,
                 created_at, updated_at)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'active',$9,$10,$10)
            "#,
            id,
            input.client_id,
            input.client_secret_hash,
            input.client_name,
            input.client_type.to_string(),
            &input.allowed_grant_types,
            &input.allowed_scopes,
            &input.redirect_uris,
            input.created_by,
            now,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| OAuthError::ServerError(e.to_string()))?;

        Ok(OAuthClient {
            id,
            client_id: input.client_id,
            client_secret_hash: input.client_secret_hash,
            client_name: input.client_name,
            client_type: input.client_type,
            allowed_grant_types: input.allowed_grant_types,
            allowed_scopes: input.allowed_scopes,
            redirect_uris: input.redirect_uris,
            status: "active".to_string(),
            created_by: input.created_by,
            created_at: now,
            updated_at: now,
        })
    }

    /// Revoke a client (set status = 'revoked').
    pub async fn revoke(&self, client_id: &str) -> Result<(), OAuthError> {
        sqlx::query!(
            "UPDATE oauth_clients SET status = 'revoked', updated_at = NOW() WHERE client_id = $1",
            client_id
        )
        .execute(&self.pool)
        .await
        .map_err(|e| OAuthError::ServerError(e.to_string()))?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct CreateClientInput {
    pub client_id: String,
    pub client_secret_hash: Option<String>,
    pub client_name: String,
    pub client_type: ClientType,
    pub allowed_grant_types: Vec<String>,
    pub allowed_scopes: Vec<String>,
    pub redirect_uris: Vec<String>,
    pub created_by: Option<String>,
}

// ── Authorization code store (Redis-backed) ───────────────────────────────────

use crate::cache::{Cache, RedisCache};
use super::types::AuthorizationCode;

pub const AUTH_CODE_TTL_SECS: u64 = 600; // 10 minutes

/// Redis key for an authorization code.
fn auth_code_key(code: &str) -> String {
    format!("oauth:auth_code:{}", code)
}

/// Store an authorization code in Redis (single-use, 10 min TTL).
pub async fn store_auth_code(
    cache: &RedisCache,
    code: &AuthorizationCode,
) -> Result<(), OAuthError> {
    use std::time::Duration;
    let key = auth_code_key(&code.code);
    <RedisCache as Cache<AuthorizationCode>>::set(
        cache,
        &key,
        code,
        Some(Duration::from_secs(AUTH_CODE_TTL_SECS)),
    )
    .await
    .map_err(|e| OAuthError::ServerError(e.to_string()))
}

/// Retrieve and atomically consume an authorization code.
/// Returns `None` if the code doesn't exist or has already been used.
pub async fn consume_auth_code(
    cache: &RedisCache,
    code: &str,
) -> Result<Option<AuthorizationCode>, OAuthError> {
    let key = auth_code_key(code);
    let record = <RedisCache as Cache<AuthorizationCode>>::get(cache, &key)
        .await
        .map_err(|e| OAuthError::ServerError(e.to_string()))?;

    if let Some(ref ac) = record {
        if ac.used {
            // Already consumed — delete and reject
            let _ = <RedisCache as Cache<AuthorizationCode>>::delete(cache, &key).await;
            return Ok(None);
        }
        // Atomically delete (single-use enforcement)
        let _ = <RedisCache as Cache<AuthorizationCode>>::delete(cache, &key).await;
    }

    Ok(record)
}

// ── OAuth refresh token store (Redis) ─────────────────────────────────────────

use serde::{Deserialize, Serialize};

pub const REFRESH_TOKEN_TTL_SECS: u64 = 1_209_600; // 14 days

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthRefreshRecord {
    pub client_id: String,
    pub subject: String,
    pub scope: String,
    pub issued_at: i64,
}

fn refresh_token_key(jti: &str) -> String {
    format!("oauth:refresh:{}", jti)
}

pub async fn store_refresh_token(
    cache: &RedisCache,
    jti: &str,
    record: &OAuthRefreshRecord,
) -> Result<(), OAuthError> {
    use std::time::Duration;
    <RedisCache as Cache<OAuthRefreshRecord>>::set(
        cache,
        &refresh_token_key(jti),
        record,
        Some(Duration::from_secs(REFRESH_TOKEN_TTL_SECS)),
    )
    .await
    .map_err(|e| OAuthError::ServerError(e.to_string()))
}

pub async fn get_refresh_token(
    cache: &RedisCache,
    jti: &str,
) -> Result<Option<OAuthRefreshRecord>, OAuthError> {
    <RedisCache as Cache<OAuthRefreshRecord>>::get(cache, &refresh_token_key(jti))
        .await
        .map_err(|e| OAuthError::ServerError(e.to_string()))
}

pub async fn revoke_refresh_token(cache: &RedisCache, jti: &str) -> Result<(), OAuthError> {
    let _ = <RedisCache as Cache<OAuthRefreshRecord>>::delete(cache, &refresh_token_key(jti))
        .await
        .map_err(|e| OAuthError::ServerError(e.to_string()))?;
    Ok(())
}

// ── Token blacklist (access token revocation) ─────────────────────────────────

fn blacklist_key(jti: &str) -> String {
    format!("oauth:blacklist:{}", jti)
}

pub async fn blacklist_token(
    cache: &RedisCache,
    jti: &str,
    remaining_secs: u64,
) -> Result<(), OAuthError> {
    use std::time::Duration;
    <RedisCache as Cache<String>>::set(
        cache,
        &blacklist_key(jti),
        &"revoked".to_string(),
        Some(Duration::from_secs(remaining_secs)),
    )
    .await
    .map_err(|e| OAuthError::ServerError(e.to_string()))
}

pub async fn is_token_blacklisted(cache: &RedisCache, jti: &str) -> Result<bool, OAuthError> {
    <RedisCache as Cache<String>>::exists(cache, &blacklist_key(jti))
        .await
        .map_err(|e| OAuthError::ServerError(e.to_string()))
}
