//! Token registry repository for OAuth 2.0 access token tracking
//!
//! Persists token metadata for:
//! - JTI tracking
//! - Revocation status
//! - Token lifecycle management

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use super::error::{DatabaseError, DatabaseErrorKind, DbResult};
use crate::database::Repository;

// ── Token registry entity ────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct TokenRegistry {
    pub id: String,
    pub jti: String,
    pub consumer_id: String,
    pub client_id: String,
    pub scope: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revoked: bool,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// ── Create request ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateTokenRegistryRequest {
    pub jti: String,
    pub consumer_id: String,
    pub client_id: String,
    pub scope: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

// ── Token registry repository ────────────────────────────────────────────────

pub struct TokenRegistryRepository {
    db: Repository,
}

impl TokenRegistryRepository {
    pub fn new(db: Repository) -> Self {
        Self { db }
    }

    /// Create a new token registry entry
    pub async fn create(&self, req: CreateTokenRegistryRequest) -> DbResult<TokenRegistry> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();

        let token = sqlx::query_as::<_, TokenRegistry>(
            r#"
            INSERT INTO token_registry (
                id, jti, consumer_id, client_id, scope,
                issued_at, expires_at, revoked, revoked_at,
                created_at, updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            RETURNING *
            "#,
        )
        .bind(&id)
        .bind(&req.jti)
        .bind(&req.consumer_id)
        .bind(&req.client_id)
        .bind(&req.scope)
        .bind(req.issued_at)
        .bind(req.expires_at)
        .bind(false)
        .bind::<Option<DateTime<Utc>>>(None)
        .bind(now)
        .bind(now)
        .fetch_one(self.db.pool())
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(token)
    }

    /// Find token by JTI
    pub async fn find_by_jti(&self, jti: &str) -> DbResult<Option<TokenRegistry>> {
        let token = sqlx::query_as::<_, TokenRegistry>(
            "SELECT * FROM token_registry WHERE jti = $1",
        )
        .bind(jti)
        .fetch_optional(self.db.pool())
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(token)
    }

    /// Find token by ID
    pub async fn find_by_id(&self, id: &str) -> DbResult<Option<TokenRegistry>> {
        let token = sqlx::query_as::<_, TokenRegistry>(
            "SELECT * FROM token_registry WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(self.db.pool())
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(token)
    }

    /// List tokens for a consumer
    pub async fn list_by_consumer(
        &self,
        consumer_id: &str,
        limit: i64,
        offset: i64,
    ) -> DbResult<Vec<TokenRegistry>> {
        let tokens = sqlx::query_as::<_, TokenRegistry>(
            r#"
            SELECT * FROM token_registry
            WHERE consumer_id = $1
            ORDER BY created_at DESC
            LIMIT $2 OFFSET $3
            "#,
        )
        .bind(consumer_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(self.db.pool())
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(tokens)
    }

    /// Count active tokens for a consumer
    pub async fn count_active_tokens(&self, consumer_id: &str) -> DbResult<i64> {
        let result = sqlx::query_scalar::<_, i64>(
            r#"
            SELECT COUNT(*) FROM token_registry
            WHERE consumer_id = $1
            AND revoked = false
            AND expires_at > NOW()
            "#,
        )
        .bind(consumer_id)
        .fetch_one(self.db.pool())
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(result)
    }

    /// Revoke a token by JTI
    pub async fn revoke(&self, jti: &str) -> DbResult<bool> {
        let now = Utc::now();

        let result = sqlx::query(
            r#"
            UPDATE token_registry
            SET revoked = true, revoked_at = $1, updated_at = $2
            WHERE jti = $3 AND revoked = false
            "#,
        )
        .bind(now)
        .bind(now)
        .bind(jti)
        .execute(self.db.pool())
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(result.rows_affected() > 0)
    }

    /// Check if token is revoked
    pub async fn is_revoked(&self, jti: &str) -> DbResult<bool> {
        let result = sqlx::query_scalar::<_, bool>(
            "SELECT revoked FROM token_registry WHERE jti = $1",
        )
        .bind(jti)
        .fetch_optional(self.db.pool())
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(result.unwrap_or(false))
    }

    /// Revoke all tokens for a consumer
    pub async fn revoke_all_for_consumer(&self, consumer_id: &str) -> DbResult<u64> {
        let now = Utc::now();

        let result = sqlx::query(
            r#"
            UPDATE token_registry
            SET revoked = true, revoked_at = $1, updated_at = $2
            WHERE consumer_id = $3 AND revoked = false
            "#,
        )
        .bind(now)
        .bind(now)
        .bind(consumer_id)
        .execute(self.db.pool())
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(result.rows_affected())
    }

    /// Delete expired tokens (cleanup)
    pub async fn delete_expired(&self, before: DateTime<Utc>) -> DbResult<u64> {
        let result = sqlx::query(
            "DELETE FROM token_registry WHERE expires_at < $1",
        )
        .bind(before)
        .execute(self.db.pool())
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(result.rows_affected())
    }

    /// Get token statistics
    pub async fn get_stats(&self) -> DbResult<TokenRegistryStats> {
        let stats = sqlx::query_as::<_, TokenRegistryStats>(
            r#"
            SELECT
                COUNT(*) as total_tokens,
                COUNT(CASE WHEN revoked = true THEN 1 END) as revoked_tokens,
                COUNT(CASE WHEN revoked = false AND expires_at > NOW() THEN 1 END) as active_tokens,
                COUNT(CASE WHEN expires_at < NOW() THEN 1 END) as expired_tokens
            FROM token_registry
            "#,
        )
        .fetch_one(self.db.pool())
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(stats)
    }
}

// ── Statistics ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct TokenRegistryStats {
    pub total_tokens: i64,
    pub revoked_tokens: i64,
    pub active_tokens: i64,
    pub expired_tokens: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_registry_serialization() {
        let now = Utc::now();
        let token = TokenRegistry {
            id: "id_1".to_string(),
            jti: "jti_123".to_string(),
            consumer_id: "consumer_1".to_string(),
            client_id: "client_1".to_string(),
            scope: "read write".to_string(),
            issued_at: now,
            expires_at: now + chrono::Duration::hours(1),
            revoked: false,
            revoked_at: None,
            created_at: now,
            updated_at: now,
        };

        let json = serde_json::to_string(&token).unwrap();
        let deserialized: TokenRegistry = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.jti, token.jti);
    }
}
