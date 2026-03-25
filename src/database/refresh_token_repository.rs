//! Refresh token repository for OAuth 2.0 token rotation and theft detection
//!
//! Persists refresh token metadata with:
//! - Token family tracking for theft detection
//! - Token rotation history
//! - Status lifecycle management
//! - Revocation and expiry tracking

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use super::error::{DatabaseError, DbResult};
use crate::database::Repository;
use crate::auth::refresh_token_service::RefreshTokenStatus;

// ── Refresh token entity ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct RefreshToken {
    pub id: String,
    pub token_id: String,
    pub family_id: String,
    pub token_hash: String,
    pub consumer_id: String,
    pub client_id: String,
    pub scope: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub family_expires_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub parent_token_id: Option<String>,
    pub replacement_token_id: Option<String>,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// ── Create request ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateRefreshTokenRequest {
    pub token_id: String,
    pub family_id: String,
    pub token_hash: String,
    pub consumer_id: String,
    pub client_id: String,
    pub scope: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub family_expires_at: DateTime<Utc>,
    pub parent_token_id: Option<String>,
}

// ── Refresh token repository ─────────────────────────────────────────────────

pub struct RefreshTokenRepository {
    db: Repository,
}

impl RefreshTokenRepository {
    pub fn new(db: Repository) -> Self {
        Self { db }
    }

    /// Create a new refresh token
    pub async fn create(&self, req: CreateRefreshTokenRequest) -> DbResult<RefreshToken> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();

        let token = sqlx::query_as::<_, RefreshToken>(
            r#"
            INSERT INTO refresh_tokens (
                id, token_id, family_id, token_hash, consumer_id, client_id,
                scope, issued_at, expires_at, family_expires_at, parent_token_id,
                status, created_at, updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
            RETURNING *
            "#,
        )
        .bind(&id)
        .bind(&req.token_id)
        .bind(&req.family_id)
        .bind(&req.token_hash)
        .bind(&req.consumer_id)
        .bind(&req.client_id)
        .bind(&req.scope)
        .bind(req.issued_at)
        .bind(req.expires_at)
        .bind(req.family_expires_at)
        .bind(&req.parent_token_id)
        .bind(RefreshTokenStatus::Active.as_str())
        .bind(now)
        .bind(now)
        .fetch_one(self.db.pool())
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(token)
    }

    /// Find token by token_id
    pub async fn find_by_token_id(&self, token_id: &str) -> DbResult<Option<RefreshToken>> {
        let token = sqlx::query_as::<_, RefreshToken>(
            "SELECT * FROM refresh_tokens WHERE token_id = $1",
        )
        .bind(token_id)
        .fetch_optional(self.db.pool())
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(token)
    }

    /// Find token by ID
    pub async fn find_by_id(&self, id: &str) -> DbResult<Option<RefreshToken>> {
        let token = sqlx::query_as::<_, RefreshToken>(
            "SELECT * FROM refresh_tokens WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(self.db.pool())
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(token)
    }

    /// Find all tokens in a family
    pub async fn find_by_family(&self, family_id: &str) -> DbResult<Vec<RefreshToken>> {
        let tokens = sqlx::query_as::<_, RefreshToken>(
            "SELECT * FROM refresh_tokens WHERE family_id = $1 ORDER BY created_at DESC",
        )
        .bind(family_id)
        .fetch_all(self.db.pool())
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(tokens)
    }

    /// List active tokens for a consumer
    pub async fn list_active_by_consumer(
        &self,
        consumer_id: &str,
        limit: i64,
        offset: i64,
    ) -> DbResult<Vec<RefreshToken>> {
        let tokens = sqlx::query_as::<_, RefreshToken>(
            r#"
            SELECT * FROM refresh_tokens
            WHERE consumer_id = $1
            AND status = 'active'
            AND expires_at > NOW()
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
            SELECT COUNT(*) FROM refresh_tokens
            WHERE consumer_id = $1
            AND status = 'active'
            AND expires_at > NOW()
            "#,
        )
        .bind(consumer_id)
        .fetch_one(self.db.pool())
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(result)
    }

    /// Mark token as used (for theft detection)
    pub async fn mark_as_used(&self, token_id: &str) -> DbResult<bool> {
        let now = Utc::now();

        let result = sqlx::query(
            r#"
            UPDATE refresh_tokens
            SET status = 'used', last_used_at = $1, updated_at = $2
            WHERE token_id = $3 AND status = 'active'
            "#,
        )
        .bind(now)
        .bind(now)
        .bind(token_id)
        .execute(self.db.pool())
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(result.rows_affected() > 0)
    }

    /// Set replacement token for rotation
    pub async fn set_replacement(
        &self,
        token_id: &str,
        replacement_token_id: &str,
    ) -> DbResult<bool> {
        let now = Utc::now();

        let result = sqlx::query(
            r#"
            UPDATE refresh_tokens
            SET replacement_token_id = $1, updated_at = $2
            WHERE token_id = $3
            "#,
        )
        .bind(replacement_token_id)
        .bind(now)
        .bind(token_id)
        .execute(self.db.pool())
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(result.rows_affected() > 0)
    }

    /// Revoke a token
    pub async fn revoke(&self, token_id: &str) -> DbResult<bool> {
        let now = Utc::now();

        let result = sqlx::query(
            r#"
            UPDATE refresh_tokens
            SET status = 'revoked', updated_at = $1
            WHERE token_id = $2 AND status != 'revoked'
            "#,
        )
        .bind(now)
        .bind(token_id)
        .execute(self.db.pool())
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(result.rows_affected() > 0)
    }

    /// Revoke entire token family (theft detection)
    pub async fn revoke_family(&self, family_id: &str) -> DbResult<u64> {
        let now = Utc::now();

        let result = sqlx::query(
            r#"
            UPDATE refresh_tokens
            SET status = 'revoked', updated_at = $1
            WHERE family_id = $2 AND status != 'revoked'
            "#,
        )
        .bind(now)
        .bind(family_id)
        .execute(self.db.pool())
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(result.rows_affected())
    }

    /// Revoke all tokens for a consumer
    pub async fn revoke_all_for_consumer(&self, consumer_id: &str) -> DbResult<u64> {
        let now = Utc::now();

        let result = sqlx::query(
            r#"
            UPDATE refresh_tokens
            SET status = 'revoked', updated_at = $1
            WHERE consumer_id = $2 AND status != 'revoked'
            "#,
        )
        .bind(now)
        .bind(consumer_id)
        .execute(self.db.pool())
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(result.rows_affected())
    }

    /// Check if token has been used (reuse detection)
    pub async fn is_used(&self, token_id: &str) -> DbResult<bool> {
        let result = sqlx::query_scalar::<_, String>(
            "SELECT status FROM refresh_tokens WHERE token_id = $1",
        )
        .bind(token_id)
        .fetch_optional(self.db.pool())
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(result.map(|status| status == "used").unwrap_or(false))
    }

    /// Check if token is revoked
    pub async fn is_revoked(&self, token_id: &str) -> DbResult<bool> {
        let result = sqlx::query_scalar::<_, String>(
            "SELECT status FROM refresh_tokens WHERE token_id = $1",
        )
        .bind(token_id)
        .fetch_optional(self.db.pool())
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(result.map(|status| status == "revoked").unwrap_or(false))
    }

    /// Delete expired tokens (cleanup)
    pub async fn delete_expired(&self, before: DateTime<Utc>) -> DbResult<u64> {
        let result = sqlx::query(
            "DELETE FROM refresh_tokens WHERE expires_at < $1",
        )
        .bind(before)
        .execute(self.db.pool())
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(result.rows_affected())
    }

    /// Delete expired families (cleanup)
    pub async fn delete_expired_families(&self, before: DateTime<Utc>) -> DbResult<u64> {
        let result = sqlx::query(
            "DELETE FROM refresh_tokens WHERE family_expires_at < $1",
        )
        .bind(before)
        .execute(self.db.pool())
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(result.rows_affected())
    }

    /// Get token statistics
    pub async fn get_stats(&self) -> DbResult<RefreshTokenStats> {
        let stats = sqlx::query_as::<_, RefreshTokenStats>(
            r#"
            SELECT
                COUNT(*) as total_tokens,
                COUNT(CASE WHEN status = 'active' AND expires_at > NOW() THEN 1 END) as active_tokens,
                COUNT(CASE WHEN status = 'used' THEN 1 END) as used_tokens,
                COUNT(CASE WHEN status = 'revoked' THEN 1 END) as revoked_tokens,
                COUNT(CASE WHEN expires_at < NOW() THEN 1 END) as expired_tokens,
                COUNT(DISTINCT family_id) as total_families
            FROM refresh_tokens
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
pub struct RefreshTokenStats {
    pub total_tokens: i64,
    pub active_tokens: i64,
    pub used_tokens: i64,
    pub revoked_tokens: i64,
    pub expired_tokens: i64,
    pub total_families: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_refresh_token_serialization() {
        let now = Utc::now();
        let token = RefreshToken {
            id: "id_1".to_string(),
            token_id: "token_123".to_string(),
            family_id: "family_123".to_string(),
            token_hash: "hash_123".to_string(),
            consumer_id: "consumer_1".to_string(),
            client_id: "client_1".to_string(),
            scope: "read write".to_string(),
            issued_at: now,
            expires_at: now + chrono::Duration::days(7),
            family_expires_at: now + chrono::Duration::days(30),
            last_used_at: None,
            parent_token_id: None,
            replacement_token_id: None,
            status: "active".to_string(),
            created_at: now,
            updated_at: now,
        };

        let json = serde_json::to_string(&token).unwrap();
        let deserialized: RefreshToken = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.token_id, token.token_id);
        assert_eq!(deserialized.family_id, token.family_id);
    }
}
