//! OAuth Scope Repository
//!
//! Persists scope definitions and approvals in the database.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use super::error::{DatabaseError, DbResult};
use crate::database::Repository;

// ── OAuth Scope Entity ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct OAuthScopeEntity {
    pub id: String,
    pub name: String,
    pub description: String,
    pub category: String,
    pub is_sensitive: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// ── Scope Approval Entity ────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ScopeApprovalEntity {
    pub id: String,
    pub client_id: String,
    pub scope_name: String,
    pub status: String, // pending, approved, rejected
    pub requested_at: DateTime<Utc>,
    pub approved_at: Option<DateTime<Utc>>,
    pub approved_by: Option<String>,
    pub rejection_reason: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// ── OAuth Scope Repository ───────────────────────────────────────────────────

pub struct OAuthScopeRepository {
    db: Repository,
}

impl OAuthScopeRepository {
    pub fn new(db: Repository) -> Self {
        Self { db }
    }

    /// Create or update a scope
    pub async fn upsert_scope(
        &self,
        name: &str,
        description: &str,
        category: &str,
        is_sensitive: bool,
    ) -> DbResult<OAuthScopeEntity> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();

        let scope = sqlx::query_as::<_, OAuthScopeEntity>(
            r#"
            INSERT INTO oauth_scopes (id, name, description, category, is_sensitive, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT (name) DO UPDATE SET
                description = $3,
                category = $4,
                is_sensitive = $5,
                updated_at = $7
            RETURNING *
            "#,
        )
        .bind(&id)
        .bind(name)
        .bind(description)
        .bind(category)
        .bind(is_sensitive)
        .bind(now)
        .bind(now)
        .fetch_one(self.db.pool())
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(scope)
    }

    /// Get scope by name
    pub async fn get_scope(&self, name: &str) -> DbResult<Option<OAuthScopeEntity>> {
        let scope = sqlx::query_as::<_, OAuthScopeEntity>(
            "SELECT * FROM oauth_scopes WHERE name = $1",
        )
        .bind(name)
        .fetch_optional(self.db.pool())
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(scope)
    }

    /// Get all scopes
    pub async fn get_all_scopes(&self) -> DbResult<Vec<OAuthScopeEntity>> {
        let scopes = sqlx::query_as::<_, OAuthScopeEntity>(
            "SELECT * FROM oauth_scopes ORDER BY category, name",
        )
        .fetch_all(self.db.pool())
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(scopes)
    }

    /// Get scopes by category
    pub async fn get_scopes_by_category(&self, category: &str) -> DbResult<Vec<OAuthScopeEntity>> {
        let scopes = sqlx::query_as::<_, OAuthScopeEntity>(
            "SELECT * FROM oauth_scopes WHERE category = $1 ORDER BY name",
        )
        .bind(category)
        .fetch_all(self.db.pool())
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(scopes)
    }

    /// Get sensitive scopes
    pub async fn get_sensitive_scopes(&self) -> DbResult<Vec<OAuthScopeEntity>> {
        let scopes = sqlx::query_as::<_, OAuthScopeEntity>(
            "SELECT * FROM oauth_scopes WHERE is_sensitive = true ORDER BY category, name",
        )
        .fetch_all(self.db.pool())
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(scopes)
    }

    /// Update scope sensitivity
    pub async fn update_scope_sensitivity(
        &self,
        name: &str,
        is_sensitive: bool,
    ) -> DbResult<bool> {
        let now = Utc::now();

        let result = sqlx::query(
            "UPDATE oauth_scopes SET is_sensitive = $1, updated_at = $2 WHERE name = $3",
        )
        .bind(is_sensitive)
        .bind(now)
        .bind(name)
        .execute(self.db.pool())
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(result.rows_affected() > 0)
    }

    // ── Scope Approval Methods ───────────────────────────────────────────────

    /// Create a scope approval request
    pub async fn create_approval(
        &self,
        client_id: &str,
        scope_name: &str,
    ) -> DbResult<ScopeApprovalEntity> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();

        let approval = sqlx::query_as::<_, ScopeApprovalEntity>(
            r#"
            INSERT INTO scope_approvals (id, client_id, scope_name, status, requested_at, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING *
            "#,
        )
        .bind(&id)
        .bind(client_id)
        .bind(scope_name)
        .bind("pending")
        .bind(now)
        .bind(now)
        .bind(now)
        .fetch_one(self.db.pool())
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(approval)
    }

    /// Get pending approvals
    pub async fn get_pending_approvals(&self) -> DbResult<Vec<ScopeApprovalEntity>> {
        let approvals = sqlx::query_as::<_, ScopeApprovalEntity>(
            "SELECT * FROM scope_approvals WHERE status = 'pending' ORDER BY requested_at DESC",
        )
        .fetch_all(self.db.pool())
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(approvals)
    }

    /// Get approvals for a client
    pub async fn get_client_approvals(
        &self,
        client_id: &str,
    ) -> DbResult<Vec<ScopeApprovalEntity>> {
        let approvals = sqlx::query_as::<_, ScopeApprovalEntity>(
            "SELECT * FROM scope_approvals WHERE client_id = $1 ORDER BY requested_at DESC",
        )
        .bind(client_id)
        .fetch_all(self.db.pool())
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(approvals)
    }

    /// Approve a scope request
    pub async fn approve_scope(
        &self,
        approval_id: &str,
        approved_by: &str,
    ) -> DbResult<bool> {
        let now = Utc::now();

        let result = sqlx::query(
            r#"
            UPDATE scope_approvals
            SET status = 'approved', approved_at = $1, approved_by = $2, updated_at = $3
            WHERE id = $4
            "#,
        )
        .bind(now)
        .bind(approved_by)
        .bind(now)
        .bind(approval_id)
        .execute(self.db.pool())
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(result.rows_affected() > 0)
    }

    /// Reject a scope request
    pub async fn reject_scope(
        &self,
        approval_id: &str,
        rejection_reason: &str,
    ) -> DbResult<bool> {
        let now = Utc::now();

        let result = sqlx::query(
            r#"
            UPDATE scope_approvals
            SET status = 'rejected', rejection_reason = $1, updated_at = $2
            WHERE id = $3
            "#,
        )
        .bind(rejection_reason)
        .bind(now)
        .bind(approval_id)
        .execute(self.db.pool())
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(result.rows_affected() > 0)
    }

    /// Check if a scope is approved for a client
    pub async fn is_scope_approved(&self, client_id: &str, scope_name: &str) -> DbResult<bool> {
        let result = sqlx::query_scalar::<_, bool>(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM scope_approvals
                WHERE client_id = $1 AND scope_name = $2 AND status = 'approved'
            )
            "#,
        )
        .bind(client_id)
        .bind(scope_name)
        .fetch_one(self.db.pool())
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oauth_scope_entity_serialization() {
        let now = Utc::now();
        let scope = OAuthScopeEntity {
            id: "id_1".to_string(),
            name: "wallet:read".to_string(),
            description: "Read wallet".to_string(),
            category: "wallet".to_string(),
            is_sensitive: false,
            created_at: now,
            updated_at: now,
        };

        let json = serde_json::to_string(&scope).unwrap();
        let deserialized: OAuthScopeEntity = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.name, scope.name);
    }

    #[test]
    fn test_scope_approval_entity_serialization() {
        let now = Utc::now();
        let approval = ScopeApprovalEntity {
            id: "id_1".to_string(),
            client_id: "client_1".to_string(),
            scope_name: "wallet:trustline".to_string(),
            status: "pending".to_string(),
            requested_at: now,
            approved_at: None,
            approved_by: None,
            rejection_reason: None,
            created_at: now,
            updated_at: now,
        };

        let json = serde_json::to_string(&approval).unwrap();
        let deserialized: ScopeApprovalEntity = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.status, "pending");
    }
}
