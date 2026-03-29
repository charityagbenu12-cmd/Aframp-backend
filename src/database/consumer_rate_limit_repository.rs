//! Repository for consumer rate limit profiles and overrides (Issue #175)

use super::{DatabaseError, PgPool, TransactionalRepository};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{json::PgJson, FromRow, PgPool};
use std::sync::Arc;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow, sqlx::Type)]
#[sqlx(type_name = "consumer_type", rename_all = "snake_case")]
pub enum ConsumerType {
    MobileClient,
    Partner,
    Microservice,
    Admin,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LimitDimension {
    pub limit: i64,
    pub window_secs: i64,
    #[serde(default)]
    pub burst_multiplier: Option<f64>,
    #[serde(default)]
    pub allow_burst: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitsConfig {
    #[serde(flatten)]
    pub global: LimitDimension,
    #[serde(flatten, prefix = "endpoint_")]
    pub endpoint: std::collections::HashMap<String, LimitDimension>,  // endpoint_standard, etc.
    #[serde(flatten, prefix = "tx_")]
    pub transaction_type: std::collections::HashMap<String, LimitDimension>,
    #[serde(flatten)]
    pub ip: LimitDimension,
}

pub type LimitsJson = serde_json::Value;  // Flexible JSONB

#[derive(Debug, Clone, FromRow)]
pub struct Profile {
    pub consumer_type: String,
    pub limits_json: PgJson<LimitsJson>,
    pub burst_multiplier: f64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow)]
pub struct Override {
    pub id: Uuid,
    pub consumer_id: Uuid,
    pub limits_json: PgJson<LimitsJson>,
    pub expiry_at: Option<DateTime<Utc>>,
    pub created_by: Option<Uuid>,
    pub reason: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone)]
pub struct ConsumerRateLimitRepository {
    pool: Arc<PgPool>,
}

impl ConsumerRateLimitRepository {
    pub fn new(pool: Arc<PgPool>) -> Self {
        Self { pool }
    }

    pub async fn create_profile(
        &self,
        consumer_type: &str,
        limits_json: &LimitsJson,
        burst_multiplier: f64,
    ) -> Result<Profile, DatabaseError> {
        let profile = sqlx::query_as!(
            Profile,
            r#"
            INSERT INTO consumer_rate_limit_profiles (consumer_type, limits_json, burst_multiplier)
            VALUES ($1, $2, $3)
            RETURNING *
            "#,
            consumer_type,
            limits_json as PgJson<LimitsJson>,
            burst_multiplier
        )
        .fetch_one(self.pool.as_ref())
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(profile)
    }

    pub async fn get_profile(&self, consumer_type: &str) -> Result<Option<Profile>, DatabaseError> {
        let profile = sqlx::query_as!(
            Profile,
            "SELECT * FROM consumer_rate_limit_profiles WHERE consumer_type = $1",
            consumer_type
        )
        .fetch_optional(self.pool.as_ref())
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(profile)
    }

    pub async fn create_override(
        &self,
        consumer_id: Uuid,
        limits_json: &LimitsJson,
        expiry_at: Option<DateTime<Utc>>,
        created_by: Option<Uuid>,
        reason: Option<String>,
    ) -> Result<Override, DatabaseError> {
        let override_rec = sqlx::query_as!(
            Override,
            r#"
            INSERT INTO consumer_rate_limit_overrides (consumer_id, limits_json, expiry_at, created_by, reason)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING *
            "#,
            consumer_id,
            limits_json as PgJson<LimitsJson>,
            expiry_at,
            created_by,
            reason
        )
        .fetch_one(self.pool.as_ref())
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(override_rec)
    }

    pub async fn delete_override(&self, override_id: Uuid) -> Result<bool, DatabaseError> {
        let result = sqlx::query!(
            "DELETE FROM consumer_rate_limit_overrides WHERE id = $1",
            override_id
        )
        .execute(self.pool.as_ref())
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(result.rows_affected() > 0)
    }

    /// Get effective limits: override OR profile (via PG func)
    pub async fn get_effective_limits(&self, consumer_id: Uuid) -> Result<Option<LimitsJson>, DatabaseError> {
        let json: Option<LimitsJson> = sqlx::query_scalar(
            "SELECT get_effective_rate_limits($1)",
            consumer_id
        )
        .fetch_optional(self.pool.as_ref())
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(json)
    }

    /// List active overrides for consumer
    pub async fn list_overrides(&self, consumer_id: Uuid) -> Result<Vec<Override>, DatabaseError> {
        let overrides = sqlx::query_as!(
            Override,
            r#"
            SELECT * FROM consumer_rate_limit_overrides 
            WHERE consumer_id = $1 
              AND (expiry_at IS NULL OR expiry_at > CURRENT_TIMESTAMP)
            ORDER BY created_at DESC
            "#,
            consumer_id
        )
        .fetch_all(self.pool.as_ref())
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(overrides)
    }
}

#[async_trait]
impl TransactionalRepository for ConsumerRateLimitRepository {
    fn pool(&self) -> &PgPool {
        self.pool.as_ref()
    }
}

