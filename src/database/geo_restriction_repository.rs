//! Geo-Restriction Repository
//!
//! Manages country access policies, region groupings, consumer overrides, and audit logging.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use super::error::{DatabaseError, DbResult};
use crate::database::Repository;

// ── Country Access Policy Entity ──────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct CountryAccessPolicyEntity {
    pub id: String,
    pub country_code: String,
    pub country_name: String,
    pub access_level: String, // 'allowed', 'restricted', 'blocked'
    pub restriction_reason: Option<String>,
    pub applicable_transaction_types: Vec<String>,
    pub enhanced_verification_required: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// ── Region Grouping Entity ────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct RegionGroupingEntity {
    pub id: String,
    pub region_name: String,
    pub member_country_codes: Vec<String>,
    pub access_level: Option<String>,
    pub restriction_reason: Option<String>,
    pub applicable_transaction_types: Vec<String>,
    pub enhanced_verification_required: Option<bool>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// ── Consumer Geo-Override Entity ──────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ConsumerGeoOverrideEntity {
    pub id: String,
    pub consumer_id: String,
    pub country_code: String,
    pub override_type: String, // 'allow', 'block'
    pub override_reason: String,
    pub granted_by_admin_id: String,
    pub expiry_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

// ── Geo-Restriction Audit Entity ──────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct GeoRestrictionAuditEntity {
    pub id: String,
    pub request_ip: String,
    pub resolved_country_code: Option<String>,
    pub applied_policy: String, // JSON
    pub access_decision: String,
    pub consumer_id: Option<String>,
    pub endpoint: Option<String>,
    pub transaction_type: Option<String>,
    pub user_agent: Option<String>,
    pub timestamp: DateTime<Utc>,
}

// ── Geo-Restriction Repository ────────────────────────────────────────────────

pub struct GeoRestrictionRepository {
    db: Repository,
}

impl GeoRestrictionRepository {
    pub fn new(db: Repository) -> Self {
        Self { db }
    }

    /// Get country access policy by country code
    pub async fn get_country_policy(&self, country_code: &str) -> DbResult<Option<CountryAccessPolicyEntity>> {
        let policy = sqlx::query_as::<_, CountryAccessPolicyEntity>(
            "SELECT * FROM country_access_policies WHERE country_code = $1",
        )
        .bind(country_code)
        .fetch_optional(self.db.pool())
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(policy)
    }

    /// Get all country access policies
    pub async fn get_all_country_policies(&self) -> DbResult<Vec<CountryAccessPolicyEntity>> {
        let policies = sqlx::query_as::<_, CountryAccessPolicyEntity>(
            "SELECT * FROM country_access_policies ORDER BY country_code",
        )
        .fetch_all(self.db.pool())
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(policies)
    }

    /// Update country access policy
    pub async fn update_country_policy(
        &self,
        country_code: &str,
        access_level: &str,
        restriction_reason: Option<&str>,
        applicable_transaction_types: &[String],
        enhanced_verification_required: bool,
    ) -> DbResult<CountryAccessPolicyEntity> {
        let policy = sqlx::query_as::<_, CountryAccessPolicyEntity>(
            r#"
            UPDATE country_access_policies
            SET access_level = $2, restriction_reason = $3,
                applicable_transaction_types = $4, enhanced_verification_required = $5
            WHERE country_code = $1
            RETURNING *
            "#,
        )
        .bind(country_code)
        .bind(access_level)
        .bind(restriction_reason)
        .bind(applicable_transaction_types)
        .bind(enhanced_verification_required)
        .fetch_one(self.db.pool())
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(policy)
    }

    /// Get region grouping by region name
    pub async fn get_region_grouping(&self, region_name: &str) -> DbResult<Option<RegionGroupingEntity>> {
        let region = sqlx::query_as::<_, RegionGroupingEntity>(
            "SELECT * FROM region_groupings WHERE region_name = $1",
        )
        .bind(region_name)
        .fetch_optional(self.db.pool())
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(region)
    }

    /// Get all region groupings
    pub async fn get_all_region_groupings(&self) -> DbResult<Vec<RegionGroupingEntity>> {
        let regions = sqlx::query_as::<_, RegionGroupingEntity>(
            "SELECT * FROM region_groupings ORDER BY region_name",
        )
        .fetch_all(self.db.pool())
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(regions)
    }

    /// Update region grouping policy
    pub async fn update_region_policy(
        &self,
        region_id: &str,
        access_level: Option<&str>,
        restriction_reason: Option<&str>,
        applicable_transaction_types: &[String],
        enhanced_verification_required: Option<bool>,
    ) -> DbResult<RegionGroupingEntity> {
        let region = sqlx::query_as::<_, RegionGroupingEntity>(
            r#"
            UPDATE region_groupings
            SET access_level = $2, restriction_reason = $3,
                applicable_transaction_types = $4, enhanced_verification_required = $5
            WHERE id = $1
            RETURNING *
            "#,
        )
        .bind(region_id)
        .bind(access_level)
        .bind(restriction_reason)
        .bind(applicable_transaction_types)
        .bind(enhanced_verification_required)
        .fetch_one(self.db.pool())
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(region)
    }

    /// Get active consumer geo-override
    pub async fn get_consumer_override(
        &self,
        consumer_id: &str,
        country_code: &str,
    ) -> DbResult<Option<ConsumerGeoOverrideEntity>> {
        let override_record = sqlx::query_as::<_, ConsumerGeoOverrideEntity>(
            r#"
            SELECT * FROM active_consumer_geo_overrides
            WHERE consumer_id = $1 AND country_code = $2
            "#,
        )
        .bind(consumer_id)
        .bind(country_code)
        .fetch_optional(self.db.pool())
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(override_record)
    }

    /// Get all active consumer overrides for a consumer
    pub async fn get_consumer_overrides(&self, consumer_id: &str) -> DbResult<Vec<ConsumerGeoOverrideEntity>> {
        let overrides = sqlx::query_as::<_, ConsumerGeoOverrideEntity>(
            r#"
            SELECT * FROM active_consumer_geo_overrides
            WHERE consumer_id = $1
            ORDER BY created_at DESC
            "#,
        )
        .bind(consumer_id)
        .fetch_all(self.db.pool())
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(overrides)
    }

    /// Create consumer geo-override
    pub async fn create_consumer_override(
        &self,
        consumer_id: &str,
        country_code: &str,
        override_type: &str,
        override_reason: &str,
        granted_by_admin_id: &str,
        expiry_at: Option<DateTime<Utc>>,
    ) -> DbResult<ConsumerGeoOverrideEntity> {
        let override_record = sqlx::query_as::<_, ConsumerGeoOverrideEntity>(
            r#"
            INSERT INTO consumer_geo_overrides
            (consumer_id, country_code, override_type, override_reason, granted_by_admin_id, expiry_at)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (consumer_id, country_code) DO UPDATE SET
                override_type = $3,
                override_reason = $4,
                granted_by_admin_id = $5,
                expiry_at = $6,
                created_at = NOW()
            RETURNING *
            "#,
        )
        .bind(consumer_id)
        .bind(country_code)
        .bind(override_type)
        .bind(override_reason)
        .bind(granted_by_admin_id)
        .bind(expiry_at)
        .fetch_one(self.db.pool())
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(override_record)
    }

    /// Delete consumer geo-override
    pub async fn delete_consumer_override(&self, override_id: &str) -> DbResult<bool> {
        let result = sqlx::query(
            "DELETE FROM consumer_geo_overrides WHERE id = $1",
        )
        .bind(override_id)
        .execute(self.db.pool())
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(result.rows_affected() > 0)
    }

    /// Log geo-restriction audit event
    pub async fn log_audit_event(
        &self,
        request_ip: &str,
        resolved_country_code: Option<&str>,
        applied_policy: &str,
        access_decision: &str,
        consumer_id: Option<&str>,
        endpoint: Option<&str>,
        transaction_type: Option<&str>,
        user_agent: Option<&str>,
    ) -> DbResult<()> {
        sqlx::query(
            r#"
            INSERT INTO geo_restriction_audit
            (request_ip, resolved_country_code, applied_policy, access_decision,
             consumer_id, endpoint, transaction_type, user_agent)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            "#,
        )
        .bind(request_ip)
        .bind(resolved_country_code)
        .bind(applied_policy)
        .bind(access_decision)
        .bind(consumer_id)
        .bind(endpoint)
        .bind(transaction_type)
        .bind(user_agent)
        .execute(self.db.pool())
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(())
    }

    /// Clean up expired consumer overrides
    pub async fn cleanup_expired_overrides(&self) -> DbResult<i64> {
        let result = sqlx::query(
            "DELETE FROM consumer_geo_overrides WHERE expiry_at IS NOT NULL AND expiry_at <= NOW()",
        )
        .execute(self.db.pool())
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(result.rows_affected() as i64)
    }

    /// Get geo-restriction statistics for reporting
    pub async fn get_geo_stats(&self, since: DateTime<Utc>) -> DbResult<serde_json::Value> {
        let stats = sqlx::query!(
            r#"
            SELECT
                resolved_country_code,
                access_decision,
                transaction_type,
                COUNT(*) as count
            FROM geo_restriction_audit
            WHERE timestamp >= $1
            GROUP BY resolved_country_code, access_decision, transaction_type
            ORDER BY resolved_country_code, count DESC
            "#,
            since
        )
        .fetch_all(self.db.pool())
        .await
        .map_err(DatabaseError::from_sqlx)?;

        // Convert to JSON structure
        let mut result = serde_json::Map::new();
        for stat in stats {
            let country = stat.resolved_country_code.unwrap_or_else(|| "unknown".to_string());
            let decision = stat.access_decision;
            let tx_type = stat.transaction_type.unwrap_or_else(|| "unknown".to_string());
            let count = stat.count.unwrap_or(0);

            result.insert(format!("{}_{}_{}", country, decision, tx_type), serde_json::Value::Number(count.into()));
        }

        Ok(serde_json::Value::Object(result))
    }
}