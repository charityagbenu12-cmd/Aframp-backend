//! IP Reputation Repository
//!
//! Manages IP reputation records and evidence tracking for suspicious IP detection.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use std::net::IpAddr;
use uuid::Uuid;

use super::error::{DatabaseError, DbResult};
use crate::database::Repository;

// ── IP Reputation Entity ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct IpReputationEntity {
    pub id: String,
    pub ip_address_or_cidr: String, // Store as string for INET type compatibility
    pub reputation_score: rust_decimal::Decimal,
    pub detection_source: String,
    pub first_seen_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
    pub block_status: Option<String>, // 'temporary', 'permanent', 'shadow'
    pub block_expiry_at: Option<DateTime<Utc>>,
    pub is_whitelisted: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl IpReputationEntity {
    pub fn is_blocked(&self) -> bool {
        match self.block_status.as_deref() {
            Some("temporary") | Some("permanent") | Some("shadow") => {
                // Check if temporary block has expired
                if let (Some("temporary"), Some(expiry)) = (self.block_status.as_deref(), self.block_expiry_at) {
                    expiry > Utc::now()
                } else {
                    true
                }
            }
            _ => false,
        }
    }

    pub fn is_hard_blocked(&self) -> bool {
        matches!(self.block_status.as_deref(), Some("temporary") | Some("permanent"))
    }

    pub fn is_shadow_blocked(&self) -> bool {
        self.block_status.as_deref() == Some("shadow")
    }
}

// ── IP Evidence Entity ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct IpEvidenceEntity {
    pub id: String,
    pub ip_address_or_cidr: String,
    pub evidence_type: String,
    pub evidence_detail: serde_json::Value,
    pub detected_at: DateTime<Utc>,
    pub consumer_id: Option<String>,
    pub created_at: DateTime<Utc>,
}

// ── IP Reputation Repository ──────────────────────────────────────────────────

pub struct IpReputationRepository {
    db: Repository,
}

impl IpReputationRepository {
    pub fn new(db: Repository) -> Self {
        Self { db }
    }

    /// Get or create IP reputation record
    pub async fn get_or_create_reputation(
        &self,
        ip: &str,
        detection_source: &str,
    ) -> DbResult<IpReputationEntity> {
        let reputation = sqlx::query_as::<_, IpReputationEntity>(
            r#"
            INSERT INTO ip_reputation_records (ip_address_or_cidr, detection_source)
            VALUES ($1, $2)
            ON CONFLICT (ip_address_or_cidr) DO UPDATE SET
                last_seen_at = NOW(),
                updated_at = NOW()
            RETURNING *
            "#,
        )
        .bind(ip)
        .bind(detection_source)
        .fetch_one(self.db.pool())
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(reputation)
    }

    /// Get IP reputation by IP address
    pub async fn get_reputation(&self, ip: &str) -> DbResult<Option<IpReputationEntity>> {
        let reputation = sqlx::query_as::<_, IpReputationEntity>(
            "SELECT * FROM ip_reputation_records WHERE ip_address_or_cidr = $1",
        )
        .bind(ip)
        .fetch_optional(self.db.pool())
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(reputation)
    }

    /// Update reputation score
    pub async fn update_reputation_score(
        &self,
        ip: &str,
        new_score: rust_decimal::Decimal,
    ) -> DbResult<IpReputationEntity> {
        let reputation = sqlx::query_as::<_, IpReputationEntity>(
            r#"
            UPDATE ip_reputation_records
            SET reputation_score = $2, updated_at = NOW()
            WHERE ip_address_or_cidr = $1
            RETURNING *
            "#,
        )
        .bind(ip)
        .bind(new_score)
        .fetch_one(self.db.pool())
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(reputation)
    }

    /// Apply block to IP
    pub async fn apply_block(
        &self,
        ip: &str,
        block_type: &str,
        expiry: Option<DateTime<Utc>>,
    ) -> DbResult<IpReputationEntity> {
        let reputation = sqlx::query_as::<_, IpReputationEntity>(
            r#"
            UPDATE ip_reputation_records
            SET block_status = $2, block_expiry_at = $3, updated_at = NOW()
            WHERE ip_address_or_cidr = $1
            RETURNING *
            "#,
        )
        .bind(ip)
        .bind(block_type)
        .bind(expiry)
        .fetch_one(self.db.pool())
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(reputation)
    }

    /// Remove block from IP
    pub async fn remove_block(&self, ip: &str) -> DbResult<IpReputationEntity> {
        let reputation = sqlx::query_as::<_, IpReputationEntity>(
            r#"
            UPDATE ip_reputation_records
            SET block_status = NULL, block_expiry_at = NULL, updated_at = NOW()
            WHERE ip_address_or_cidr = $1
            RETURNING *
            "#,
        )
        .bind(ip)
        .fetch_one(self.db.pool())
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(reputation)
    }

    /// Whitelist IP (prevents automated blocking)
    pub async fn whitelist_ip(&self, ip: &str) -> DbResult<IpReputationEntity> {
        let reputation = sqlx::query_as::<_, IpReputationEntity>(
            r#"
            UPDATE ip_reputation_records
            SET is_whitelisted = TRUE, block_status = NULL, block_expiry_at = NULL, updated_at = NOW()
            WHERE ip_address_or_cidr = $1
            RETURNING *
            "#,
        )
        .bind(ip)
        .fetch_one(self.db.pool())
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(reputation)
    }

    /// Add evidence record
    pub async fn add_evidence(
        &self,
        ip: &str,
        evidence_type: &str,
        evidence_detail: serde_json::Value,
        consumer_id: Option<&str>,
    ) -> DbResult<IpEvidenceEntity> {
        let evidence = sqlx::query_as::<_, IpEvidenceEntity>(
            r#"
            INSERT INTO ip_evidence_records (ip_address_or_cidr, evidence_type, evidence_detail, consumer_id)
            VALUES ($1, $2, $3, $4)
            RETURNING *
            "#,
        )
        .bind(ip)
        .bind(evidence_type)
        .bind(evidence_detail)
        .bind(consumer_id)
        .fetch_one(self.db.pool())
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(evidence)
    }

    /// Get evidence records for IP
    pub async fn get_evidence_for_ip(
        &self,
        ip: &str,
        limit: Option<i64>,
    ) -> DbResult<Vec<IpEvidenceEntity>> {
        let limit = limit.unwrap_or(100);
        let evidence = sqlx::query_as::<_, IpEvidenceEntity>(
            r#"
            SELECT * FROM ip_evidence_records
            WHERE ip_address_or_cidr = $1
            ORDER BY detected_at DESC
            LIMIT $2
            "#,
        )
        .bind(ip)
        .bind(limit)
        .fetch_all(self.db.pool())
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(evidence)
    }

    /// Get all blocked IPs (for Redis bootstrap)
    pub async fn get_all_blocked_ips(&self) -> DbResult<Vec<IpReputationEntity>> {
        let blocked_ips = sqlx::query_as::<_, IpReputationEntity>(
            r#"
            SELECT * FROM ip_reputation_records
            WHERE block_status IS NOT NULL
            AND (block_expiry_at IS NULL OR block_expiry_at > NOW())
            AND is_whitelisted = FALSE
            "#,
        )
        .fetch_all(self.db.pool())
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(blocked_ips)
    }

    /// Get flagged IPs with pagination
    pub async fn get_flagged_ips(
        &self,
        limit: i64,
        offset: i64,
    ) -> DbResult<Vec<IpReputationEntity>> {
        let ips = sqlx::query_as::<_, IpReputationEntity>(
            r#"
            SELECT * FROM ip_reputation_records
            WHERE reputation_score < 0
            ORDER BY reputation_score ASC, last_seen_at DESC
            LIMIT $1 OFFSET $2
            "#,
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(self.db.pool())
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(ips)
    }

    /// Clean up expired temporary blocks
    pub async fn cleanup_expired_blocks(&self) -> DbResult<i64> {
        let result = sqlx::query(
            r#"
            UPDATE ip_reputation_records
            SET block_status = NULL, block_expiry_at = NULL, updated_at = NOW()
            WHERE block_status = 'temporary'
            AND block_expiry_at IS NOT NULL
            AND block_expiry_at <= NOW()
            "#,
        )
        .execute(self.db.pool())
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(result.rows_affected() as i64)
    }
}