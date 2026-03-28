use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;
use bigdecimal::BigDecimal;
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type, PartialEq)]
#[sqlx(type_name = "kyc_tier", rename_all = "snake_case")]
pub enum KycTier {
    Unverified,
    Basic,
    Standard,
    Enhanced,
}

impl Default for KycTier {
    fn default() -> Self {
        KycTier::Unverified
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type, PartialEq)]
#[sqlx(type_name = "kyc_status", rename_all = "snake_case")]
pub enum KycStatus {
    Pending,
    Approved,
    Rejected,
    ManualReview,
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type, PartialEq)]
#[sqlx(type_name = "document_type", rename_all = "snake_case")]
pub enum DocumentType {
    NationalId,
    Passport,
    DriversLicense,
    UtilityBill,
    BankStatement,
    GovernmentLetter,
    SourceOfFunds,
    BusinessRegistration,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type, PartialEq)]
#[sqlx(type_name = "document_status", rename_all = "snake_case")]
pub enum DocumentStatus {
    Pending,
    Approved,
    Rejected,
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type, PartialEq)]
#[sqlx(type_name = "kyc_event_type", rename_all = "snake_case")]
pub enum KycEventType {
    SessionInitiated,
    DocumentSubmitted,
    SelfieSubmitted,
    ProviderCallback,
    StatusUpdated,
    ManualReviewAssigned,
    DecisionMade,
    TierChanged,
    LimitsUpdated,
    ResubmissionAllowed,
    EnhancedDueDiligenceTriggered,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct KycRecord {
    pub id: Uuid,
    pub consumer_id: Uuid,
    pub tier: KycTier,
    pub status: KycStatus,
    pub verification_provider: Option<String>,
    pub verification_session_id: Option<String>,
    pub verification_decision: Option<String>,
    pub decision_timestamp: Option<DateTime<Utc>>,
    pub decision_reason: Option<String>,
    pub reviewer_identity: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub resubmission_allowed_at: Option<DateTime<Utc>>,
    pub enhanced_due_diligence_active: bool,
    pub effective_tier: KycTier,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct KycDocument {
    pub id: Uuid,
    pub kyc_record_id: Uuid,
    pub document_type: DocumentType,
    pub document_number: Option<String>,
    pub issuing_country: Option<String>,
    pub expiry_date: Option<DateTime<Utc>>,
    pub front_image_reference: Option<String>,
    pub back_image_reference: Option<String>,
    pub selfie_image_reference: Option<String>,
    pub verification_outcome: Option<DocumentStatus>,
    pub rejection_reason: Option<String>,
    pub provider_document_id: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct KycEvent {
    pub id: Uuid,
    pub consumer_id: Uuid,
    pub kyc_record_id: Option<Uuid>,
    pub event_type: KycEventType,
    pub event_detail: Option<String>,
    pub provider_response: Option<String>,
    pub metadata: Option<serde_json::Value>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KycTierDefinition {
    pub tier: KycTier,
    pub name: String,
    pub description: String,
    pub required_documents: Vec<DocumentType>,
    pub max_transaction_amount: BigDecimal,
    pub daily_volume_limit: BigDecimal,
    pub monthly_volume_limit: BigDecimal,
    pub requires_enhanced_due_diligence: bool,
    pub cooling_off_period_days: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KycLimits {
    pub tier: KycTier,
    pub max_transaction_amount: BigDecimal,
    pub daily_volume_limit: BigDecimal,
    pub monthly_volume_limit: BigDecimal,
    pub daily_volume_used: BigDecimal,
    pub monthly_volume_used: BigDecimal,
    pub last_daily_reset: DateTime<Utc>,
    pub last_monthly_reset: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KycSession {
    pub session_id: String,
    pub consumer_id: Uuid,
    pub provider: String,
    pub target_tier: KycTier,
    pub status: KycStatus,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub callback_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManualReviewQueue {
    pub id: Uuid,
    pub kyc_record_id: Uuid,
    pub consumer_id: Uuid,
    pub priority: i32,
    pub assigned_to: Option<Uuid>,
    pub review_reason: String,
    pub provider_risk_score: Option<i32>,
    pub provider_flags: Option<Vec<String>>,
    pub created_at: DateTime<Utc>,
    pub assigned_at: Option<DateTime<Utc>>,
    pub resolved_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KycComplianceReport {
    pub report_date: DateTime<Utc>,
    pub total_verifications: i64,
    pub verifications_by_tier: HashMap<KycTier, i64>,
    pub approval_rate: f64,
    pub rejection_rate: f64,
    pub pending_reviews: i64,
    pub enhanced_due_diligence_cases: i64,
    pub average_processing_time_hours: f64,
    pub provider_performance: HashMap<String, ProviderStats>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderStats {
    pub total_submissions: i64,
    pub approved: i64,
    pub rejected: i64,
    pub manual_review: i64,
    pub average_processing_time_hours: f64,
    pub webhook_success_rate: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KycAuditTrail {
    pub consumer_id: Uuid,
    pub events: Vec<KycEvent>,
    pub documents: Vec<KycDocument>,
    pub decisions: Vec<KycDecision>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KycDecision {
    pub id: Uuid,
    pub kyc_record_id: Uuid,
    pub decision: KycStatus,
    pub reason: String,
    pub made_by: Option<Uuid>,
    pub provider_response: Option<String>,
    pub timestamp: DateTime<Utc>,
    pub previous_tier: Option<KycTier>,
    pub new_tier: Option<KycTier>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnhancedDueDiligenceCase {
    pub id: Uuid,
    pub consumer_id: Uuid,
    pub kyc_record_id: Uuid,
    pub trigger_reason: String,
    pub risk_factors: Vec<String>,
    pub status: EddStatus,
    pub assigned_to: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type, PartialEq)]
#[sqlx(type_name = "edd_status", rename_all = "snake_case")]
pub enum EddStatus {
    Active,
    UnderReview,
    Resolved,
    Escalated,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KycVolumeTracker {
    pub consumer_id: Uuid,
    pub date: chrono::NaiveDate,
    pub daily_volume: BigDecimal,
    pub monthly_volume: BigDecimal,
    pub transaction_count: i32,
    pub last_updated: DateTime<Utc>,
}

// Database repository for KYC operations
pub struct KycRepository {
    pool: sqlx::PgPool,
}

impl KycRepository {
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }

    // KYC Record operations
    pub async fn create_kyc_record(
        &self,
        consumer_id: Uuid,
        tier: KycTier,
    ) -> Result<KycRecord, sqlx::Error> {
        let id = Uuid::new_v4();
        let now = Utc::now();
        
        sqlx::query_as!(
            KycRecord,
            r#"
            INSERT INTO kyc_records (
                id, consumer_id, tier, status, created_at, updated_at,
                enhanced_due_diligence_active, effective_tier
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING *
            "#,
            id,
            consumer_id,
            tier as KycTier,
            KycStatus::Pending as KycStatus,
            now,
            now,
            false,
            tier as KycTier,
        )
        .fetch_one(&self.pool)
        .await
    }

    pub async fn get_kyc_record_by_consumer(
        &self,
        consumer_id: Uuid,
    ) -> Result<Option<KycRecord>, sqlx::Error> {
        sqlx::query_as!(
            KycRecord,
            r#"
            SELECT * FROM kyc_records 
            WHERE consumer_id = $1 
            ORDER BY created_at DESC 
            LIMIT 1
            "#,
            consumer_id
        )
        .fetch_optional(&self.pool)
        .await
    }

    pub async fn update_kyc_status(
        &self,
        id: Uuid,
        status: KycStatus,
        decision_reason: Option<String>,
        reviewer_identity: Option<Uuid>,
    ) -> Result<KycRecord, sqlx::Error> {
        let now = Utc::now();
        
        sqlx::query_as!(
            KycRecord,
            r#"
            UPDATE kyc_records 
            SET status = $1, decision_reason = $2, reviewer_identity = $3, 
                decision_timestamp = $4, updated_at = $5
            WHERE id = $6
            RETURNING *
            "#,
            status as KycStatus,
            decision_reason,
            reviewer_identity,
            now,
            now,
            id
        )
        .fetch_one(&self.pool)
        .await
    }

    pub async fn update_kyc_tier(
        &self,
        id: Uuid,
        tier: KycTier,
    ) -> Result<KycRecord, sqlx::Error> {
        let now = Utc::now();
        
        sqlx::query_as!(
            KycRecord,
            r#"
            UPDATE kyc_records 
            SET tier = $1, effective_tier = $1, updated_at = $2
            WHERE id = $3
            RETURNING *
            "#,
            tier as KycTier,
            now,
            id
        )
        .fetch_one(&self.pool)
        .await
    }

    // Document operations
    pub async fn create_document(
        &self,
        kyc_record_id: Uuid,
        document_type: DocumentType,
        document_number: Option<String>,
        issuing_country: Option<String>,
        expiry_date: Option<DateTime<Utc>>,
        front_image_reference: Option<String>,
        back_image_reference: Option<String>,
        selfie_image_reference: Option<String>,
    ) -> Result<KycDocument, sqlx::Error> {
        let id = Uuid::new_v4();
        let now = Utc::now();
        
        sqlx::query_as!(
            KycDocument,
            r#"
            INSERT INTO kyc_documents (
                id, kyc_record_id, document_type, document_number, issuing_country,
                expiry_date, front_image_reference, back_image_reference,
                selfie_image_reference, created_at, updated_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            RETURNING *
            "#,
            id,
            kyc_record_id,
            document_type as DocumentType,
            document_number,
            issuing_country,
            expiry_date,
            front_image_reference,
            back_image_reference,
            selfie_image_reference,
            now,
            now
        )
        .fetch_one(&self.pool)
        .await
    }

    pub async fn get_documents_by_kyc_record(
        &self,
        kyc_record_id: Uuid,
    ) -> Result<Vec<KycDocument>, sqlx::Error> {
        sqlx::query_as!(
            KycDocument,
            r#"
            SELECT * FROM kyc_documents 
            WHERE kyc_record_id = $1 
            ORDER BY created_at ASC
            "#,
            kyc_record_id
        )
        .fetch_all(&self.pool)
        .await
    }

    // Event operations
    pub async fn create_event(
        &self,
        consumer_id: Uuid,
        kyc_record_id: Option<Uuid>,
        event_type: KycEventType,
        event_detail: Option<String>,
        provider_response: Option<String>,
        metadata: Option<serde_json::Value>,
    ) -> Result<KycEvent, sqlx::Error> {
        let id = Uuid::new_v4();
        let now = Utc::now();
        
        sqlx::query_as!(
            KycEvent,
            r#"
            INSERT INTO kyc_events (
                id, consumer_id, kyc_record_id, event_type, event_detail,
                provider_response, metadata, timestamp
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING *
            "#,
            id,
            consumer_id,
            kyc_record_id,
            event_type as KycEventType,
            event_detail,
            provider_response,
            metadata,
            now
        )
        .fetch_one(&self.pool)
        .await
    }

    pub async fn get_events_by_consumer(
        &self,
        consumer_id: Uuid,
        limit: Option<i64>,
    ) -> Result<Vec<KycEvent>, sqlx::Error> {
        let limit = limit.unwrap_or(100);
        
        sqlx::query_as!(
            KycEvent,
            r#"
            SELECT * FROM kyc_events 
            WHERE consumer_id = $1 
            ORDER BY timestamp DESC 
            LIMIT $2
            "#,
            consumer_id,
            limit
        )
        .fetch_all(&self.pool)
        .await
    }

    // Manual review queue operations
    pub async fn add_to_manual_review_queue(
        &self,
        kyc_record_id: Uuid,
        consumer_id: Uuid,
        review_reason: String,
        provider_risk_score: Option<i32>,
        provider_flags: Option<Vec<String>>,
    ) -> Result<ManualReviewQueue, sqlx::Error> {
        let id = Uuid::new_v4();
        let now = Utc::now();
        
        sqlx::query_as!(
            ManualReviewQueue,
            r#"
            INSERT INTO manual_review_queue (
                id, kyc_record_id, consumer_id, priority, review_reason,
                provider_risk_score, provider_flags, created_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING *
            "#,
            id,
            kyc_record_id,
            consumer_id,
            1, // Default priority
            review_reason,
            provider_risk_score,
                provider_flags.as_ref().map(|flags| serde_json::to_value(flags).unwrap()),
            now
        )
        .fetch_one(&self.pool)
        .await
    }

    pub async fn get_manual_review_queue(
        &self,
        limit: Option<i64>,
        offset: Option<i64>,
    ) -> Result<Vec<ManualReviewQueue>, sqlx::Error> {
        let limit = limit.unwrap_or(50);
        let offset = offset.unwrap_or(0);
        
        sqlx::query_as!(
            ManualReviewQueue,
            r#"
            SELECT * FROM manual_review_queue 
            WHERE resolved_at IS NULL 
            ORDER BY priority ASC, created_at ASC 
            LIMIT $1 OFFSET $2
            "#,
            limit,
            offset
        )
        .fetch_all(&self.pool)
        .await
    }

    // Volume tracking operations
    pub async fn update_volume_tracker(
        &self,
        consumer_id: Uuid,
        transaction_amount: BigDecimal,
    ) -> Result<KycVolumeTracker, sqlx::Error> {
        let now = Utc::now();
        let today = now.date_naive();
        
        sqlx::query_as!(
            KycVolumeTracker,
            r#"
            INSERT INTO kyc_volume_trackers (
                consumer_id, date, daily_volume, monthly_volume, 
                transaction_count, last_updated
            ) VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (consumer_id, date) 
            DO UPDATE SET 
                daily_volume = kyc_volume_trackers.daily_volume + EXCLUDED.daily_volume,
                monthly_volume = kyc_volume_trackers.monthly_volume + EXCLUDED.monthly_volume,
                transaction_count = kyc_volume_trackers.transaction_count + 1,
                last_updated = EXCLUDED.last_updated
            RETURNING *
            "#,
            consumer_id,
            today,
            transaction_amount,
            transaction_amount,
            1i32,
            now
        )
        .fetch_one(&self.pool)
        .await
    }

    pub async fn get_current_limits(
        &self,
        consumer_id: Uuid,
    ) -> Result<Option<KycLimits>, sqlx::Error> {
        let now = Utc::now();
        let today = now.date_naive();
        
        sqlx::query_as!(
            KycLimits,
            r#"
            SELECT 
                kr.tier as tier,
                tdl.max_transaction_amount,
                tdl.daily_volume_limit,
                tdl.monthly_volume_limit,
                COALESCE(vt.daily_volume, '0'::BigDecimal) as daily_volume_used,
                COALESCE(vt.monthly_volume, '0'::BigDecimal) as monthly_volume_used,
                COALESCE(vt.last_updated, $3) as "last_daily_reset!",
                COALESCE(vt.last_updated, $3) as "last_monthly_reset!"
            FROM kyc_records kr
            JOIN kyc_tier_definitions tdl ON kr.tier = tdl.tier
            LEFT JOIN kyc_volume_trackers vt ON kr.consumer_id = vt.consumer_id AND vt.date = $1
            WHERE kr.consumer_id = $2
            ORDER BY kr.created_at DESC
            LIMIT 1
            "#,
            today,
            consumer_id,
            now
        )
        .fetch_optional(&self.pool)
        .await
    }
}
