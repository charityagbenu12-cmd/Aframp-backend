use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use bigdecimal::BigDecimal;
use std::collections::HashMap;

use crate::auth::AuthenticatedAdmin;
use crate::database::kyc_repository::{
    KycRepository, KycRecord, KycDocument, KycEvent, KycTier, KycStatus,
    ManualReviewQueue, EnhancedDueDiligenceCase, EddStatus
};
use crate::kyc::service::{KycService, KycServiceError};
use crate::kyc::limits::KycLimitsEnforcer;
use crate::error::ApiError;

#[derive(Debug, Serialize, Deserialize)]
pub struct ManualReviewQueueItem {
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
    pub consumer_info: ConsumerInfo,
    pub kyc_details: KycDetails,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ConsumerInfo {
    pub consumer_id: Uuid,
    pub email: Option<String>,
    pub full_name: Option<String>,
    pub registration_date: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KycDetails {
    pub tier: KycTier,
    pub status: KycStatus,
    pub verification_provider: Option<String>,
    pub submitted_documents: Vec<DocumentSummary>,
    pub decision_reason: Option<String>,
    pub resubmission_allowed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DocumentSummary {
    pub id: Uuid,
    pub document_type: String,
    pub document_number: Option<String>,
    pub issuing_country: Option<String>,
    pub verification_outcome: Option<String>,
    pub rejection_reason: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ApproveKycRequest {
    pub tier: KycTier,
    pub reviewer_notes: Option<String>,
    pub notify_consumer: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RejectKycRequest {
    pub rejection_reason: String,
    pub reviewer_notes: Option<String>,
    pub allow_resubmission: Option<bool>,
    pub resubmission_days: Option<i32>, // Override default cooling-off period
    pub notify_consumer: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DowngradeKycRequest {
    pub new_tier: KycTier,
    pub reason: String,
    pub notify_consumer: Option<bool>,
    pub temporary: Option<bool>, // If true, tier can be restored later
    pub duration_days: Option<i32>, // For temporary downgrades
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KycHistoryResponse {
    pub consumer_id: Uuid,
    pub current_record: KycRecord,
    pub historical_records: Vec<KycRecord>,
    pub documents: Vec<KycDocument>,
    pub events: Vec<KycEvent>,
    pub decisions: Vec<KycDecision>,
    pub manual_reviews: Vec<ManualReviewQueue>,
    pub edd_cases: Vec<EnhancedDueDiligenceCase>,
}

#[derive(Debug, Serialize, Deserialize)]
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

#[derive(Debug, Serialize, Deserialize)]
pub struct ManualReviewQueueParams {
    pub page: Option<i64>,
    pub limit: Option<i64>,
    pub status: Option<String>, // "pending", "assigned", "resolved"
    pub priority: Option<i32>,
    pub assigned_to: Option<Uuid>,
    pub provider: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ManualReviewQueueResponse {
    pub items: Vec<ManualReviewQueueItem>,
    pub total_count: i64,
    pub page: i64,
    pub limit: i64,
    pub has_next: bool,
    pub has_prev: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AdminActionResponse {
    pub success: bool,
    pub message: String,
    pub kyc_record_id: Uuid,
    pub action: String,
    pub timestamp: DateTime<Utc>,
}

pub fn admin_kyc_routes() -> Router<KycService> {
    Router::new()
        .route("/queue", get(get_manual_review_queue))
        .route("/queue/:consumer_id/approve", post(approve_kyc))
        .route("/queue/:consumer_id/reject", post(reject_kyc))
        .route("/consumers/:consumer_id", get(get_consumer_kyc_history))
        .route("/consumers/:consumer_id/downgrade", post(downgrade_kyc))
        .route("/edd/active", get(get_active_edd_cases))
        .route("/edd/:case_id/resolve", post(resolve_edd_case))
        .route("/stats", get(get_kyc_statistics))
}

async fn get_manual_review_queue(
    State(kyc_service): State<KycService>,
    _auth: AuthenticatedAdmin,
    Query(params): Query<ManualReviewQueueParams>,
) -> Result<Json<ManualReviewQueueResponse>, ApiError> {
    let page = params.page.unwrap_or(1);
    let limit = params.limit.unwrap_or(50);
    let offset = (page - 1) * limit;

    // Get manual review queue items
    let queue_items = kyc_service.repository
        .get_manual_review_queue(Some(limit), Some(offset))
        .await
        .map_err(|e| ApiError::InternalServerError(format!("Database error: {}", e)))?;

    // Get total count
    let total_count = sqlx::query_scalar!(
        "SELECT COUNT(*) FROM manual_review_queue WHERE resolved_at IS NULL"
    )
    .fetch_one(&kyc_service.repository.pool)
    .await
    .map_err(|e| ApiError::InternalServerError(format!("Database error: {}", e)))?
    .unwrap_or(0);

    // Enrich with consumer and KYC details
    let mut enriched_items = Vec::new();
    for item in queue_items {
        let consumer_info = get_consumer_info(&kyc_service.repository.pool, item.consumer_id).await?;
        let kyc_details = get_kyc_details(&kyc_service.repository, item.kyc_record_id).await?;

        enriched_items.push(ManualReviewQueueItem {
            id: item.id,
            kyc_record_id: item.kyc_record_id,
            consumer_id: item.consumer_id,
            priority: item.priority,
            assigned_to: item.assigned_to,
            review_reason: item.review_reason,
            provider_risk_score: item.provider_risk_score,
            provider_flags: item.provider_flags,
            created_at: item.created_at,
            assigned_at: item.assigned_at,
            consumer_info,
            kyc_details,
        });
    }

    let response = ManualReviewQueueResponse {
        items: enriched_items,
        total_count,
        page,
        limit,
        has_next: (page * limit) < total_count,
        has_prev: page > 1,
    };

    Ok(Json(response))
}

async fn approve_kyc(
    State(kyc_service): State<KycService>,
    _auth: AuthenticatedAdmin,
    Path(consumer_id): Path<Uuid>,
    Json(request): Json<ApproveKycRequest>,
) -> Result<Json<AdminActionResponse>, ApiError> {
    // Get current KYC record
    let kyc_record = kyc_service.repository
        .get_kyc_record_by_consumer(consumer_id)
        .await
        .map_err(|e| ApiError::InternalServerError(format!("Database error: {}", e)))?
        .ok_or_else(|| ApiError::NotFound("KYC record not found".to_string()))?;

    // Update KYC tier and status
    kyc_service.repository
        .update_kyc_tier(kyc_record.id, request.tier)
        .await
        .map_err(|e| ApiError::InternalServerError(format!("Database error: {}", e)))?;

    kyc_service.repository
        .update_kyc_status(
            kyc_record.id,
            KycStatus::Approved,
            Some(format!("Approved by admin: {:?}", request.reviewer_notes)),
            Some(_auth.admin_id),
        )
        .await
        .map_err(|e| ApiError::InternalServerError(format!("Database error: {}", e)))?;

    // Remove from manual review queue
    sqlx::query!(
        "UPDATE manual_review_queue SET resolved_at = $1 WHERE kyc_record_id = $2",
        Utc::now(),
        kyc_record.id
    )
    .execute(&kyc_service.repository.pool)
    .await
    .map_err(|e| ApiError::InternalServerError(format!("Database error: {}", e)))?;

    // Log the decision
    kyc_service.repository.create_event(
        consumer_id,
        Some(kyc_record.id),
        crate::database::kyc_repository::KycEventType::DecisionMade,
        Some(format!("Manually approved by admin: {:?}", request.reviewer_notes)),
        None,
        Some(serde_json::json!({
            "admin_id": _auth.admin_id,
            "approved_tier": format!("{:?}", request.tier),
            "reviewer_notes": request.reviewer_notes
        }))
    ).await
    .map_err(|e| ApiError::InternalServerError(format!("Database error: {}", e)))?;

    // TODO: Send notification to consumer if requested

    Ok(Json(AdminActionResponse {
        success: true,
        message: "KYC verification approved successfully".to_string(),
        kyc_record_id: kyc_record.id,
        action: "approve".to_string(),
        timestamp: Utc::now(),
    }))
}

async fn reject_kyc(
    State(kyc_service): State<KycService>,
    _auth: AuthenticatedAdmin,
    Path(consumer_id): Path<Uuid>,
    Json(request): Json<RejectKycRequest>,
) -> Result<Json<AdminActionResponse>, ApiError> {
    // Get current KYC record
    let kyc_record = kyc_service.repository
        .get_kyc_record_by_consumer(consumer_id)
        .await
        .map_err(|e| ApiError::InternalServerError(format!("Database error: {}", e)))?
        .ok_or_else(|| ApiError::NotFound("KYC record not found".to_string()))?;

    // Update KYC status
    kyc_service.repository
        .update_kyc_status(
            kyc_record.id,
            KycStatus::Rejected,
            Some(format!("Rejected by admin: {}", request.rejection_reason)),
            Some(_auth.admin_id),
        )
        .await
        .map_err(|e| ApiError::InternalServerError(format!("Database error: {}", e)))?;

    // Set resubmission allowed date
    let allow_resubmission = request.allow_resubmission.unwrap_or(true);
    let resubmission_days = if allow_resubmission {
        request.resubmission_days
    } else {
        None
    };

    if let Some(days) = resubmission_days {
        let resubmission_date = Utc::now() + chrono::Duration::days(days as i64);
        sqlx::query!(
            "UPDATE kyc_records SET resubmission_allowed_at = $1 WHERE id = $2",
            resubmission_date,
            kyc_record.id
        )
        .execute(&kyc_service.repository.pool)
        .await
        .map_err(|e| ApiError::InternalServerError(format!("Database error: {}", e)))?;
    }

    // Remove from manual review queue
    sqlx::query!(
        "UPDATE manual_review_queue SET resolved_at = $1 WHERE kyc_record_id = $2",
        Utc::now(),
        kyc_record.id
    )
    .execute(&kyc_service.repository.pool)
    .await
    .map_err(|e| ApiError::InternalServerError(format!("Database error: {}", e)))?;

    // Log the decision
    kyc_service.repository.create_event(
        consumer_id,
        Some(kyc_record.id),
        crate::database::kyc_repository::KycEventType::DecisionMade,
        Some(format!("Rejected by admin: {}", request.rejection_reason)),
        None,
        Some(serde_json::json!({
            "admin_id": _auth.admin_id,
            "rejection_reason": request.rejection_reason,
            "reviewer_notes": request.reviewer_notes,
            "allow_resubmission": allow_resubmission,
            "resubmission_days": resubmission_days
        }))
    ).await
    .map_err(|e| ApiError::InternalServerError(format!("Database error: {}", e)))?;

    // TODO: Send notification to consumer if requested

    Ok(Json(AdminActionResponse {
        success: true,
        message: "KYC verification rejected successfully".to_string(),
        kyc_record_id: kyc_record.id,
        action: "reject".to_string(),
        timestamp: Utc::now(),
    }))
}

async fn downgrade_kyc(
    State(kyc_service): State<KycService>,
    _auth: AuthenticatedAdmin,
    Path(consumer_id): Path<Uuid>,
    Json(request): Json<DowngradeKycRequest>,
) -> Result<Json<AdminActionResponse>, ApiError> {
    // Get current KYC record
    let kyc_record = kyc_service.repository
        .get_kyc_record_by_consumer(consumer_id)
        .await
        .map_err(|e| ApiError::InternalServerError(format!("Database error: {}", e)))?
        .ok_or_else(|| ApiError::NotFound("KYC record not found".to_string()))?;

    // Validate new tier is lower than current
    if request.new_tier as i32 >= kyc_record.tier as i32 {
        return Err(ApiError::BadRequest("New tier must be lower than current tier".to_string()));
    }

    // Update effective tier (or both tiers if not temporary)
    if request.temporary.unwrap_or(false) {
        // Only update effective tier for temporary downgrade
        sqlx::query!(
            r#"
            UPDATE kyc_records 
            SET effective_tier = $1, updated_at = $2
            WHERE id = $3
            "#,
            request.new_tier as KycTier,
            Utc::now(),
            kyc_record.id
        )
        .execute(&kyc_service.repository.pool)
        .await
        .map_err(|e| ApiError::InternalServerError(format!("Database error: {}", e)))?;
    } else {
        // Update both tiers for permanent downgrade
        kyc_service.repository
            .update_kyc_tier(kyc_record.id, request.new_tier)
            .await
            .map_err(|e| ApiError::InternalServerError(format!("Database error: {}", e)))?;
    }

    // Log the downgrade
    kyc_service.repository.create_event(
        consumer_id,
        Some(kyc_record.id),
        crate::database::kyc_repository::KycEventType::TierChanged,
        Some(format!("Tier downgraded by admin: {}", request.reason)),
        None,
        Some(serde_json::json!({
            "admin_id": _auth.admin_id,
            "previous_tier": format!("{:?}", kyc_record.tier),
            "new_tier": format!("{:?}", request.new_tier),
            "reason": request.reason,
            "temporary": request.temporary,
            "duration_days": request.duration_days
        }))
    ).await
    .map_err(|e| ApiError::InternalServerError(format!("Database error: {}", e)))?;

    // TODO: Send notification to consumer if requested
    // TODO: Schedule tier restoration if temporary

    Ok(Json(AdminActionResponse {
        success: true,
        message: "KYC tier downgraded successfully".to_string(),
        kyc_record_id: kyc_record.id,
        action: "downgrade".to_string(),
        timestamp: Utc::now(),
    }))
}

async fn get_consumer_kyc_history(
    State(kyc_service): State<KycService>,
    _auth: AuthenticatedAdmin,
    Path(consumer_id): Path<Uuid>,
) -> Result<Json<KycHistoryResponse>, ApiError> {
    // Get all KYC records for the consumer
    let all_records = sqlx::query_as!(
        KycRecord,
        "SELECT * FROM kyc_records WHERE consumer_id = $1 ORDER BY created_at DESC",
        consumer_id
    )
    .fetch_all(&kyc_service.repository.pool)
    .await
    .map_err(|e| ApiError::InternalServerError(format!("Database error: {}", e)))?;

    if all_records.is_empty() {
        return Err(ApiError::NotFound("No KYC records found for consumer".to_string()));
    }

    let current_record = all_records[0].clone();
    let historical_records = all_records[1..].to_vec();

    // Get related data
    let documents = kyc_service.repository
        .get_documents_by_kyc_record(current_record.id)
        .await
        .map_err(|e| ApiError::InternalServerError(format!("Database error: {}", e)))?;

    let events = kyc_service.repository
        .get_events_by_consumer(consumer_id, Some(1000))
        .await
        .map_err(|e| ApiError::InternalServerError(format!("Database error: {}", e)))?;

    // Get decisions
    let decisions = sqlx::query_as!(
        KycDecision,
        "SELECT * FROM kyc_decisions WHERE kyc_record_id = $1 ORDER BY timestamp DESC",
        current_record.id
    )
    .fetch_all(&kyc_service.repository.pool)
    .await
    .map_err(|e| ApiError::InternalServerError(format!("Database error: {}", e)))?;

    // Get manual review history
    let manual_reviews = sqlx::query_as!(
        ManualReviewQueue,
        "SELECT * FROM manual_review_queue WHERE consumer_id = $1 ORDER BY created_at DESC",
        consumer_id
    )
    .fetch_all(&kyc_service.repository.pool)
    .await
    .map_err(|e| ApiError::InternalServerError(format!("Database error: {}", e)))?;

    // Get EDD cases
    let edd_cases = sqlx::query_as!(
        EnhancedDueDiligenceCase,
        "SELECT * FROM enhanced_due_diligence_cases WHERE consumer_id = $1 ORDER BY created_at DESC",
        consumer_id
    )
    .fetch_all(&kyc_service.repository.pool)
    .await
    .map_err(|e| ApiError::InternalServerError(format!("Database error: {}", e)))?;

    Ok(Json(KycHistoryResponse {
        consumer_id,
        current_record,
        historical_records,
        documents,
        events,
        decisions,
        manual_reviews,
        edd_cases,
    }))
}

async fn get_active_edd_cases(
    State(kyc_service): State<KycService>,
    _auth: AuthenticatedAdmin,
) -> Result<Json<Vec<EnhancedDueDiligenceCase>>, ApiError> {
    let cases = sqlx::query_as!(
        EnhancedDueDiligenceCase,
        r#"
        SELECT edc.* 
        FROM enhanced_due_diligence_cases edc
        WHERE edc.status IN ('active', 'under_review')
        ORDER BY edc.created_at DESC
        "#
    )
    .fetch_all(&kyc_service.repository.pool)
    .await
    .map_err(|e| ApiError::InternalServerError(format!("Database error: {}", e)))?;

    Ok(Json(cases))
}

async fn resolve_edd_case(
    State(kyc_service): State<KycService>,
    _auth: AuthenticatedAdmin,
    Path(case_id): Path<Uuid>,
    Json(request): Json<serde_json::Value>, // Could include resolution notes, actions taken, etc.
) -> Result<Json<AdminActionResponse>, ApiError> {
    // Get EDD case
    let edd_case = sqlx::query_as!(
        EnhancedDueDiligenceCase,
        "SELECT * FROM enhanced_due_diligence_cases WHERE id = $1",
        case_id
    )
    .fetch_optional(&kyc_service.repository.pool)
    .await
    .map_err(|e| ApiError::InternalServerError(format!("Database error: {}", e)))?
    .ok_or_else(|| ApiError::NotFound("EDD case not found".to_string()))?;

    // Update case status
    sqlx::query!(
        r#"
        UPDATE enhanced_due_diligence_cases 
        SET status = 'resolved', resolved_at = $1, assigned_to = $2, notes = $3
        WHERE id = $4
        "#,
        Utc::now(),
        Some(_auth.admin_id),
        request.get("notes").and_then(|v| v.as_str()).map(|s| s.to_string()),
        case_id
    )
    .execute(&kyc_service.repository.pool)
    .await
    .map_err(|e| ApiError::InternalServerError(format!("Database error: {}", e)))?;

    // Restore consumer's effective tier if it was reduced
    if let Err(e) = kyc_service.repository.restore_effective_tier(edd_case.consumer_id, "EDD case resolved".to_string()).await {
        warn!("Failed to restore effective tier for consumer {}: {}", edd_case.consumer_id, e);
    }

    // Log the resolution
    kyc_service.repository.create_event(
        edd_case.consumer_id,
        Some(edd_case.kyc_record_id),
        crate::database::kyc_repository::KycEventType::StatusUpdated,
        Some("EDD case resolved".to_string()),
        None,
        Some(serde_json::json!({
            "admin_id": _auth.admin_id,
            "edd_case_id": case_id,
            "resolution_notes": request.get("notes")
        }))
    ).await
    .map_err(|e| ApiError::InternalServerError(format!("Database error: {}", e)))?;

    Ok(Json(AdminActionResponse {
        success: true,
        message: "EDD case resolved successfully".to_string(),
        kyc_record_id: edd_case.kyc_record_id,
        action: "resolve_edd".to_string(),
        timestamp: Utc::now(),
    }))
}

async fn get_kyc_statistics(
    State(kyc_service): State<KycService>,
    _auth: AuthenticatedAdmin,
) -> Result<Json<serde_json::Value>, ApiError> {
    // Get various KYC statistics
    let total_verifications = sqlx::query_scalar!(
        "SELECT COUNT(*) FROM kyc_records"
    )
    .fetch_one(&kyc_service.repository.pool)
    .await
    .map_err(|e| ApiError::InternalServerError(format!("Database error: {}", e)))?
    .unwrap_or(0);

    let verifications_by_tier = sqlx::query!(
        r#"
        SELECT tier, COUNT(*) as count
        FROM kyc_records
        GROUP BY tier
        ORDER BY tier
        "#
    )
    .fetch_all(&kyc_service.repository.pool)
    .await
    .map_err(|e| ApiError::InternalServerError(format!("Database error: {}", e)))?;

    let approval_stats = sqlx::query!(
        r#"
        SELECT 
            COUNT(*) FILTER (WHERE status = 'approved') as approved,
            COUNT(*) FILTER (WHERE status = 'rejected') as rejected,
            COUNT(*) FILTER (WHERE status = 'pending') as pending,
            COUNT(*) FILTER (WHERE status = 'manual_review') as manual_review
        FROM kyc_records
        WHERE created_at >= NOW() - INTERVAL '30 days'
        "#
    )
    .fetch_one(&kyc_service.repository.pool)
    .await
    .map_err(|e| ApiError::InternalServerError(format!("Database error: {}", e)))?;

    let queue_depth = sqlx::query_scalar!(
        "SELECT COUNT(*) FROM manual_review_queue WHERE resolved_at IS NULL"
    )
    .fetch_one(&kyc_service.repository.pool)
    .await
    .map_err(|e| ApiError::InternalServerError(format!("Database error: {}", e)))?
    .unwrap_or(0);

    let active_edd_cases = sqlx::query_scalar!(
        "SELECT COUNT(*) FROM enhanced_due_diligence_cases WHERE status IN ('active', 'under_review')"
    )
    .fetch_one(&kyc_service.repository.pool)
    .await
    .map_err(|e| ApiError::InternalServerError(format!("Database error: {}", e)))?
    .unwrap_or(0);

    let stats = serde_json::json!({
        "total_verifications": total_verifications,
        "verifications_by_tier": verifications_by_tier,
        "recent_30_days": {
            "approved": approval_stats.approved,
            "rejected": approval_stats.rejected,
            "pending": approval_stats.pending,
            "manual_review": approval_stats.manual_review,
            "approval_rate": if (approval_stats.approved + approval_stats.rejected) > 0 {
                approval_stats.approved as f64 / (approval_stats.approved + approval_stats.rejected) as f64
            } else { 0.0 }
        },
        "manual_review_queue_depth": queue_depth,
        "active_edd_cases": active_edd_cases,
        "generated_at": Utc::now().to_rfc3339()
    });

    Ok(Json(stats))
}

// Helper functions
async fn get_consumer_info(pool: &sqlx::PgPool, consumer_id: Uuid) -> Result<ConsumerInfo, ApiError> {
    let consumer = sqlx::query!(
        r#"
        SELECT c.id, c.email, c.full_name, c.created_at
        FROM consumers c
        WHERE c.id = $1
        "#,
        consumer_id
    )
    .fetch_optional(pool)
    .await
    .map_err(|e| ApiError::InternalServerError(format!("Database error: {}", e)))?
    .ok_or_else(|| ApiError::NotFound("Consumer not found".to_string()))?;

    Ok(ConsumerInfo {
        consumer_id: consumer.id,
        email: consumer.email,
        full_name: consumer.full_name,
        registration_date: consumer.created_at,
    })
}

async fn get_kyc_details(repository: &KycRepository, kyc_record_id: Uuid) -> Result<KycDetails, ApiError> {
    let kyc_record = sqlx::query_as!(
        KycRecord,
        "SELECT * FROM kyc_records WHERE id = $1",
        kyc_record_id
    )
    .fetch_one(&repository.pool)
    .await
    .map_err(|e| ApiError::InternalServerError(format!("Database error: {}", e)))?;

    let documents = repository
        .get_documents_by_kyc_record(kyc_record_id)
        .await
        .map_err(|e| ApiError::InternalServerError(format!("Database error: {}", e)))?;

    let document_summaries: Vec<DocumentSummary> = documents.into_iter().map(|doc| DocumentSummary {
        id: doc.id,
        document_type: format!("{:?}", doc.document_type),
        document_number: doc.document_number,
        issuing_country: doc.issuing_country,
        verification_outcome: doc.verification_outcome.map(|s| format!("{:?}", s)),
        rejection_reason: doc.rejection_reason,
        created_at: doc.created_at,
    }).collect();

    Ok(KycDetails {
        tier: kyc_record.tier,
        status: kyc_record.status,
        verification_provider: kyc_record.verification_provider,
        submitted_documents: document_summaries,
        decision_reason: kyc_record.decision_reason,
        resubmission_allowed_at: kyc_record.resubmission_allowed_at,
    })
}
