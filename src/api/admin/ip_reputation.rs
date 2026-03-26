//! Admin IP Reputation Management API
//!
//! Endpoints for managing IP reputation records and blocks.

use crate::database::ip_reputation_repository::{IpReputationEntity, IpReputationRepository};
use crate::database::Repository;
use crate::error::AppError;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use utoipa::ToSchema;
use uuid::Uuid;

// ── Request/Response Models ───────────────────────────────────────────────────

#[derive(Debug, Serialize, ToSchema)]
pub struct IpReputationSummary {
    pub id: String,
    pub ip_address_or_cidr: String,
    pub reputation_score: rust_decimal::Decimal,
    pub detection_source: String,
    pub block_status: Option<String>,
    pub is_whitelisted: bool,
    pub first_seen_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
    pub evidence_count: i64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct IpReputationDetail {
    #[serde(flatten)]
    pub summary: IpReputationSummary,
    pub block_expiry_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub evidence: Vec<IpEvidenceSummary>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct IpEvidenceSummary {
    pub id: String,
    pub evidence_type: String,
    pub evidence_detail: serde_json::Value,
    pub detected_at: DateTime<Utc>,
    pub consumer_id: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct BlockIpRequest {
    pub block_type: String, // "temporary" or "permanent"
    pub duration_minutes: Option<i64>, // for temporary blocks
    pub reason: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ListIpReputationQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

// ── API State ─────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct IpReputationState {
    pub repo: IpReputationRepository,
}

// ── API Handlers ─────────────────────────────────────────────────────────────

/// GET /api/admin/ip-reputation
/// List flagged IPs with pagination
#[utoipa::path(
    get,
    path = "/api/admin/ip-reputation",
    tag = "IP Reputation",
    params(
        ("limit" = Option<i64>, Query, description = "Maximum number of results"),
        ("offset" = Option<i64>, Query, description = "Pagination offset")
    ),
    responses(
        (status = 200, description = "List of flagged IPs", body = Vec<IpReputationSummary>),
        (status = 500, description = "Internal server error")
    )
)]
pub async fn list_flagged_ips(
    State(state): State<IpReputationState>,
    Query(query): Query<ListIpReputationQuery>,
) -> Result<Json<Vec<IpReputationSummary>>, AppError> {
    let limit = query.limit.unwrap_or(50).min(200);
    let offset = query.offset.unwrap_or(0);

    let ips = state.repo.get_flagged_ips(limit, offset).await?;

    let mut summaries = Vec::new();
    for ip in ips {
        let evidence_count = state.repo.get_evidence_for_ip(&ip.ip_address_or_cidr, Some(1)).await?.len() as i64;
        summaries.push(IpReputationSummary {
            id: ip.id,
            ip_address_or_cidr: ip.ip_address_or_cidr,
            reputation_score: ip.reputation_score,
            detection_source: ip.detection_source,
            block_status: ip.block_status,
            is_whitelisted: ip.is_whitelisted,
            first_seen_at: ip.first_seen_at,
            last_seen_at: ip.last_seen_at,
            evidence_count,
        });
    }

    Ok(Json(summaries))
}

/// GET /api/admin/ip-reputation/{ip}
/// Get detailed reputation information for a specific IP
#[utoipa::path(
    get,
    path = "/api/admin/ip-reputation/{ip}",
    tag = "IP Reputation",
    params(
        ("ip" = String, Path, description = "IP address or CIDR range")
    ),
    responses(
        (status = 200, description = "IP reputation details", body = IpReputationDetail),
        (status = 404, description = "IP not found"),
        (status = 500, description = "Internal server error")
    )
)]
pub async fn get_ip_reputation(
    State(state): State<IpReputationState>,
    Path(ip): Path<String>,
) -> Result<Json<IpReputationDetail>, AppError> {
    let reputation = state.repo.get_reputation(&ip).await?
        .ok_or_else(|| AppError::NotFound(format!("IP reputation record not found: {}", ip)))?;

    let evidence = state.repo.get_evidence_for_ip(&ip, None).await?;
    let evidence_summaries: Vec<IpEvidenceSummary> = evidence.into_iter()
        .map(|e| IpEvidenceSummary {
            id: e.id,
            evidence_type: e.evidence_type,
            evidence_detail: e.evidence_detail,
            detected_at: e.detected_at,
            consumer_id: e.consumer_id,
        })
        .collect();

    let evidence_count = evidence_summaries.len() as i64;

    let detail = IpReputationDetail {
        summary: IpReputationSummary {
            id: reputation.id,
            ip_address_or_cidr: reputation.ip_address_or_cidr,
            reputation_score: reputation.reputation_score,
            detection_source: reputation.detection_source,
            block_status: reputation.block_status,
            is_whitelisted: reputation.is_whitelisted,
            first_seen_at: reputation.first_seen_at,
            last_seen_at: reputation.last_seen_at,
            evidence_count,
        },
        block_expiry_at: reputation.block_expiry_at,
        created_at: reputation.created_at,
        updated_at: reputation.updated_at,
        evidence: evidence_summaries,
    };

    Ok(Json(detail))
}

/// POST /api/admin/ip-reputation/{ip}/block
/// Apply a block to an IP address
#[utoipa::path(
    post,
    path = "/api/admin/ip-reputation/{ip}/block",
    tag = "IP Reputation",
    params(
        ("ip" = String, Path, description = "IP address or CIDR range")
    ),
    request_body = BlockIpRequest,
    responses(
        (status = 200, description = "Block applied successfully", body = IpReputationEntity),
        (status = 400, description = "Invalid request"),
        (status = 500, description = "Internal server error")
    )
)]
pub async fn block_ip(
    State(state): State<IpReputationState>,
    Path(ip): Path<String>,
    Json(request): Json<BlockIpRequest>,
) -> Result<Json<IpReputationEntity>, AppError> {
    // Validate block type
    if !matches!(request.block_type.as_str(), "temporary" | "permanent") {
        return Err(AppError::BadRequest("block_type must be 'temporary' or 'permanent'".to_string()));
    }

    // Calculate expiry for temporary blocks
    let expiry = if request.block_type == "temporary" {
        let duration = request.duration_minutes.unwrap_or(60); // Default 1 hour
        Some(Utc::now() + chrono::Duration::minutes(duration))
    } else {
        None
    };

    let reputation = state.repo.apply_block(&ip, &request.block_type, expiry).await?;

    // TODO: Update Redis cache via detection service

    Ok(Json(reputation))
}

/// POST /api/admin/ip-reputation/{ip}/unblock
/// Remove block from an IP address
#[utoipa::path(
    post,
    path = "/api/admin/ip-reputation/{ip}/unblock",
    tag = "IP Reputation",
    params(
        ("ip" = String, Path, description = "IP address or CIDR range")
    ),
    responses(
        (status = 200, description = "Block removed successfully", body = IpReputationEntity),
        (status = 500, description = "Internal server error")
    )
)]
pub async fn unblock_ip(
    State(state): State<IpReputationState>,
    Path(ip): Path<String>,
) -> Result<Json<IpReputationEntity>, AppError> {
    let reputation = state.repo.remove_block(&ip).await?;

    // TODO: Update Redis cache via detection service

    Ok(Json(reputation))
}

/// POST /api/admin/ip-reputation/{ip}/whitelist
/// Whitelist an IP address (prevents automated blocking)
#[utoipa::path(
    post,
    path = "/api/admin/ip-reputation/{ip}/whitelist",
    tag = "IP Reputation",
    params(
        ("ip" = String, Path, description = "IP address or CIDR range")
    ),
    responses(
        (status = 200, description = "IP whitelisted successfully", body = IpReputationEntity),
        (status = 500, description = "Internal server error")
    )
)]
pub async fn whitelist_ip(
    State(state): State<IpReputationState>,
    Path(ip): Path<String>,
) -> Result<Json<IpReputationEntity>, AppError> {
    let reputation = state.repo.whitelist_ip(&ip).await?;

    // TODO: Update Redis cache via detection service

    Ok(Json(reputation))
}