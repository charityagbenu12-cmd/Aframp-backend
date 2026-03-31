use crate::bug_bounty::{
    models::{
        BugBountyError, CreateInvitationRequest, CreateReportRequest, RecordRewardRequest,
        UpdateReportRequest,
    },
    service::BugBountyService,
};
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

pub type BugBountyState = Arc<BugBountyService>;

// ---------------------------------------------------------------------------
// Error helpers
// ---------------------------------------------------------------------------

fn map_error(e: BugBountyError) -> (StatusCode, Json<serde_json::Value>) {
    match e {
        BugBountyError::ReportNotFound => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "report not found"})),
        ),
        BugBountyError::RewardOutOfTier { .. } => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({"error": e.to_string()})),
        ),
        BugBountyError::TransitionCriteriaNotMet { ref unmet } => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({
                "error": "transition criteria not met",
                "unmet_criteria": unmet,
            })),
        ),
        BugBountyError::InvitationRequired => (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "invitation required for private programme"})),
        ),
        BugBountyError::DatabaseError(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "internal server error"})),
        ),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        ),
    }
}

// ---------------------------------------------------------------------------
// Query params
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct PaginationParams {
    #[serde(default = "default_page")]
    pub page: u32,
    #[serde(default = "default_per_page")]
    pub per_page: u32,
}

fn default_page() -> u32 {
    1
}
fn default_per_page() -> u32 {
    20
}

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct PaginatedReportsResponse {
    pub reports: Vec<crate::bug_bounty::models::BugBountyReport>,
    pub total: i64,
    pub page: u32,
    pub per_page: u32,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// POST /api/admin/security/bug-bounty/reports
pub async fn create_report(
    State(svc): State<BugBountyState>,
    Json(req): Json<CreateReportRequest>,
) -> Result<(StatusCode, Json<crate::bug_bounty::models::BugBountyReport>), (StatusCode, Json<serde_json::Value>)>
{
    // admin_id: use Uuid::nil() as placeholder (auth enforced by middleware)
    let admin_id = Uuid::nil();
    svc.create_report(req, admin_id)
        .await
        .map(|r| (StatusCode::CREATED, Json(r)))
        .map_err(map_error)
}

/// GET /api/admin/security/bug-bounty/reports
pub async fn list_reports(
    State(svc): State<BugBountyState>,
    Query(params): Query<PaginationParams>,
) -> Result<Json<PaginatedReportsResponse>, (StatusCode, Json<serde_json::Value>)> {
    svc.list_reports(params.page, params.per_page)
        .await
        .map(|(reports, total)| {
            Json(PaginatedReportsResponse {
                reports,
                total,
                page: params.page,
                per_page: params.per_page,
            })
        })
        .map_err(map_error)
}

/// GET /api/admin/security/bug-bounty/reports/:report_id
pub async fn get_report(
    State(svc): State<BugBountyState>,
    Path(report_id): Path<Uuid>,
) -> Result<Json<crate::bug_bounty::models::BugBountyReport>, (StatusCode, Json<serde_json::Value>)>
{
    svc.get_report(report_id)
        .await
        .map(Json)
        .map_err(map_error)
}

/// PATCH /api/admin/security/bug-bounty/reports/:report_id
pub async fn update_report(
    State(svc): State<BugBountyState>,
    Path(report_id): Path<Uuid>,
    Json(req): Json<UpdateReportRequest>,
) -> Result<Json<crate::bug_bounty::models::BugBountyReport>, (StatusCode, Json<serde_json::Value>)>
{
    let admin_id = Uuid::nil();
    svc.update_report(report_id, req, admin_id)
        .await
        .map(Json)
        .map_err(map_error)
}

/// POST /api/admin/security/bug-bounty/reports/:report_id/reward
pub async fn record_reward(
    State(svc): State<BugBountyState>,
    Path(report_id): Path<Uuid>,
    Json(req): Json<RecordRewardRequest>,
) -> Result<(StatusCode, Json<crate::bug_bounty::models::RewardRecord>), (StatusCode, Json<serde_json::Value>)>
{
    let admin_id = Uuid::nil();
    svc.record_reward(report_id, req, admin_id)
        .await
        .map(|r| (StatusCode::CREATED, Json(r)))
        .map_err(map_error)
}

/// GET /api/admin/security/bug-bounty/metrics
pub async fn get_metrics(
    State(svc): State<BugBountyState>,
) -> Result<Json<crate::bug_bounty::models::ProgrammeMetrics>, (StatusCode, Json<serde_json::Value>)>
{
    svc.get_metrics().await.map(Json).map_err(map_error)
}

/// POST /api/admin/security/bug-bounty/invitations
pub async fn create_invitation(
    State(svc): State<BugBountyState>,
    Json(req): Json<CreateInvitationRequest>,
) -> Result<(StatusCode, Json<crate::bug_bounty::models::ResearcherInvitation>), (StatusCode, Json<serde_json::Value>)>
{
    let admin_id = Uuid::nil();
    svc.create_invitation(req, admin_id)
        .await
        .map(|inv| (StatusCode::CREATED, Json(inv)))
        .map_err(map_error)
}

/// GET /api/admin/security/bug-bounty/invitations
pub async fn list_invitations(
    State(svc): State<BugBountyState>,
) -> Result<Json<Vec<crate::bug_bounty::models::ResearcherInvitation>>, (StatusCode, Json<serde_json::Value>)>
{
    svc.list_invitations().await.map(Json).map_err(map_error)
}

/// POST /api/admin/security/bug-bounty/transition-to-public
pub async fn transition_to_public(
    State(svc): State<BugBountyState>,
) -> Result<Json<crate::bug_bounty::models::TransitionResult>, (StatusCode, Json<serde_json::Value>)>
{
    let admin_id = Uuid::nil();
    svc.attempt_transition_to_public(admin_id)
        .await
        .map(Json)
        .map_err(map_error)
}
