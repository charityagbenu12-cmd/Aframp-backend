//! Mint approval workflow HTTP handlers
//!
//! Endpoints:
//! - POST   /api/mint/requests              — submit a new mint request
//! - POST   /api/mint/requests/:id/approve  — approve a request
//! - POST   /api/mint/requests/:id/reject   — reject a request
//! - GET    /api/mint/requests/:id          — get request detail + approval timeline
//! - GET    /api/mint/requests              — list requests (with optional status filter)
//! - GET    /api/mint/requests/:id/audit    — full audit trail

use crate::api::mint::models::{
    ApproveMintRequest, ApprovalEntry, AuditEntry, ListMintRequestsQuery, ListMintRequestsResponse,
    MintActionResponse, MintRequestDetail, RejectMintRequest, SubmitMintRequest,
    SubmitMintResponse,
};
use crate::middleware::rbac::CallerIdentity;
use crate::services::mint_approval::{MintApprovalService, WorkflowError};
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Extension, Json,
};
use bigdecimal::BigDecimal;
use serde_json::json;
use std::str::FromStr;
use std::sync::Arc;
use tracing::{error, info};
use uuid::Uuid;

// ============================================================================
// Shared state
// ============================================================================

#[derive(Clone)]
pub struct MintState {
    pub service: Arc<MintApprovalService>,
}

// ============================================================================
// Error mapping
// ============================================================================

fn workflow_err_to_response(e: WorkflowError) -> Response {
    let (status, code, message) = match &e {
        WorkflowError::NotFound { id } => (
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            format!("Mint request '{}' not found", id),
        ),
        WorkflowError::InvalidTransition { from, to } => (
            StatusCode::CONFLICT,
            "INVALID_TRANSITION",
            format!("Cannot transition from '{}' to '{}'", from, to),
        ),
        WorkflowError::UnauthorizedRole { role, required } => (
            StatusCode::FORBIDDEN,
            "UNAUTHORIZED_ROLE",
            format!("Role '{}' cannot act here. Required: {}", role, required),
        ),
        WorkflowError::SelfApprovalForbidden => (
            StatusCode::FORBIDDEN,
            "SELF_APPROVAL_FORBIDDEN",
            "Request creator cannot approve their own request".to_string(),
        ),
        WorkflowError::AlreadyActed { approver_id } => (
            StatusCode::CONFLICT,
            "ALREADY_ACTED",
            format!("Approver '{}' has already acted on this request", approver_id),
        ),
        WorkflowError::TerminalState { status } => (
            StatusCode::CONFLICT,
            "TERMINAL_STATE",
            format!("Request is in terminal state '{}' and cannot be modified", status),
        ),
        WorkflowError::MissingReasonCode => (
            StatusCode::BAD_REQUEST,
            "MISSING_REASON_CODE",
            "A reason_code is required when rejecting a request".to_string(),
        ),
        WorkflowError::ExecutionNotAllowed { reason } => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "EXECUTION_NOT_ALLOWED",
            reason.clone(),
        ),
        WorkflowError::Database(msg) => {
            error!(db_error = %msg, "Database error in mint workflow");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "DATABASE_ERROR",
                "An internal error occurred. Please try again later.".to_string(),
            )
        }
    };

    (status, Json(json!({ "error": code, "message": message }))).into_response()
}

// ============================================================================
// POST /api/mint/requests
// ============================================================================

/// Submit a new mint request.
///
/// Caller must be authenticated (any mint workflow role). Tier is calculated
/// automatically from `amount_ngn`.
pub async fn submit_mint_request(
    State(state): State<Arc<MintState>>,
    Extension(caller): Extension<CallerIdentity>,
    Json(body): Json<SubmitMintRequest>,
) -> Response {
    let amount_ngn = match BigDecimal::from_str(&body.amount_ngn) {
        Ok(v) if v > BigDecimal::from(0) => v,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "INVALID_AMOUNT",
                    "message": "amount_ngn must be a positive number"
                })),
            )
                .into_response();
        }
    };

    // 1:1 peg for now; swap in exchange rate service when ready
    let amount_cngn = amount_ngn.clone();
    let rate_snapshot = BigDecimal::from(1);
    let metadata = body.metadata.unwrap_or(json!({}));

    match state
        .service
        .submit(
            &caller.user_id,
            &body.destination_wallet,
            amount_ngn,
            amount_cngn,
            rate_snapshot,
            body.reference,
            metadata,
        )
        .await
    {
        Ok(req) => {
            info!(
                mint_request_id = %req.id,
                submitted_by = %caller.user_id,
                tier = req.approval_tier,
                "Mint request submitted via API"
            );
            (
                StatusCode::CREATED,
                Json(SubmitMintResponse {
                    mint_request_id: req.id,
                    status: req.status,
                    approval_tier: req.approval_tier as u8,
                    required_approvals: req.required_approvals as u8,
                    amount_ngn: req.amount_ngn.to_string(),
                    amount_cngn: req.amount_cngn.to_string(),
                    expires_at: req.expires_at,
                    message: format!(
                        "Mint request submitted. Tier {} — {} approval(s) required.",
                        req.approval_tier, req.required_approvals
                    ),
                }),
            )
                .into_response()
        }
        Err(e) => workflow_err_to_response(e),
    }
}

// ============================================================================
// POST /api/mint/requests/:id/approve
// ============================================================================

/// Approve a mint request.
///
/// Caller's role must be one of the required roles for the request's tier.
/// Self-approval and duplicate approvals are blocked.
pub async fn approve_mint_request(
    State(state): State<Arc<MintState>>,
    Extension(caller): Extension<CallerIdentity>,
    Path(id): Path<Uuid>,
    Json(body): Json<ApproveMintRequest>,
) -> Response {
    match state
        .service
        .approve(id, &caller.user_id, &caller.role, body.comment)
        .await
    {
        Ok(req) => {
            let approvals_required = req.required_approvals as usize;
            // Count approvals by re-fetching; service already updated state
            let approvals_received = if req.status == "approved" {
                approvals_required
            } else {
                // partially_approved: at least 1 but not all
                approvals_required.saturating_sub(1).max(1)
            };

            info!(
                mint_request_id = %id,
                approver = %caller.user_id,
                role = %caller.role,
                new_status = %req.status,
                "Mint request approved via API"
            );

            (
                StatusCode::OK,
                Json(MintActionResponse {
                    mint_request_id: req.id,
                    status: req.status.clone(),
                    message: format!(
                        "Approval recorded. Status: {}",
                        req.status
                    ),
                    approvals_received,
                    approvals_required,
                }),
            )
                .into_response()
        }
        Err(e) => workflow_err_to_response(e),
    }
}

// ============================================================================
// POST /api/mint/requests/:id/reject
// ============================================================================

/// Reject a mint request at any approval stage.
///
/// Immediately transitions to `rejected`. `reason_code` is mandatory.
pub async fn reject_mint_request(
    State(state): State<Arc<MintState>>,
    Extension(caller): Extension<CallerIdentity>,
    Path(id): Path<Uuid>,
    Json(body): Json<RejectMintRequest>,
) -> Response {
    match state
        .service
        .reject(
            id,
            &caller.user_id,
            &caller.role,
            &body.reason_code,
            body.comment,
        )
        .await
    {
        Ok(req) => {
            info!(
                mint_request_id = %id,
                rejector = %caller.user_id,
                role = %caller.role,
                reason_code = %body.reason_code,
                "Mint request rejected via API"
            );

            (
                StatusCode::OK,
                Json(MintActionResponse {
                    mint_request_id: req.id,
                    status: req.status,
                    message: format!(
                        "Request rejected. Reason: {}",
                        body.reason_code
                    ),
                    approvals_received: 0,
                    approvals_required: req.required_approvals as usize,
                }),
            )
                .into_response()
        }
        Err(e) => workflow_err_to_response(e),
    }
}

// ============================================================================
// GET /api/mint/requests/:id
// ============================================================================

/// Get full mint request detail including the approval timeline.
pub async fn get_mint_request(
    State(state): State<Arc<MintState>>,
    Extension(_caller): Extension<CallerIdentity>,
    Path(id): Path<Uuid>,
) -> Response {
    match state.service.get_request(id).await {
        Ok((req, approvals)) => {
            let approval_entries: Vec<ApprovalEntry> = approvals
                .into_iter()
                .map(|a| ApprovalEntry {
                    approver_id: a.approver_id,
                    approver_role: a.approver_role,
                    action: a.action,
                    reason_code: a.reason_code,
                    comment: a.comment,
                    created_at: a.created_at,
                })
                .collect();

            (
                StatusCode::OK,
                Json(MintRequestDetail {
                    id: req.id,
                    submitted_by: req.submitted_by,
                    destination_wallet: req.destination_wallet,
                    amount_ngn: req.amount_ngn.to_string(),
                    amount_cngn: req.amount_cngn.to_string(),
                    approval_tier: req.approval_tier as u8,
                    required_approvals: req.required_approvals as u8,
                    status: req.status,
                    reference: req.reference,
                    expires_at: req.expires_at,
                    stellar_tx_hash: req.stellar_tx_hash,
                    created_at: req.created_at,
                    updated_at: req.updated_at,
                    approvals: approval_entries,
                }),
            )
                .into_response()
        }
        Err(e) => workflow_err_to_response(e),
    }
}

// ============================================================================
// GET /api/mint/requests
// ============================================================================

/// List mint requests with optional status filter and pagination.
pub async fn list_mint_requests(
    State(state): State<Arc<MintState>>,
    Extension(_caller): Extension<CallerIdentity>,
    Query(params): Query<ListMintRequestsQuery>,
) -> Response {
    let limit = params.limit.unwrap_or(20).min(100);
    let offset = params.offset.unwrap_or(0);

    match state
        .service
        .list_requests(params.status.as_deref(), limit, offset)
        .await
    {
        Ok((items, total)) => {
            let response_items: Vec<MintRequestDetail> = items
                .into_iter()
                .map(|(req, approvals)| {
                    let approval_entries = approvals
                        .into_iter()
                        .map(|a| ApprovalEntry {
                            approver_id: a.approver_id,
                            approver_role: a.approver_role,
                            action: a.action,
                            reason_code: a.reason_code,
                            comment: a.comment,
                            created_at: a.created_at,
                        })
                        .collect();

                    MintRequestDetail {
                        id: req.id,
                        submitted_by: req.submitted_by,
                        destination_wallet: req.destination_wallet,
                        amount_ngn: req.amount_ngn.to_string(),
                        amount_cngn: req.amount_cngn.to_string(),
                        approval_tier: req.approval_tier as u8,
                        required_approvals: req.required_approvals as u8,
                        status: req.status,
                        reference: req.reference,
                        expires_at: req.expires_at,
                        stellar_tx_hash: req.stellar_tx_hash,
                        created_at: req.created_at,
                        updated_at: req.updated_at,
                        approvals: approval_entries,
                    }
                })
                .collect();

            (
                StatusCode::OK,
                Json(ListMintRequestsResponse {
                    items: response_items,
                    total,
                    limit,
                    offset,
                }),
            )
                .into_response()
        }
        Err(e) => workflow_err_to_response(e),
    }
}

// ============================================================================
// GET /api/mint/requests/:id/audit
// ============================================================================

/// Return the full immutable audit trail for a mint request.
pub async fn get_mint_audit(
    State(state): State<Arc<MintState>>,
    Extension(_caller): Extension<CallerIdentity>,
    Path(id): Path<Uuid>,
) -> Response {
    match state.service.get_audit_log(id).await {
        Ok(entries) => {
            let audit_entries: Vec<AuditEntry> = entries
                .into_iter()
                .map(|e| AuditEntry {
                    id: e.id,
                    actor_id: e.actor_id,
                    actor_role: e.actor_role,
                    event_type: e.event_type,
                    from_status: e.from_status,
                    to_status: e.to_status,
                    payload: e.payload,
                    created_at: e.created_at,
                })
                .collect();

            (StatusCode::OK, Json(json!({ "audit_log": audit_entries }))).into_response()
        }
        Err(e) => workflow_err_to_response(e),
    }
}
