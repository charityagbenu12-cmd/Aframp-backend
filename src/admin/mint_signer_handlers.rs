use crate::admin::mint_signer_models::*;
use crate::admin::mint_signer_service::MintSignerService;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

#[derive(Serialize)]
pub struct ApiResponse<T: Serialize> { pub success: bool, pub data: T }

fn ok<T: Serialize>(data: T) -> Json<ApiResponse<T>> {
    Json(ApiResponse { success: true, data })
}

#[derive(Deserialize)]
pub struct PaginationQuery { pub limit: Option<i64>, pub offset: Option<i64> }

// POST /api/admin/mint/signers
pub async fn initiate_onboarding(
    State(svc): State<Arc<MintSignerService>>,
    Json(req): Json<InitiateOnboardingRequest>,
) -> Result<(StatusCode, Json<ApiResponse<serde_json::Value>>), (StatusCode, String)> {
    // In production, initiated_by comes from the auth context extension
    let initiated_by = Uuid::nil(); // placeholder — wire from AdminAuthContext
    let (signer, token) = svc.initiate_onboarding(req, initiated_by).await
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    Ok((StatusCode::CREATED, Json(ApiResponse {
        success: true,
        data: serde_json::json!({ "signer_id": signer.id, "onboarding_token": token }),
    })))
}

// POST /api/admin/mint/signers/complete-onboarding
pub async fn complete_onboarding(
    State(svc): State<Arc<MintSignerService>>,
    Json(req): Json<CompleteOnboardingRequest>,
) -> Result<Json<ApiResponse<MintSigner>>, (StatusCode, String)> {
    let signer = svc.complete_onboarding(req, None).await
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    Ok(ok(signer))
}

// POST /api/admin/mint/signers/:id/confirm-identity
pub async fn confirm_identity(
    State(svc): State<Arc<MintSignerService>>,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<()>>, (StatusCode, String)> {
    svc.confirm_identity(id).await.map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    Ok(ok(()))
}

// POST /api/admin/mint/signers/:id/challenge
pub async fn request_challenge(
    State(svc): State<Arc<MintSignerService>>,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<serde_json::Value>>, (StatusCode, String)> {
    let challenge = svc.generate_challenge(id, None).await
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    Ok(ok(serde_json::json!({ "challenge": challenge })))
}

// POST /api/admin/mint/signers/:id/rotate-key
pub async fn rotate_key(
    State(svc): State<Arc<MintSignerService>>,
    Path(id): Path<Uuid>,
    Json(req): Json<RotateKeyRequest>,
) -> Result<Json<ApiResponse<MintSignerKeyRotation>>, (StatusCode, String)> {
    let initiated_by = Uuid::nil(); // wire from auth context
    let rotation = svc.initiate_key_rotation(id, req, initiated_by, None).await
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    Ok(ok(rotation))
}

// POST /api/admin/mint/signers/:id/rotate-key/challenge
pub async fn request_rotation_challenge(
    State(svc): State<Arc<MintSignerService>>,
    Path(id): Path<Uuid>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<ApiResponse<serde_json::Value>>, (StatusCode, String)> {
    let new_key = body.get("new_stellar_public_key").and_then(|v| v.as_str())
        .ok_or((StatusCode::BAD_REQUEST, "new_stellar_public_key required".into()))?;
    let challenge = svc.generate_rotation_challenge(id, new_key, None).await
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    Ok(ok(serde_json::json!({ "challenge": challenge })))
}

// POST /api/admin/mint/signers/:id/suspend
pub async fn suspend_signer(
    State(svc): State<Arc<MintSignerService>>,
    Path(id): Path<Uuid>,
    Json(req): Json<SuspendSignerRequest>,
) -> Result<Json<ApiResponse<()>>, (StatusCode, String)> {
    svc.suspend(id, &req.reason).await.map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    Ok(ok(()))
}

// POST /api/admin/mint/signers/:id/remove
pub async fn remove_signer(
    State(svc): State<Arc<MintSignerService>>,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<()>>, (StatusCode, String)> {
    svc.remove(id).await.map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    Ok(ok(()))
}

// GET /api/admin/mint/signers
pub async fn list_signers(
    State(svc): State<Arc<MintSignerService>>,
) -> Result<Json<ApiResponse<Vec<SignerSummary>>>, (StatusCode, String)> {
    let signers = svc.repo_list_all().await.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    let summaries = signers.into_iter().map(|s| SignerSummary {
        id: s.id,
        full_legal_name: s.full_legal_name,
        role: s.role,
        organisation: s.organisation,
        status: s.status,
        key_fingerprint: s.key_fingerprint,
        last_signing_at: s.last_signing_at,
        key_expires_at: s.key_expires_at,
    }).collect();
    Ok(ok(summaries))
}

// GET /api/admin/mint/signers/:id
pub async fn get_signer(
    State(svc): State<Arc<MintSignerService>>,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<MintSigner>>, (StatusCode, String)> {
    let signer = svc.repo_find_by_id(id).await.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?
        .ok_or((StatusCode::NOT_FOUND, "Signer not found".into()))?;
    Ok(ok(signer))
}

// GET /api/admin/mint/signers/:id/activity
pub async fn get_signer_activity(
    State(svc): State<Arc<MintSignerService>>,
    Path(id): Path<Uuid>,
    Query(q): Query<PaginationQuery>,
) -> Result<Json<ApiResponse<Vec<MintSignerActivity>>>, (StatusCode, String)> {
    let activity = svc.repo_list_activity(id, q.limit.unwrap_or(50), q.offset.unwrap_or(0)).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok(ok(activity))
}

// GET /api/admin/mint/quorum
pub async fn get_quorum(
    State(svc): State<Arc<MintSignerService>>,
) -> Result<Json<ApiResponse<QuorumStatus>>, (StatusCode, String)> {
    let status = svc.get_quorum_status().await.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok(ok(status))
}

// PATCH /api/admin/mint/quorum
pub async fn update_quorum(
    State(svc): State<Arc<MintSignerService>>,
    Json(req): Json<UpdateQuorumRequest>,
) -> Result<Json<ApiResponse<MintQuorumConfig>>, (StatusCode, String)> {
    let updated_by = Uuid::nil(); // wire from auth context
    let cfg = svc.update_quorum(req, updated_by).await
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    Ok(ok(cfg))
}
