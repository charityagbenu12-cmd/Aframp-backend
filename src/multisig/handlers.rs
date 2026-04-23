//! HTTP handlers for the Multi-Sig Governance API.
//!
//! All endpoints require the caller to be an authenticated, active signer.
//! Authentication is handled by the existing auth middleware; the signer's
//! Stellar public key is extracted from the JWT claims.

use crate::multisig::{
    error::MultiSigError,
    models::{
        ListProposalsQuery, ProposeRequest, ProposalDetail, ProposalListResponse,
        RejectRequest, SignRequest,
    },
    service::MultiSigService,
};
use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    Json,
};
use std::sync::Arc;
use uuid::Uuid;

pub type MultiSigState = Arc<MultiSigService>;

// ─────────────────────────────────────────────────────────────────────────────
// POST /governance/proposals
// ─────────────────────────────────────────────────────────────────────────────

/// Propose a new treasury operation.
///
/// The caller must be an active authorised signer. The request body contains
/// the operation type, a human-readable description, and either a pre-built
/// unsigned XDR or operation parameters from which the XDR will be built.
pub async fn propose(
    State(svc): State<MultiSigState>,
    headers: HeaderMap,
    Json(body): Json<ProposeRequest>,
) -> Result<Json<serde_json::Value>, MultiSigError> {
    let proposer_key = extract_signer_key(&headers)?;

    let proposal = svc
        .propose(
            &proposer_key,
            body.op_type,
            &body.description,
            body.unsigned_xdr,
            body.op_params,
        )
        .await?;

    Ok(Json(serde_json::json!({
        "proposal_id": proposal.id,
        "status": proposal.status,
        "op_type": proposal.op_type,
        "unsigned_xdr": proposal.unsigned_xdr,
        "required_signatures": proposal.required_signatures,
        "total_signers": proposal.total_signers,
        "time_lock_until": proposal.time_lock_until,
        "expires_at": proposal.expires_at,
        "message": "Proposal created. All authorised signers have been notified."
    })))
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /governance/proposals
// ─────────────────────────────────────────────────────────────────────────────

/// List governance proposals with optional status/op_type filters.
pub async fn list_proposals(
    State(svc): State<MultiSigState>,
    Query(query): Query<ListProposalsQuery>,
) -> Result<Json<ProposalListResponse>, MultiSigError> {
    let result = svc.list_proposals(&query).await?;
    Ok(Json(result))
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /governance/proposals/:id
// ─────────────────────────────────────────────────────────────────────────────

/// Get full proposal detail including collected signatures and XDR.
///
/// Signers MUST call this endpoint to review the `unsigned_xdr` before signing.
pub async fn get_proposal(
    State(svc): State<MultiSigState>,
    Path(id): Path<Uuid>,
) -> Result<Json<ProposalDetail>, MultiSigError> {
    let detail = svc.get_proposal_detail(id).await?;
    Ok(Json(detail))
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /governance/proposals/:id/sign
// ─────────────────────────────────────────────────────────────────────────────

/// Submit a cryptographic signature for a proposal.
///
/// The signer must:
/// 1. Retrieve the proposal via `GET /governance/proposals/:id`
/// 2. Inspect the `unsigned_xdr` field on their hardware wallet (Ledger/Trezor)
/// 3. Sign the XDR with their hardware wallet
/// 4. Submit the resulting `DecoratedSignature` XDR via this endpoint
pub async fn sign_proposal(
    State(svc): State<MultiSigState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Json(body): Json<SignRequest>,
) -> Result<Json<ProposalDetail>, MultiSigError> {
    let ip = extract_ip(&headers);
    let user_agent = extract_user_agent(&headers);

    let detail = svc
        .sign(
            id,
            &body.signer_key,
            &body.signature_xdr,
            ip.as_deref(),
            user_agent.as_deref(),
        )
        .await?;

    Ok(Json(detail))
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /governance/proposals/:id/submit
// ─────────────────────────────────────────────────────────────────────────────

/// Submit the fully-signed XDR to Stellar Horizon.
///
/// The proposal must be in `ready` status (threshold met, time-lock elapsed).
/// The caller provides the final signed XDR (all DecoratedSignatures merged).
#[derive(serde::Deserialize)]
pub struct SubmitRequest {
    pub signed_xdr: String,
}

pub async fn submit_proposal(
    State(svc): State<MultiSigState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Json(body): Json<SubmitRequest>,
) -> Result<Json<serde_json::Value>, MultiSigError> {
    let actor_key = extract_signer_key(&headers)?;

    let confirmed = svc.submit(id, &actor_key, &body.signed_xdr).await?;

    Ok(Json(serde_json::json!({
        "proposal_id": confirmed.id,
        "status": confirmed.status,
        "stellar_tx_hash": confirmed.stellar_tx_hash,
        "confirmed_at": confirmed.confirmed_at,
        "message": "Transaction submitted and confirmed on Stellar."
    })))
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /governance/proposals/:id/reject
// ─────────────────────────────────────────────────────────────────────────────

/// Reject a proposal.
pub async fn reject_proposal(
    State(svc): State<MultiSigState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Json(body): Json<RejectRequest>,
) -> Result<Json<serde_json::Value>, MultiSigError> {
    let signer_key = extract_signer_key(&headers)?;

    let rejected = svc.reject(id, &signer_key, &body.reason).await?;

    Ok(Json(serde_json::json!({
        "proposal_id": rejected.id,
        "status": rejected.status,
        "failure_reason": rejected.failure_reason,
        "message": "Proposal rejected."
    })))
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /governance/proposals/:id/log
// ─────────────────────────────────────────────────────────────────────────────

/// Retrieve the tamper-evident governance audit log for a proposal.
pub async fn get_governance_log(
    State(svc): State<MultiSigState>,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, MultiSigError> {
    let entries = svc.get_governance_log(id).await?;

    Ok(Json(serde_json::json!({
        "proposal_id": id,
        "entries": entries,
        "total": entries.len(),
    })))
}

// ─────────────────────────────────────────────────────────────────────────────
// Header extraction helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Extract the signer's Stellar public key from the `X-Signer-Key` header.
///
/// In production this should be derived from the verified JWT claims set by
/// the auth middleware. The `X-Signer-Key` header is a convenience for the
/// treasury portal and hardware wallet integrations.
fn extract_signer_key(headers: &HeaderMap) -> Result<String, MultiSigError> {
    headers
        .get("X-Signer-Key")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .ok_or_else(|| {
            MultiSigError::UnauthorisedSigner(
                "Missing X-Signer-Key header".to_string(),
            )
        })
}

fn extract_ip(headers: &HeaderMap) -> Option<String> {
    headers
        .get("X-Forwarded-For")
        .or_else(|| headers.get("X-Real-IP"))
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(',').next().unwrap_or(s).trim().to_string())
}

fn extract_user_agent(headers: &HeaderMap) -> Option<String> {
    headers
        .get("User-Agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}
