use crate::lp_onboarding::{
    models::*,
    service::{LpOnboardingService, ServiceError},
};
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use std::sync::Arc;
use uuid::Uuid;

pub type LpOnboardingState = Arc<LpOnboardingService>;

fn service_err(e: ServiceError) -> (StatusCode, Json<serde_json::Value>) {
    let status = match &e {
        ServiceError::PartnerNotFound | ServiceError::AgreementNotFound => StatusCode::NOT_FOUND,
        ServiceError::PartnerNotActive
        | ServiceError::KybNotPassed
        | ServiceError::NoSignedAgreement
        | ServiceError::InvalidStellarAddress => StatusCode::UNPROCESSABLE_ENTITY,
        ServiceError::DocuSignError(_) => StatusCode::BAD_GATEWAY,
        ServiceError::Db(_) => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (status, Json(serde_json::json!({ "error": e.to_string() })))
}

// ── Partner handlers ──────────────────────────────────────────────────────────

pub async fn register_partner(
    State(svc): State<LpOnboardingState>,
    Json(req): Json<RegisterPartnerRequest>,
) -> impl IntoResponse {
    match svc.register_partner(req).await {
        Ok(p) => (StatusCode::CREATED, Json(serde_json::to_value(p).unwrap())).into_response(),
        Err(e) => service_err(e).into_response(),
    }
}

#[derive(Deserialize)]
pub struct ListPartnersQuery {
    pub status: Option<LpStatus>,
}

pub async fn list_partners(
    State(svc): State<LpOnboardingState>,
    Query(q): Query<ListPartnersQuery>,
) -> impl IntoResponse {
    match svc.list_partners(q.status).await {
        Ok(list) => Json(serde_json::to_value(list).unwrap()).into_response(),
        Err(e) => service_err(e).into_response(),
    }
}

pub async fn get_dashboard(
    State(svc): State<LpOnboardingState>,
    Path(partner_id): Path<Uuid>,
) -> impl IntoResponse {
    match svc.get_dashboard(partner_id).await {
        Ok(d) => Json(serde_json::to_value(d).unwrap()).into_response(),
        Err(e) => service_err(e).into_response(),
    }
}

pub async fn revoke_partner(
    State(svc): State<LpOnboardingState>,
    Path(partner_id): Path<Uuid>,
    // In production, extract admin_id from JWT claims; using header for brevity
    axum::extract::Extension(admin_id): axum::extract::Extension<Uuid>,
    Json(req): Json<RevokePartnerRequest>,
) -> impl IntoResponse {
    match svc.revoke_partner(partner_id, admin_id, req).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => service_err(e).into_response(),
    }
}

pub async fn update_tier(
    State(svc): State<LpOnboardingState>,
    Path(partner_id): Path<Uuid>,
    Json(req): Json<UpdatePartnerTierRequest>,
) -> impl IntoResponse {
    match svc.update_tier(partner_id, req).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => service_err(e).into_response(),
    }
}

pub async fn mark_kyb_passed(
    State(svc): State<LpOnboardingState>,
    Path(partner_id): Path<Uuid>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let kyb_ref = match body["kyb_reference_id"]
        .as_str()
        .and_then(|s| Uuid::parse_str(s).ok())
    {
        Some(id) => id,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error":"missing kyb_reference_id"})),
            )
                .into_response()
        }
    };
    match svc.mark_kyb_passed(partner_id, kyb_ref).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => service_err(e).into_response(),
    }
}

// ── Document handlers ─────────────────────────────────────────────────────────

pub async fn upload_document(
    State(svc): State<LpOnboardingState>,
    Path(partner_id): Path<Uuid>,
    Json(req): Json<UploadDocumentRequest>,
) -> impl IntoResponse {
    match svc.upload_document(partner_id, req).await {
        Ok(d) => (StatusCode::CREATED, Json(serde_json::to_value(d).unwrap())).into_response(),
        Err(e) => service_err(e).into_response(),
    }
}

pub async fn review_document(
    State(svc): State<LpOnboardingState>,
    Path((_partner_id, document_id)): Path<(Uuid, Uuid)>,
    axum::extract::Extension(reviewer_id): axum::extract::Extension<Uuid>,
    Json(req): Json<ReviewDocumentRequest>,
) -> impl IntoResponse {
    match svc.review_document(document_id, reviewer_id, req).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => service_err(e).into_response(),
    }
}

// ── Agreement handlers ────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct SendAgreementRequest {
    #[serde(flatten)]
    pub agreement: CreateAgreementRequest,
    pub signer_email: String,
    pub signer_name: String,
}

pub async fn send_agreement(
    State(svc): State<LpOnboardingState>,
    Path(partner_id): Path<Uuid>,
    Json(req): Json<SendAgreementRequest>,
) -> impl IntoResponse {
    match svc
        .send_agreement_for_signature(
            partner_id,
            req.agreement,
            req.signer_email,
            req.signer_name,
        )
        .await
    {
        Ok(a) => (StatusCode::CREATED, Json(serde_json::to_value(a).unwrap())).into_response(),
        Err(e) => service_err(e).into_response(),
    }
}

pub async fn docusign_webhook(
    State(svc): State<LpOnboardingState>,
    Json(payload): Json<DocuSignWebhookPayload>,
) -> impl IntoResponse {
    match svc.handle_docusign_webhook(payload).await {
        Ok(()) => StatusCode::OK.into_response(),
        Err(e) => service_err(e).into_response(),
    }
}

// ── Stellar key handlers ──────────────────────────────────────────────────────

pub async fn add_stellar_key(
    State(svc): State<LpOnboardingState>,
    Path(partner_id): Path<Uuid>,
    axum::extract::Extension(admin_id): axum::extract::Extension<Uuid>,
    Json(req): Json<AddStellarKeyRequest>,
) -> impl IntoResponse {
    match svc.add_stellar_key(partner_id, admin_id, req).await {
        Ok(k) => (StatusCode::CREATED, Json(serde_json::to_value(k).unwrap())).into_response(),
        Err(e) => service_err(e).into_response(),
    }
}

pub async fn revoke_stellar_key(
    State(svc): State<LpOnboardingState>,
    Path((_partner_id, key_id)): Path<(Uuid, Uuid)>,
    axum::extract::Extension(admin_id): axum::extract::Extension<Uuid>,
) -> impl IntoResponse {
    match svc.revoke_stellar_key(key_id, admin_id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => service_err(e).into_response(),
    }
}
