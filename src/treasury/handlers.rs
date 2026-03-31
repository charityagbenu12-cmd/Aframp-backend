use crate::treasury::{
    engine::InterventionEngine,
    types::{ListInterventionsQuery, SystemMode, TriggerInterventionRequest, TriggerInterventionResponse},
};
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use std::sync::Arc;
use uuid::Uuid;

pub type EngineState = Arc<InterventionEngine>;

/// POST /treasury/intervention/trigger
///
/// One-click emergency intervention. Validates hardware-token OTP, submits
/// the Stellar transaction, and returns within the 60-second SLA.
pub async fn trigger_intervention(
    State(engine): State<EngineState>,
    // In production the admin identity comes from the JWT / session middleware.
    // We read it from a custom header set by the auth layer.
    axum::extract::Extension(admin_id): axum::extract::Extension<String>,
    Json(req): Json<TriggerInterventionRequest>,
) -> impl IntoResponse {
    match engine.execute(req, &admin_id).await {
        Ok(record) => {
            let resp = TriggerInterventionResponse {
                intervention_id: record.id,
                status: record.status,
                stellar_tx_hash: record.stellar_tx_hash,
                message: "Emergency intervention executed successfully".to_string(),
            };
            (StatusCode::CREATED, Json(resp)).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e })),
        )
            .into_response(),
    }
}

/// GET /treasury/intervention/:id
pub async fn get_intervention(
    State(engine): State<EngineState>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    match engine.fetch_record(id).await {
        Ok(record) => (StatusCode::OK, Json(record)).into_response(),
        Err(e) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": e })),
        )
            .into_response(),
    }
}

/// GET /treasury/intervention
pub async fn list_interventions(
    State(engine): State<EngineState>,
    Query(q): Query<ListInterventionsQuery>,
) -> impl IntoResponse {
    match engine
        .list_records(q.status, q.page_size(), q.offset())
        .await
    {
        Ok(records) => (StatusCode::OK, Json(records)).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e })),
        )
            .into_response(),
    }
}

/// GET /treasury/mode
///
/// Returns the current system mode. The frontend uses this to display the
/// "System Under Intervention" banner for internal staff.
pub async fn get_system_mode(State(engine): State<EngineState>) -> impl IntoResponse {
    let mode = *engine.current_mode().read().await;
    let under_intervention = mode == SystemMode::UnderIntervention;
    Json(serde_json::json!({
        "mode": if under_intervention { "under_intervention" } else { "normal" },
        "under_intervention": under_intervention,
    }))
}
