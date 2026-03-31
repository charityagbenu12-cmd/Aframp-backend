use crate::lp_payout::repository::LpPayoutRepository;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde_json::{json, Value};
use std::sync::Arc;
use uuid::Uuid;

pub type LpPayoutState = Arc<LpPayoutRepository>;

/// GET /api/lp/rewards/:lp_provider_id — accrued vs paid summary per epoch
pub async fn get_accrued_vs_paid(
    State(repo): State<LpPayoutState>,
    Path(lp_provider_id): Path<Uuid>,
) -> Result<Json<Value>, StatusCode> {
    let summary = repo
        .accrued_vs_paid(lp_provider_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(json!({ "data": summary })))
}

/// GET /api/lp/epochs — list all epochs with payout records
pub async fn list_epochs(
    State(repo): State<LpPayoutState>,
) -> Result<Json<Value>, StatusCode> {
    let epochs = repo
        .get_unfinalized_epochs()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(json!({ "data": epochs.iter().map(|e| json!({
        "id": e.id,
        "epoch_start": e.epoch_start,
        "epoch_end": e.epoch_end,
        "total_fees_stroops": e.total_fees_stroops,
        "total_volume_stroops": e.total_volume_stroops,
        "is_finalized": e.is_finalized,
    })).collect::<Vec<_>>() })))
}
