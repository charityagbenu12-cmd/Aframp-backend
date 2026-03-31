//! Partner reporting HTTP handlers

use super::repository::ReportingRepository;
use super::statement::StatementGenerator;
use axum::{
    extract::{Path, Query, State},
    http::{header, StatusCode},
    response::IntoResponse,
    Json,
};
use chrono::NaiveDate;
use serde::Deserialize;
use std::sync::Arc;
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct DateRangeQuery {
    pub from: NaiveDate,
    pub to: NaiveDate,
}

#[derive(Debug, Deserialize)]
pub struct DateQuery {
    pub date: NaiveDate,
}

/// GET /v1/reporting/partner/:partner_id/reconciliation?from=&to=
/// Partner ERP reconciliation endpoint — returns JSON batch data
pub async fn get_reconciliation(
    State(repo): State<Arc<ReportingRepository>>,
    Path((partner_id, corridor_id)): Path<(Uuid, String)>,
    Query(params): Query<DateRangeQuery>,
) -> impl IntoResponse {
    match repo
        .get_reconciliation_entries(partner_id, &corridor_id, params.from, params.to)
        .await
    {
        Ok(entries) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "partner_id": partner_id,
                "corridor_id": corridor_id,
                "from": params.from,
                "to": params.to,
                "count": entries.len(),
                "entries": entries,
            })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

/// GET /v1/reporting/partner/:partner_id/statement/:corridor_id?date=
/// Download daily settlement statement as CSV
pub async fn download_statement(
    State(generator): State<Arc<StatementGenerator>>,
    Path((partner_id, corridor_id)): Path<(Uuid, String)>,
    Query(params): Query<DateQuery>,
) -> impl IntoResponse {
    match generator
        .generate_csv(partner_id, &corridor_id, params.date)
        .await
    {
        Ok(csv) => {
            let filename = format!(
                "settlement_{}_{}.csv",
                corridor_id,
                params.date
            );
            (
                StatusCode::OK,
                [
                    (header::CONTENT_TYPE, "text/csv"),
                    (
                        header::CONTENT_DISPOSITION,
                        &format!("attachment; filename=\"{}\"", filename),
                    ),
                ],
                csv,
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

/// GET /v1/reporting/partner/:partner_id/analytics/:corridor_id?from=&to=
pub async fn get_corridor_analytics(
    State(repo): State<Arc<ReportingRepository>>,
    Path((partner_id, corridor_id)): Path<(Uuid, String)>,
    Query(params): Query<DateRangeQuery>,
) -> impl IntoResponse {
    match repo
        .get_corridor_analytics(partner_id, &corridor_id, params.from, params.to)
        .await
    {
        Ok(analytics) => (StatusCode::OK, Json(analytics)).into_response(),
        Err(e) => (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}
