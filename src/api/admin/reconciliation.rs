//! Admin API: Reconciliation discrepancy review and period-close lock.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, patch},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

// ── State ─────────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct ReconciliationState {
    pub pool: PgPool,
}

// ── Request / Response types ──────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ListDiscrepanciesQuery {
    pub status: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct ResolveDiscrepancyRequest {
    pub notes: Option<String>,
    pub resolved_by: String,
}

#[derive(Debug, Serialize)]
pub struct DiscrepancyRow {
    pub id: Uuid,
    pub transaction_id: Option<Uuid>,
    pub discrepancy_type: String,
    pub status: String,
    pub fiat_amount: Option<String>,
    pub mint_amount: Option<String>,
    pub stellar_tx_hash: Option<String>,
    pub payment_reference: Option<String>,
    pub detected_at: chrono::DateTime<chrono::Utc>,
    pub resolved_at: Option<chrono::DateTime<chrono::Utc>>,
    pub notes: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ReportRow {
    pub id: Uuid,
    pub report_date: chrono::NaiveDate,
    pub total_transactions: i32,
    pub matched_count: i32,
    pub discrepancy_count: i32,
    pub missing_mint_count: i32,
    pub unauthorized_mint_count: i32,
    pub amount_mismatch_count: i32,
    pub has_open_discrepancies: bool,
    pub period_closed: bool,
    pub generated_at: chrono::DateTime<chrono::Utc>,
}

// ── Handlers ──────────────────────────────────────────────────────────────────

/// GET /admin/reconciliation/discrepancies
async fn list_discrepancies(
    State(state): State<Arc<ReconciliationState>>,
    Query(q): Query<ListDiscrepanciesQuery>,
) -> impl IntoResponse {
    let status_filter = q.status.as_deref().unwrap_or("OPEN");
    let limit = q.limit.unwrap_or(50).min(200);
    let offset = q.offset.unwrap_or(0);

    let rows = sqlx::query!(
        r#"
        SELECT id, transaction_id, discrepancy_type::TEXT as dtype,
               status::TEXT as status,
               fiat_amount::TEXT as fiat_amount,
               mint_amount::TEXT as mint_amount,
               stellar_tx_hash, payment_reference,
               detected_at, resolved_at, notes
        FROM discrepancy_log
        WHERE status::TEXT = $1
        ORDER BY detected_at DESC
        LIMIT $2 OFFSET $3
        "#,
        status_filter,
        limit,
        offset
    )
    .fetch_all(&state.pool)
    .await;

    match rows {
        Ok(rows) => {
            let result: Vec<DiscrepancyRow> = rows
                .into_iter()
                .map(|r| DiscrepancyRow {
                    id: r.id,
                    transaction_id: r.transaction_id,
                    discrepancy_type: r.dtype.unwrap_or_default(),
                    status: r.status.unwrap_or_default(),
                    fiat_amount: r.fiat_amount,
                    mint_amount: r.mint_amount,
                    stellar_tx_hash: r.stellar_tx_hash,
                    payment_reference: r.payment_reference,
                    detected_at: r.detected_at,
                    resolved_at: r.resolved_at,
                    notes: r.notes,
                })
                .collect();
            Json(result).into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to list discrepancies");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// PATCH /admin/reconciliation/discrepancies/:id/resolve
async fn resolve_discrepancy(
    State(state): State<Arc<ReconciliationState>>,
    Path(id): Path<Uuid>,
    Json(body): Json<ResolveDiscrepancyRequest>,
) -> impl IntoResponse {
    let result = sqlx::query!(
        r#"
        UPDATE discrepancy_log
        SET status = 'RESOLVED',
            resolved_at = now(),
            resolved_by = $2,
            notes = COALESCE($3, notes)
        WHERE id = $1 AND status != 'RESOLVED'
        RETURNING id
        "#,
        id,
        body.resolved_by,
        body.notes,
    )
    .fetch_optional(&state.pool)
    .await;

    match result {
        Ok(Some(_)) => StatusCode::OK.into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            tracing::error!(error = %e, "Failed to resolve discrepancy");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// GET /admin/reconciliation/reports
async fn list_reports(
    State(state): State<Arc<ReconciliationState>>,
) -> impl IntoResponse {
    let rows = sqlx::query!(
        r#"
        SELECT id, report_date, total_transactions, matched_count, discrepancy_count,
               missing_mint_count, unauthorized_mint_count, amount_mismatch_count,
               has_open_discrepancies, period_closed, generated_at
        FROM reconciliation_reports
        ORDER BY report_date DESC
        LIMIT 30
        "#
    )
    .fetch_all(&state.pool)
    .await;

    match rows {
        Ok(rows) => {
            let result: Vec<ReportRow> = rows
                .into_iter()
                .map(|r| ReportRow {
                    id: r.id,
                    report_date: r.report_date,
                    total_transactions: r.total_transactions,
                    matched_count: r.matched_count,
                    discrepancy_count: r.discrepancy_count,
                    missing_mint_count: r.missing_mint_count,
                    unauthorized_mint_count: r.unauthorized_mint_count,
                    amount_mismatch_count: r.amount_mismatch_count,
                    has_open_discrepancies: r.has_open_discrepancies,
                    period_closed: r.period_closed,
                    generated_at: r.generated_at,
                })
                .collect();
            Json(result).into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to list reconciliation reports");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// PATCH /admin/reconciliation/reports/:date/close
/// Prevents closing a period if open discrepancies exist.
async fn close_period(
    State(state): State<Arc<ReconciliationState>>,
    Path(date): Path<chrono::NaiveDate>,
) -> impl IntoResponse {
    // Block close if open discrepancies exist for this date
    let open_count: i64 = sqlx::query_scalar!(
        r#"
        SELECT COUNT(*) FROM discrepancy_log
        WHERE detected_at::DATE = $1 AND status != 'RESOLVED'
        "#,
        date
    )
    .fetch_one(&state.pool)
    .await
    .unwrap_or(Some(0))
    .unwrap_or(0);

    if open_count > 0 {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "error": "Cannot close period: open discrepancies exist",
                "open_count": open_count
            })),
        )
            .into_response();
    }

    let result = sqlx::query!(
        "UPDATE reconciliation_reports SET period_closed = TRUE WHERE report_date = $1 RETURNING id",
        date
    )
    .fetch_optional(&state.pool)
    .await;

    match result {
        Ok(Some(_)) => StatusCode::OK.into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            tracing::error!(error = %e, "Failed to close period");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

// ── Router ────────────────────────────────────────────────────────────────────

pub fn reconciliation_routes(state: Arc<ReconciliationState>) -> Router {
    Router::new()
        .route("/discrepancies", get(list_discrepancies))
        .route("/discrepancies/:id/resolve", patch(resolve_discrepancy))
        .route("/reports", get(list_reports))
        .route("/reports/:date/close", patch(close_period))
        .with_state(state)
}
