//! Recurring payments API
//!
//! POST   /api/recurring              — create schedule
//! GET    /api/recurring              — list schedules for wallet
//! GET    /api/recurring/:id          — get schedule + execution history
//! PATCH  /api/recurring/:id          — update / pause / resume
//! DELETE /api/recurring/:id          — soft-cancel

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::types::BigDecimal;
use std::str::FromStr;
use std::sync::Arc;
use tracing::{error, info};
use uuid::Uuid;

use crate::database::recurring_payment_repository::{
    RecurringExecution, RecurringPaymentRepository, RecurringSchedule,
};
use crate::recurring::frequency::{next_execution_from_now, Frequency};

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct RecurringState {
    pub repo: Arc<RecurringPaymentRepository>,
    /// Default consecutive-failure threshold before auto-suspension.
    pub default_failure_threshold: i32,
}

// ---------------------------------------------------------------------------
// Request / Response types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct CreateScheduleRequest {
    pub wallet_address: String,
    pub transaction_type: String,
    pub provider: Option<String>,
    pub amount: String,
    pub currency: String,
    pub frequency: String,
    /// Required when frequency == "custom"
    pub custom_interval_days: Option<i32>,
    /// ISO-8601 start date; defaults to now if omitted
    pub start_at: Option<DateTime<Utc>>,
    /// Provider-specific fields (meter_number, account_number, etc.)
    #[serde(default)]
    pub payment_metadata: serde_json::Value,
}

#[derive(Debug, Deserialize, Default)]
pub struct ListSchedulesQuery {
    pub wallet_address: String,
    pub status: Option<String>,
    pub transaction_type: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateScheduleRequest {
    pub wallet_address: String,
    pub amount: Option<String>,
    pub frequency: Option<String>,
    pub custom_interval_days: Option<i32>,
    pub next_execution_at: Option<DateTime<Utc>>,
    /// "paused" | "active"
    pub status: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CancelScheduleRequest {
    pub wallet_address: String,
}

#[derive(Debug, Serialize)]
pub struct ScheduleResponse {
    pub id: String,
    pub wallet_address: String,
    pub transaction_type: String,
    pub provider: Option<String>,
    pub amount: String,
    pub currency: String,
    pub frequency: String,
    pub custom_interval_days: Option<i32>,
    pub payment_metadata: serde_json::Value,
    pub status: String,
    pub failure_count: i32,
    pub failure_threshold: i32,
    pub next_execution_at: DateTime<Utc>,
    pub last_executed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct ExecutionResponse {
    pub id: String,
    pub schedule_id: String,
    pub scheduled_at: DateTime<Utc>,
    pub executed_at: DateTime<Utc>,
    pub outcome: String,
    pub transaction_id: Option<String>,
    pub error_message: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ScheduleDetailResponse {
    #[serde(flatten)]
    pub schedule: ScheduleResponse,
    pub executions: Vec<ExecutionResponse>,
}

#[derive(Debug, Serialize)]
pub struct ErrorBody {
    pub code: String,
    pub message: String,
}

fn err(status: StatusCode, code: &str, msg: impl Into<String>) -> impl IntoResponse {
    (status, Json(ErrorBody { code: code.to_string(), message: msg.into() }))
}

// ---------------------------------------------------------------------------
// Mapping helpers
// ---------------------------------------------------------------------------

fn map_schedule(s: RecurringSchedule) -> ScheduleResponse {
    ScheduleResponse {
        id: s.id.to_string(),
        wallet_address: s.wallet_address,
        transaction_type: s.transaction_type,
        provider: s.provider,
        amount: s.amount.to_string(),
        currency: s.currency,
        frequency: s.frequency,
        custom_interval_days: s.custom_interval_days,
        payment_metadata: s.payment_metadata,
        status: s.status,
        failure_count: s.failure_count,
        failure_threshold: s.failure_threshold,
        next_execution_at: s.next_execution_at,
        last_executed_at: s.last_executed_at,
        created_at: s.created_at,
        updated_at: s.updated_at,
    }
}

fn map_execution(e: RecurringExecution) -> ExecutionResponse {
    ExecutionResponse {
        id: e.id.to_string(),
        schedule_id: e.schedule_id.to_string(),
        scheduled_at: e.scheduled_at,
        executed_at: e.executed_at,
        outcome: e.outcome,
        transaction_id: e.transaction_id.map(|u| u.to_string()),
        error_message: e.error_message,
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// POST /api/recurring
pub async fn create_schedule(
    State(state): State<Arc<RecurringState>>,
    Json(req): Json<CreateScheduleRequest>,
) -> impl IntoResponse {
    // Validate frequency
    let freq = match Frequency::parse(&req.frequency, req.custom_interval_days) {
        Ok(f) => f,
        Err(e) => return err(StatusCode::BAD_REQUEST, "INVALID_FREQUENCY", e).into_response(),
    };

    // Validate amount
    let amount = match BigDecimal::from_str(&req.amount) {
        Ok(a) if a > BigDecimal::from(0) => a,
        _ => return err(StatusCode::BAD_REQUEST, "INVALID_AMOUNT", "amount must be a positive number").into_response(),
    };

    // Validate transaction_type
    if !["bill_payment", "onramp", "offramp"].contains(&req.transaction_type.as_str()) {
        return err(StatusCode::BAD_REQUEST, "INVALID_TYPE", "unsupported transaction_type").into_response();
    }

    let start = req.start_at.unwrap_or_else(Utc::now);
    let next_execution_at = next_execution_from_now(&freq, start);

    match state.repo.create_schedule(
        &req.wallet_address,
        &req.transaction_type,
        req.provider.as_deref(),
        amount,
        &req.currency,
        &req.frequency,
        req.custom_interval_days,
        req.payment_metadata,
        state.default_failure_threshold,
        next_execution_at,
    ).await {
        Ok(schedule) => {
            info!(
                schedule_id = %schedule.id,
                wallet = %schedule.wallet_address,
                frequency = %schedule.frequency,
                next_execution_at = %schedule.next_execution_at,
                "Recurring schedule created"
            );
            (StatusCode::CREATED, Json(map_schedule(schedule))).into_response()
        }
        Err(e) => {
            error!(error = %e, "Failed to create recurring schedule");
            err(StatusCode::INTERNAL_SERVER_ERROR, "DATABASE_ERROR", "failed to create schedule").into_response()
        }
    }
}

/// GET /api/recurring?wallet_address=...&status=...&transaction_type=...
pub async fn list_schedules(
    State(state): State<Arc<RecurringState>>,
    Query(query): Query<ListSchedulesQuery>,
) -> impl IntoResponse {
    if query.wallet_address.is_empty() {
        return err(StatusCode::BAD_REQUEST, "MISSING_WALLET", "wallet_address is required").into_response();
    }

    match state.repo.list_for_wallet(
        &query.wallet_address,
        query.status.as_deref(),
        query.transaction_type.as_deref(),
    ).await {
        Ok(schedules) => {
            let resp: Vec<ScheduleResponse> = schedules.into_iter().map(map_schedule).collect();
            Json(resp).into_response()
        }
        Err(e) => {
            error!(error = %e, "Failed to list recurring schedules");
            err(StatusCode::INTERNAL_SERVER_ERROR, "DATABASE_ERROR", "failed to list schedules").into_response()
        }
    }
}

/// GET /api/recurring/:id?wallet_address=...
pub async fn get_schedule(
    State(state): State<Arc<RecurringState>>,
    Path(id): Path<Uuid>,
    Query(query): Query<ListSchedulesQuery>,
) -> impl IntoResponse {
    if query.wallet_address.is_empty() {
        return err(StatusCode::BAD_REQUEST, "MISSING_WALLET", "wallet_address is required").into_response();
    }

    let schedule = match state.repo.find_by_id_and_wallet(id, &query.wallet_address).await {
        Ok(Some(s)) => s,
        Ok(None) => return err(StatusCode::NOT_FOUND, "NOT_FOUND", "schedule not found").into_response(),
        Err(e) => {
            error!(error = %e, "Failed to fetch recurring schedule");
            return err(StatusCode::INTERNAL_SERVER_ERROR, "DATABASE_ERROR", "failed to fetch schedule").into_response();
        }
    };

    let executions = match state.repo.list_executions_for_schedule(id).await {
        Ok(execs) => execs.into_iter().map(map_execution).collect(),
        Err(e) => {
            error!(error = %e, "Failed to fetch execution history");
            return err(StatusCode::INTERNAL_SERVER_ERROR, "DATABASE_ERROR", "failed to fetch executions").into_response();
        }
    };

    Json(ScheduleDetailResponse {
        schedule: map_schedule(schedule),
        executions,
    }).into_response()
}

/// PATCH /api/recurring/:id
pub async fn update_schedule(
    State(state): State<Arc<RecurringState>>,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateScheduleRequest>,
) -> impl IntoResponse {
    // Ownership check
    let existing = match state.repo.find_by_id_and_wallet(id, &req.wallet_address).await {
        Ok(Some(s)) => s,
        Ok(None) => return err(StatusCode::NOT_FOUND, "NOT_FOUND", "schedule not found").into_response(),
        Err(e) => {
            error!(error = %e, "DB error on update ownership check");
            return err(StatusCode::INTERNAL_SERVER_ERROR, "DATABASE_ERROR", "db error").into_response();
        }
    };

    // Cannot update cancelled or suspended schedules (except to resume from paused)
    if existing.status == "cancelled" {
        return err(StatusCode::UNPROCESSABLE_ENTITY, "CANCELLED", "cannot update a cancelled schedule").into_response();
    }

    // Validate status transition
    if let Some(ref new_status) = req.status {
        match new_status.as_str() {
            "paused" if existing.status != "active" => {
                return err(StatusCode::UNPROCESSABLE_ENTITY, "INVALID_TRANSITION", "only active schedules can be paused").into_response();
            }
            "active" if existing.status != "paused" => {
                return err(StatusCode::UNPROCESSABLE_ENTITY, "INVALID_TRANSITION", "only paused schedules can be resumed").into_response();
            }
            "paused" | "active" => {}
            _ => return err(StatusCode::BAD_REQUEST, "INVALID_STATUS", "status must be 'paused' or 'active'").into_response(),
        }
    }

    // Validate new frequency if provided
    if let Some(ref freq_str) = req.frequency {
        if let Err(e) = Frequency::parse(freq_str, req.custom_interval_days) {
            return err(StatusCode::BAD_REQUEST, "INVALID_FREQUENCY", e).into_response();
        }
    }

    let amount = match req.amount.as_deref() {
        Some(a) => match BigDecimal::from_str(a) {
            Ok(v) if v > BigDecimal::from(0) => Some(v),
            _ => return err(StatusCode::BAD_REQUEST, "INVALID_AMOUNT", "amount must be positive").into_response(),
        },
        None => None,
    };

    match state.repo.update_schedule(
        id,
        amount,
        req.frequency.as_deref(),
        req.custom_interval_days,
        req.next_execution_at,
        req.status.as_deref(),
    ).await {
        Ok(schedule) => {
            info!(schedule_id = %id, "Recurring schedule updated");
            Json(map_schedule(schedule)).into_response()
        }
        Err(e) => {
            error!(error = %e, "Failed to update recurring schedule");
            err(StatusCode::INTERNAL_SERVER_ERROR, "DATABASE_ERROR", "failed to update schedule").into_response()
        }
    }
}

/// DELETE /api/recurring/:id
pub async fn cancel_schedule(
    State(state): State<Arc<RecurringState>>,
    Path(id): Path<Uuid>,
    Json(req): Json<CancelScheduleRequest>,
) -> impl IntoResponse {
    // Ownership check
    match state.repo.find_by_id_and_wallet(id, &req.wallet_address).await {
        Ok(None) => return err(StatusCode::NOT_FOUND, "NOT_FOUND", "schedule not found").into_response(),
        Err(e) => {
            error!(error = %e, "DB error on cancel ownership check");
            return err(StatusCode::INTERNAL_SERVER_ERROR, "DATABASE_ERROR", "db error").into_response();
        }
        Ok(Some(_)) => {}
    }

    match state.repo.cancel_schedule(id).await {
        Ok(schedule) => {
            info!(schedule_id = %id, "Recurring schedule cancelled");
            Json(map_schedule(schedule)).into_response()
        }
        Err(e) => {
            error!(error = %e, "Failed to cancel recurring schedule");
            err(StatusCode::INTERNAL_SERVER_ERROR, "DATABASE_ERROR", "failed to cancel schedule").into_response()
        }
    }
}
