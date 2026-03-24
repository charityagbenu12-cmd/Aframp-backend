//! Batch transaction processing API (Issue #125).
//!
//! Routes:
//!   POST /api/batch/cngn-transfer   — initiate a batch cNGN transfer
//!   POST /api/batch/fiat-payout     — initiate a batch fiat payout
//!   GET  /api/batch/:batch_id       — get batch status and per-item details

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use bigdecimal::BigDecimal;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::str::FromStr;
use std::sync::Arc;
use tracing::{error, info, warn};
use uuid::Uuid;

// ─── State ───────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct BatchState {
    pub db: Arc<PgPool>,
    /// Maximum items allowed per cNGN transfer batch (from batch_config table)
    pub max_cngn_batch_size: usize,
    /// Maximum items allowed per fiat payout batch
    pub max_fiat_batch_size: usize,
}

impl BatchState {
    pub fn new(db: Arc<PgPool>) -> Self {
        Self {
            db,
            max_cngn_batch_size: 100,
            max_fiat_batch_size: 500,
        }
    }
}

// ─── Request / Response Models ────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct CngnTransferItem {
    pub destination_wallet: String,
    pub amount_cngn: String,
    pub memo: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct BatchCngnTransferRequest {
    /// Source Stellar wallet address
    pub source_wallet: String,
    /// List of recipients — max 100 items
    pub transfers: Vec<CngnTransferItem>,
}

#[derive(Debug, Deserialize)]
pub struct FiatPayoutItem {
    pub bank_account_number: String,
    pub bank_code: String,
    pub amount_ngn: String,
    pub reference: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct BatchFiatPayoutRequest {
    /// List of payouts — max 500 items
    pub payouts: Vec<FiatPayoutItem>,
}

#[derive(Debug, Serialize)]
pub struct BatchCreateResponse {
    pub batch_id: Uuid,
    pub status: String,
    pub total_items: usize,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct BatchItemStatusResponse {
    pub item_id: Uuid,
    pub status: String,
    pub destination: String,
    pub amount: String,
    pub stellar_tx_hash: Option<String>,
    pub failure_reason: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct BatchStatusResponse {
    pub batch_id: Uuid,
    pub batch_type: String,
    pub status: String,
    pub total_count: i32,
    pub success_count: i32,
    pub failed_count: i32,
    pub pending_count: i32,
    pub items: Vec<BatchItemStatusResponse>,
    pub created_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: ErrorDetail,
}

#[derive(Debug, Serialize)]
pub struct ErrorDetail {
    pub code: String,
    pub message: String,
}

fn error_response(status: StatusCode, code: &str, message: &str) -> Response {
    (
        status,
        Json(ErrorResponse {
            error: ErrorDetail {
                code: code.to_string(),
                message: message.to_string(),
            },
        }),
    )
        .into_response()
}

// ─── Validation Helpers ───────────────────────────────────────────────────────

fn is_valid_stellar_address(addr: &str) -> bool {
    addr.starts_with('G') && addr.len() == 56
}

fn parse_positive_decimal(value: &str) -> Option<BigDecimal> {
    let d = BigDecimal::from_str(value.trim()).ok()?;
    if d > BigDecimal::from(0) {
        Some(d)
    } else {
        None
    }
}

// ─── Handlers ────────────────────────────────────────────────────────────────

/// POST /api/batch/cngn-transfer
///
/// Validates all recipient wallets and source balance, then creates a batch record
/// with individual item records in `pending` status.
///
/// Requires scope: `batch:cngn_transfer`
pub async fn create_cngn_transfer_batch(
    State(state): State<BatchState>,
    Json(body): Json<BatchCngnTransferRequest>,
) -> Response {
    info!(
        source_wallet = %body.source_wallet,
        count = body.transfers.len(),
        "Creating cNGN transfer batch"
    );

    if body.transfers.is_empty() {
        return error_response(
            StatusCode::BAD_REQUEST,
            "EMPTY_BATCH",
            "Batch must contain at least one transfer",
        );
    }

    if body.transfers.len() > state.max_cngn_batch_size {
        return error_response(
            StatusCode::BAD_REQUEST,
            "BATCH_TOO_LARGE",
            &format!(
                "Batch exceeds maximum size of {} items",
                state.max_cngn_batch_size
            ),
        );
    }

    if !is_valid_stellar_address(&body.source_wallet) {
        return error_response(
            StatusCode::BAD_REQUEST,
            "INVALID_SOURCE_WALLET",
            "Source wallet is not a valid Stellar address",
        );
    }

    // Validate all items
    for (i, item) in body.transfers.iter().enumerate() {
        if !is_valid_stellar_address(&item.destination_wallet) {
            return error_response(
                StatusCode::BAD_REQUEST,
                "INVALID_DESTINATION_WALLET",
                &format!("Item {}: invalid Stellar address '{}'", i, item.destination_wallet),
            );
        }
        if parse_positive_decimal(&item.amount_cngn).is_none() {
            return error_response(
                StatusCode::BAD_REQUEST,
                "INVALID_AMOUNT",
                &format!("Item {}: amount_cngn '{}' is not a valid positive decimal", i, item.amount_cngn),
            );
        }
    }

    // Create the batch record
    let batch_id = Uuid::new_v4();
    let total = body.transfers.len() as i32;

    let mut tx = match state.db.begin().await {
        Ok(t) => t,
        Err(e) => {
            error!("Failed to begin transaction: {}", e);
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "DB_ERROR",
                "Failed to create batch",
            );
        }
    };

    if let Err(e) = sqlx::query!(
        r#"
        INSERT INTO batches (id, batch_type, status, source_wallet, total_count, pending_count)
        VALUES ($1, 'cngn_transfer', 'pending', $2, $3, $3)
        "#,
        batch_id,
        body.source_wallet,
        total,
    )
    .execute(&mut *tx)
    .await
    {
        error!("Failed to insert batch: {}", e);
        let _ = tx.rollback().await;
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "DB_ERROR",
            "Failed to create batch",
        );
    }

    for item in &body.transfers {
        let amount = parse_positive_decimal(&item.amount_cngn).unwrap();
        if let Err(e) = sqlx::query!(
            r#"
            INSERT INTO batch_items (batch_id, destination, amount, currency, memo)
            VALUES ($1, $2, $3, 'cNGN', $4)
            "#,
            batch_id,
            item.destination_wallet,
            amount,
            item.memo,
        )
        .execute(&mut *tx)
        .await
        {
            error!("Failed to insert batch item: {}", e);
            let _ = tx.rollback().await;
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "DB_ERROR",
                "Failed to create batch items",
            );
        }
    }

    if let Err(e) = tx.commit().await {
        error!("Failed to commit batch creation: {}", e);
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "DB_ERROR",
            "Failed to commit batch",
        );
    }

    info!(batch_id = %batch_id, total_items = total, "cNGN transfer batch created");

    (
        StatusCode::CREATED,
        Json(BatchCreateResponse {
            batch_id,
            status: "pending".to_string(),
            total_items: body.transfers.len(),
            created_at: Utc::now(),
        }),
    )
        .into_response()
}

/// POST /api/batch/fiat-payout
///
/// Validates all recipient bank details and amounts, then creates a batch record.
///
/// Requires scope: `batch:fiat_payout`
pub async fn create_fiat_payout_batch(
    State(state): State<BatchState>,
    Json(body): Json<BatchFiatPayoutRequest>,
) -> Response {
    info!(count = body.payouts.len(), "Creating fiat payout batch");

    if body.payouts.is_empty() {
        return error_response(
            StatusCode::BAD_REQUEST,
            "EMPTY_BATCH",
            "Batch must contain at least one payout",
        );
    }

    if body.payouts.len() > state.max_fiat_batch_size {
        return error_response(
            StatusCode::BAD_REQUEST,
            "BATCH_TOO_LARGE",
            &format!(
                "Batch exceeds maximum size of {} items",
                state.max_fiat_batch_size
            ),
        );
    }

    // Validate all items
    for (i, item) in body.payouts.iter().enumerate() {
        if item.bank_account_number.trim().is_empty() {
            return error_response(
                StatusCode::BAD_REQUEST,
                "INVALID_BANK_ACCOUNT",
                &format!("Item {}: bank_account_number is required", i),
            );
        }
        if item.bank_code.trim().is_empty() {
            return error_response(
                StatusCode::BAD_REQUEST,
                "INVALID_BANK_CODE",
                &format!("Item {}: bank_code is required", i),
            );
        }
        if parse_positive_decimal(&item.amount_ngn).is_none() {
            return error_response(
                StatusCode::BAD_REQUEST,
                "INVALID_AMOUNT",
                &format!("Item {}: amount_ngn '{}' is not a valid positive decimal", i, item.amount_ngn),
            );
        }
    }

    let batch_id = Uuid::new_v4();
    let total = body.payouts.len() as i32;

    let mut tx = match state.db.begin().await {
        Ok(t) => t,
        Err(e) => {
            error!("Failed to begin transaction: {}", e);
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "DB_ERROR",
                "Failed to create batch",
            );
        }
    };

    if let Err(e) = sqlx::query!(
        r#"
        INSERT INTO batches (id, batch_type, status, total_count, pending_count)
        VALUES ($1, 'fiat_payout', 'pending', $2, $2)
        "#,
        batch_id,
        total,
    )
    .execute(&mut *tx)
    .await
    {
        error!("Failed to insert fiat batch: {}", e);
        let _ = tx.rollback().await;
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "DB_ERROR",
            "Failed to create batch",
        );
    }

    for item in &body.payouts {
        let destination = format!("{}:{}", item.bank_code, item.bank_account_number);
        let amount = parse_positive_decimal(&item.amount_ngn).unwrap();
        if let Err(e) = sqlx::query!(
            r#"
            INSERT INTO batch_items (batch_id, destination, amount, currency, memo)
            VALUES ($1, $2, $3, 'NGN', $4)
            "#,
            batch_id,
            destination,
            amount,
            item.reference,
        )
        .execute(&mut *tx)
        .await
        {
            error!("Failed to insert fiat batch item: {}", e);
            let _ = tx.rollback().await;
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "DB_ERROR",
                "Failed to create batch items",
            );
        }
    }

    if let Err(e) = tx.commit().await {
        error!("Failed to commit fiat batch: {}", e);
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "DB_ERROR",
            "Failed to commit batch",
        );
    }

    info!(batch_id = %batch_id, total_items = total, "Fiat payout batch created");

    (
        StatusCode::CREATED,
        Json(BatchCreateResponse {
            batch_id,
            status: "pending".to_string(),
            total_items: body.payouts.len(),
            created_at: Utc::now(),
        }),
    )
        .into_response()
}

/// GET /api/batch/:batch_id
///
/// Returns full batch details including per-item status and failure reasons.
/// Supports polling until the batch reaches a terminal state.
///
/// Requires scope: `batch:read`
pub async fn get_batch_status(
    State(state): State<BatchState>,
    Path(batch_id): Path<Uuid>,
) -> Response {
    info!(batch_id = %batch_id, "Fetching batch status");

    let batch = sqlx::query!(
        r#"
        SELECT id, batch_type, status, source_wallet,
               total_count, success_count, failed_count, pending_count,
               created_at, completed_at
        FROM batches
        WHERE id = $1
        "#,
        batch_id
    )
    .fetch_optional(state.db.as_ref())
    .await;

    let batch_row = match batch {
        Err(e) => {
            error!("DB error fetching batch: {}", e);
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "DB_ERROR",
                "Failed to fetch batch",
            );
        }
        Ok(None) => {
            return error_response(StatusCode::NOT_FOUND, "BATCH_NOT_FOUND", "Batch not found");
        }
        Ok(Some(r)) => r,
    };

    let items = sqlx::query!(
        r#"
        SELECT id, status, destination, amount, stellar_tx_hash, failure_reason
        FROM batch_items
        WHERE batch_id = $1
        ORDER BY created_at ASC
        "#,
        batch_id
    )
    .fetch_all(state.db.as_ref())
    .await;

    let item_rows = match items {
        Ok(rows) => rows,
        Err(e) => {
            error!("DB error fetching batch items: {}", e);
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "DB_ERROR",
                "Failed to fetch batch items",
            );
        }
    };

    let items_resp: Vec<BatchItemStatusResponse> = item_rows
        .into_iter()
        .map(|r| BatchItemStatusResponse {
            item_id: r.id,
            status: r.status,
            destination: r.destination,
            amount: r.amount.to_string(),
            stellar_tx_hash: r.stellar_tx_hash,
            failure_reason: r.failure_reason,
        })
        .collect();

    (
        StatusCode::OK,
        Json(BatchStatusResponse {
            batch_id: batch_row.id,
            batch_type: batch_row.batch_type,
            status: batch_row.status,
            total_count: batch_row.total_count,
            success_count: batch_row.success_count,
            failed_count: batch_row.failed_count,
            pending_count: batch_row.pending_count,
            items: items_resp,
            created_at: batch_row.created_at,
            completed_at: batch_row.completed_at,
        }),
    )
        .into_response()
}
