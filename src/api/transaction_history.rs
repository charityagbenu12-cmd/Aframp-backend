//! Transaction history endpoint
//!
//! GET  /api/transactions         — paginated history with filtering & sorting
//! GET  /api/transactions/export  — CSV export of filtered history

use axum::{
    extract::{Query, State},
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{types::BigDecimal, FromRow, PgPool};
use std::sync::Arc;
use tracing::{debug, error};
use uuid::Uuid;

use crate::cache::cache::{Cache as CacheTrait, RedisCache};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const DEFAULT_PAGE_SIZE: i64 = 20;
const MAX_PAGE_SIZE: i64 = 100;
const MAX_DATE_RANGE_DAYS: i64 = 365;
const MAX_EXPORT_ROWS: i64 = 10_000;
const HISTORY_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(30);

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct TransactionHistoryState {
    pub pool: Arc<PgPool>,
    pub cache: Option<Arc<RedisCache>>,
}

// ---------------------------------------------------------------------------
// Cursor — encodes (created_at, transaction_id, from_amount) for all sort modes
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
struct CursorPayload {
    pub created_at: DateTime<Utc>,
    pub id: Uuid,
    /// Serialised BigDecimal string — used for amount-sort cursors
    pub amount: String,
}

fn encode_cursor(created_at: DateTime<Utc>, id: Uuid, amount: &BigDecimal) -> String {
    let payload = CursorPayload {
        created_at,
        id,
        amount: amount.to_string(),
    };
    let json = serde_json::to_vec(&payload).unwrap_or_default();
    URL_SAFE_NO_PAD.encode(&json)
}

fn decode_cursor(cursor: &str) -> Option<CursorPayload> {
    let bytes = URL_SAFE_NO_PAD.decode(cursor).ok()?;
    serde_json::from_slice(&bytes).ok()
}

// ---------------------------------------------------------------------------
// Query params
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct HistoryQuery {
    pub wallet_address: String,
    pub cursor: Option<String>,
    pub limit: Option<i64>,
    /// onramp | offramp | bill_payment
    pub tx_type: Option<String>,
    /// pending | processing | completed | failed | refunded
    pub status: Option<String>,
    pub date_from: Option<DateTime<Utc>>,
    pub date_to: Option<DateTime<Utc>>,
    pub from_currency: Option<String>,
    pub to_currency: Option<String>,
    /// created_asc | created_desc | amount_asc | amount_desc  (default: created_desc)
    pub sort: Option<String>,
}

// ---------------------------------------------------------------------------
// DB row
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, FromRow)]
struct TxRow {
    pub transaction_id: Uuid,
    pub wallet_address: String,
    pub r#type: String,
    pub from_currency: String,
    pub to_currency: String,
    pub from_amount: BigDecimal,
    pub to_amount: BigDecimal,
    pub cngn_amount: BigDecimal,
    pub status: String,
    pub payment_provider: Option<String>,
    pub payment_reference: Option<String>,
    pub blockchain_tx_hash: Option<String>,
    pub error_message: Option<String>,
    pub metadata: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Clone)]
pub struct TransactionRecord {
    pub id: String,
    pub wallet_address: String,
    pub tx_type: String,
    pub from_currency: String,
    pub to_currency: String,
    pub from_amount: String,
    pub to_amount: String,
    pub cngn_amount: String,
    pub status: String,
    pub payment_provider: Option<String>,
    pub payment_reference: Option<String>,
    pub blockchain_tx_hash: Option<String>,
    pub error_message: Option<String>,
    pub metadata: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Clone)]
pub struct HistoryResponse {
    pub data: Vec<TransactionRecord>,
    pub total: i64,
    pub next_cursor: Option<String>,
    /// True when the export was capped at MAX_EXPORT_ROWS
    pub truncated: bool,
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    pub code: String,
    pub message: String,
}

fn err_resp(status: StatusCode, code: &str, msg: impl Into<String>) -> Response {
    (status, Json(ErrorBody { code: code.to_string(), message: msg.into() })).into_response()
}

fn map_row(r: TxRow) -> TransactionRecord {
    TransactionRecord {
        id: r.transaction_id.to_string(),
        wallet_address: r.wallet_address,
        tx_type: r.r#type,
        from_currency: r.from_currency,
        to_currency: r.to_currency,
        from_amount: r.from_amount.to_string(),
        to_amount: r.to_amount.to_string(),
        cngn_amount: r.cngn_amount.to_string(),
        status: r.status,
        payment_provider: r.payment_provider,
        payment_reference: r.payment_reference,
        blockchain_tx_hash: r.blockchain_tx_hash,
        error_message: r.error_message,
        metadata: r.metadata,
        created_at: r.created_at,
        updated_at: r.updated_at,
    }
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

fn validate_query(q: &HistoryQuery) -> Result<i64, Response> {
    let limit = q.limit.unwrap_or(DEFAULT_PAGE_SIZE).clamp(1, MAX_PAGE_SIZE);

    if let Some(ref t) = q.tx_type {
        if !["onramp", "offramp", "bill_payment"].contains(&t.as_str()) {
            return Err(err_resp(StatusCode::BAD_REQUEST, "INVALID_TYPE",
                "tx_type must be onramp, offramp, or bill_payment"));
        }
    }
    if let Some(ref s) = q.status {
        if !["pending", "processing", "completed", "failed", "refunded"].contains(&s.as_str()) {
            return Err(err_resp(StatusCode::BAD_REQUEST, "INVALID_STATUS",
                "status must be pending, processing, completed, failed, or refunded"));
        }
    }
    if let (Some(from), Some(to)) = (q.date_from, q.date_to) {
        if from > to {
            return Err(err_resp(StatusCode::BAD_REQUEST, "INVALID_DATE_RANGE",
                "date_from must be before date_to"));
        }
        if (to - from) > Duration::days(MAX_DATE_RANGE_DAYS) {
            return Err(err_resp(StatusCode::BAD_REQUEST, "DATE_RANGE_TOO_LARGE",
                format!("date range cannot exceed {} days", MAX_DATE_RANGE_DAYS)));
        }
    }
    if let Some(ref sort) = q.sort {
        if !["created_asc", "created_desc", "amount_asc", "amount_desc"].contains(&sort.as_str()) {
            return Err(err_resp(StatusCode::BAD_REQUEST, "INVALID_SORT",
                "sort must be created_asc, created_desc, amount_asc, or amount_desc"));
        }
    }
    Ok(limit)
}

// ---------------------------------------------------------------------------
// Sort mode — drives both ORDER BY and cursor comparison
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq)]
enum SortMode { CreatedDesc, CreatedAsc, AmountDesc, AmountAsc }

impl SortMode {
    fn from_str(s: &str) -> Self {
        match s {
            "created_asc"  => Self::CreatedAsc,
            "amount_desc"  => Self::AmountDesc,
            "amount_asc"   => Self::AmountAsc,
            _              => Self::CreatedDesc,
        }
    }
}

// ---------------------------------------------------------------------------
// DB query — fully parameterised, no string interpolation of user data
// ---------------------------------------------------------------------------

async fn fetch_history(
    pool: &PgPool,
    q: &HistoryQuery,
    limit: i64,
    for_export: bool,
) -> Result<(Vec<TxRow>, i64), sqlx::Error> {
    let sort = SortMode::from_str(q.sort.as_deref().unwrap_or("created_desc"));
    let effective_limit = if for_export { MAX_EXPORT_ROWS + 1 } else { limit + 1 };
    let cursor = q.cursor.as_deref().and_then(decode_cursor);

    // Cursor boundary values — passed as bound parameters, never interpolated
    let cursor_created_at: Option<DateTime<Utc>> = cursor.as_ref().map(|c| c.created_at);
    let cursor_id: Option<Uuid>                  = cursor.as_ref().map(|c| c.id);
    let cursor_amount: Option<BigDecimal>        = cursor.as_ref()
        .and_then(|c| c.amount.parse::<BigDecimal>().ok());

    // We use a single parameterised query with conditional cursor logic expressed
    // entirely through bound parameters — no raw user data in the SQL string.
    //
    // Cursor semantics (keyset pagination):
    //   created_desc: (created_at, id) < (cursor_created_at, cursor_id)
    //   created_asc:  (created_at, id) > (cursor_created_at, cursor_id)
    //   amount_desc:  (from_amount, id) < (cursor_amount, cursor_id)  [tie-break by id]
    //   amount_asc:   (from_amount, id) > (cursor_amount, cursor_id)
    //
    // PostgreSQL row-value comparisons handle the composite keyset correctly.

    let rows = match sort {
        SortMode::CreatedDesc => sqlx::query_as::<_, TxRow>(
            r#"
            SELECT transaction_id, wallet_address, type, from_currency, to_currency,
                   from_amount, to_amount, cngn_amount, status, payment_provider,
                   payment_reference, blockchain_tx_hash, error_message, metadata,
                   created_at, updated_at
            FROM transactions
            WHERE wallet_address = $1
              AND ($2::text        IS NULL OR type          = $2)
              AND ($3::text        IS NULL OR status        = $3)
              AND ($4::timestamptz IS NULL OR created_at   >= $4)
              AND ($5::timestamptz IS NULL OR created_at   <= $5)
              AND ($6::text        IS NULL OR from_currency = $6)
              AND ($7::text        IS NULL OR to_currency   = $7)
              AND ($8::timestamptz IS NULL OR (created_at, transaction_id) < ($8, $9))
            ORDER BY created_at DESC, transaction_id DESC
            LIMIT $10
            "#)
            .bind(&q.wallet_address)
            .bind(q.tx_type.as_deref())
            .bind(q.status.as_deref())
            .bind(q.date_from)
            .bind(q.date_to)
            .bind(q.from_currency.as_deref())
            .bind(q.to_currency.as_deref())
            .bind(cursor_created_at)
            .bind(cursor_id)
            .bind(effective_limit)
            .fetch_all(pool).await?,

        SortMode::CreatedAsc => sqlx::query_as::<_, TxRow>(
            r#"
            SELECT transaction_id, wallet_address, type, from_currency, to_currency,
                   from_amount, to_amount, cngn_amount, status, payment_provider,
                   payment_reference, blockchain_tx_hash, error_message, metadata,
                   created_at, updated_at
            FROM transactions
            WHERE wallet_address = $1
              AND ($2::text        IS NULL OR type          = $2)
              AND ($3::text        IS NULL OR status        = $3)
              AND ($4::timestamptz IS NULL OR created_at   >= $4)
              AND ($5::timestamptz IS NULL OR created_at   <= $5)
              AND ($6::text        IS NULL OR from_currency = $6)
              AND ($7::text        IS NULL OR to_currency   = $7)
              AND ($8::timestamptz IS NULL OR (created_at, transaction_id) > ($8, $9))
            ORDER BY created_at ASC, transaction_id ASC
            LIMIT $10
            "#)
            .bind(&q.wallet_address)
            .bind(q.tx_type.as_deref())
            .bind(q.status.as_deref())
            .bind(q.date_from)
            .bind(q.date_to)
            .bind(q.from_currency.as_deref())
            .bind(q.to_currency.as_deref())
            .bind(cursor_created_at)
            .bind(cursor_id)
            .bind(effective_limit)
            .fetch_all(pool).await?,

        SortMode::AmountDesc => sqlx::query_as::<_, TxRow>(
            r#"
            SELECT transaction_id, wallet_address, type, from_currency, to_currency,
                   from_amount, to_amount, cngn_amount, status, payment_provider,
                   payment_reference, blockchain_tx_hash, error_message, metadata,
                   created_at, updated_at
            FROM transactions
            WHERE wallet_address = $1
              AND ($2::text    IS NULL OR type          = $2)
              AND ($3::text    IS NULL OR status        = $3)
              AND ($4::timestamptz IS NULL OR created_at >= $4)
              AND ($5::timestamptz IS NULL OR created_at <= $5)
              AND ($6::text    IS NULL OR from_currency = $6)
              AND ($7::text    IS NULL OR to_currency   = $7)
              AND ($8::numeric IS NULL OR (from_amount, transaction_id) < ($8, $9))
            ORDER BY from_amount DESC, transaction_id DESC
            LIMIT $10
            "#)
            .bind(&q.wallet_address)
            .bind(q.tx_type.as_deref())
            .bind(q.status.as_deref())
            .bind(q.date_from)
            .bind(q.date_to)
            .bind(q.from_currency.as_deref())
            .bind(q.to_currency.as_deref())
            .bind(cursor_amount)
            .bind(cursor_id)
            .bind(effective_limit)
            .fetch_all(pool).await?,

        SortMode::AmountAsc => sqlx::query_as::<_, TxRow>(
            r#"
            SELECT transaction_id, wallet_address, type, from_currency, to_currency,
                   from_amount, to_amount, cngn_amount, status, payment_provider,
                   payment_reference, blockchain_tx_hash, error_message, metadata,
                   created_at, updated_at
            FROM transactions
            WHERE wallet_address = $1
              AND ($2::text    IS NULL OR type          = $2)
              AND ($3::text    IS NULL OR status        = $3)
              AND ($4::timestamptz IS NULL OR created_at >= $4)
              AND ($5::timestamptz IS NULL OR created_at <= $5)
              AND ($6::text    IS NULL OR from_currency = $6)
              AND ($7::text    IS NULL OR to_currency   = $7)
              AND ($8::numeric IS NULL OR (from_amount, transaction_id) > ($8, $9))
            ORDER BY from_amount ASC, transaction_id ASC
            LIMIT $10
            "#)
            .bind(&q.wallet_address)
            .bind(q.tx_type.as_deref())
            .bind(q.status.as_deref())
            .bind(q.date_from)
            .bind(q.date_to)
            .bind(q.from_currency.as_deref())
            .bind(q.to_currency.as_deref())
            .bind(cursor_amount)
            .bind(cursor_id)
            .bind(effective_limit)
            .fetch_all(pool).await?,
    };

    // Count — same filters, no cursor, no limit
    let total: i64 = sqlx::query_scalar(
        r#"
        SELECT COUNT(*) FROM transactions
        WHERE wallet_address = $1
          AND ($2::text        IS NULL OR type          = $2)
          AND ($3::text        IS NULL OR status        = $3)
          AND ($4::timestamptz IS NULL OR created_at   >= $4)
          AND ($5::timestamptz IS NULL OR created_at   <= $5)
          AND ($6::text        IS NULL OR from_currency = $6)
          AND ($7::text        IS NULL OR to_currency   = $7)
        "#)
        .bind(&q.wallet_address)
        .bind(q.tx_type.as_deref())
        .bind(q.status.as_deref())
        .bind(q.date_from)
        .bind(q.date_to)
        .bind(q.from_currency.as_deref())
        .bind(q.to_currency.as_deref())
        .fetch_one(pool).await?;

    Ok((rows, total))
}

// ---------------------------------------------------------------------------
// Cache key — includes all filter dimensions
// ---------------------------------------------------------------------------

fn history_cache_key(q: &HistoryQuery, limit: i64) -> String {
    format!(
        "v1:tx:history:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}",
        q.wallet_address,
        q.cursor.as_deref().unwrap_or(""),
        limit,
        q.tx_type.as_deref().unwrap_or(""),
        q.status.as_deref().unwrap_or(""),
        q.date_from.map(|d| d.timestamp()).unwrap_or(0),
        q.date_to.map(|d| d.timestamp()).unwrap_or(0),
        q.from_currency.as_deref().unwrap_or(""),
        q.to_currency.as_deref().unwrap_or(""),   // was missing before
        q.sort.as_deref().unwrap_or("created_desc"),
    )
}

// ---------------------------------------------------------------------------
// GET /api/transactions
// ---------------------------------------------------------------------------

pub async fn get_transaction_history(
    State(state): State<Arc<TransactionHistoryState>>,
    Query(q): Query<HistoryQuery>,
) -> Response {
    if q.wallet_address.is_empty() {
        return err_resp(StatusCode::BAD_REQUEST, "MISSING_WALLET", "wallet_address is required");
    }
    let limit = match validate_query(&q) {
        Ok(l) => l,
        Err(e) => return e,
    };

    let cache_key = history_cache_key(&q, limit);
    if let Some(ref cache) = state.cache {
        match cache.get::<HistoryResponse>(&cache_key).await {
            Ok(Some(cached)) => {
                debug!(wallet = %q.wallet_address, "tx history cache hit");
                return Json(cached).into_response();
            }
            Ok(None) => {}
            Err(e) => debug!(error = %e, "cache get degraded"),
        }
    }

    let (mut rows, total) = match fetch_history(&state.pool, &q, limit, false).await {
        Ok(r) => r,
        Err(e) => {
            error!(error = %e, "fetch transaction history failed");
            return err_resp(StatusCode::INTERNAL_SERVER_ERROR, "DATABASE_ERROR", "failed to fetch history");
        }
    };

    let has_more = rows.len() as i64 > limit;
    if has_more { rows.truncate(limit as usize); }

    let next_cursor = if has_more {
        rows.last().map(|r| encode_cursor(r.created_at, r.transaction_id, &r.from_amount))
    } else {
        None
    };

    let response = HistoryResponse {
        total,
        next_cursor,
        truncated: false,
        data: rows.into_iter().map(map_row).collect(),
    };

    if let Some(ref cache) = state.cache {
        if let Err(e) = cache.set(&cache_key, &response, Some(HISTORY_CACHE_TTL)).await {
            debug!(error = %e, "cache set degraded");
        }
    }

    Json(response).into_response()
}

// ---------------------------------------------------------------------------
// GET /api/transactions/export
// ---------------------------------------------------------------------------

pub async fn export_transaction_history(
    State(state): State<Arc<TransactionHistoryState>>,
    Query(q): Query<HistoryQuery>,
) -> Response {
    if q.wallet_address.is_empty() {
        return err_resp(StatusCode::BAD_REQUEST, "MISSING_WALLET", "wallet_address is required");
    }
    // Export ignores cursor — always starts from the beginning of the filter set
    let export_q = HistoryQuery {
        wallet_address: q.wallet_address.clone(),
        cursor: None,
        limit: None,
        tx_type: q.tx_type.clone(),
        status: q.status.clone(),
        date_from: q.date_from,
        date_to: q.date_to,
        from_currency: q.from_currency.clone(),
        to_currency: q.to_currency.clone(),
        sort: q.sort.clone(),
    };
    if let Err(e) = validate_query(&export_q) { return e; }

    let (mut rows, _) = match fetch_history(&state.pool, &export_q, DEFAULT_PAGE_SIZE, true).await {
        Ok(r) => r,
        Err(e) => {
            error!(error = %e, "fetch transactions for export failed");
            return err_resp(StatusCode::INTERNAL_SERVER_ERROR, "DATABASE_ERROR", "failed to fetch transactions");
        }
    };

    let truncated = rows.len() as i64 > MAX_EXPORT_ROWS;
    if truncated { rows.truncate(MAX_EXPORT_ROWS as usize); }

    let mut wtr = csv::Writer::from_writer(vec![]);
    wtr.write_record(&[
        "id", "type", "status", "from_currency", "to_currency",
        "from_amount", "to_amount", "cngn_amount",
        "payment_provider", "payment_reference", "blockchain_tx_hash",
        "created_at", "updated_at",
    ]).ok();

    for row in &rows {
        wtr.write_record(&[
            row.transaction_id.to_string(),
            row.r#type.clone(),
            row.status.clone(),
            row.from_currency.clone(),
            row.to_currency.clone(),
            row.from_amount.to_string(),
            row.to_amount.to_string(),
            row.cngn_amount.to_string(),
            row.payment_provider.clone().unwrap_or_default(),
            row.payment_reference.clone().unwrap_or_default(),
            row.blockchain_tx_hash.clone().unwrap_or_default(),
            row.created_at.to_rfc3339(),
            row.updated_at.to_rfc3339(),
        ]).ok();
    }

    let csv_bytes = wtr.into_inner().unwrap_or_default();

    // Build disposition header — must be a valid HeaderValue
    let disposition = format!(
        "attachment; filename=\"transactions_{}{}.csv\"",
        q.wallet_address,
        if truncated { "_truncated" } else { "" },
    );
    let disposition_val = HeaderValue::from_str(&disposition)
        .unwrap_or_else(|_| HeaderValue::from_static("attachment; filename=\"transactions.csv\""));

    let mut resp = (StatusCode::OK, csv_bytes).into_response();
    resp.headers_mut().insert(header::CONTENT_TYPE,
        HeaderValue::from_static("text/csv; charset=utf-8"));
    resp.headers_mut().insert(header::CONTENT_DISPOSITION, disposition_val);
    if truncated {
        resp.headers_mut().insert(
            "x-export-truncated",
            HeaderValue::from_static("true"),
        );
        resp.headers_mut().insert(
            "x-export-max-rows",
            HeaderValue::from_str(&MAX_EXPORT_ROWS.to_string())
                .unwrap_or_else(|_| HeaderValue::from_static("10000")),
        );
    }
    resp
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn make_query(overrides: impl FnOnce(&mut HistoryQuery)) -> HistoryQuery {
        let mut q = HistoryQuery {
            wallet_address: "GTEST".to_string(),
            cursor: None, limit: None, tx_type: None, status: None,
            date_from: None, date_to: None,
            from_currency: None, to_currency: None, sort: None,
        };
        overrides(&mut q);
        q
    }

    // --- cursor ---

    #[test]
    fn test_cursor_roundtrip() {
        let ts = Utc.with_ymd_and_hms(2026, 1, 15, 12, 0, 0).unwrap();
        let id = Uuid::new_v4();
        let amount: BigDecimal = "123.456".parse().unwrap();
        let encoded = encode_cursor(ts, id, &amount);
        let decoded = decode_cursor(&encoded).unwrap();
        assert_eq!(decoded.created_at, ts);
        assert_eq!(decoded.id, id);
        assert_eq!(decoded.amount, "123.456");
    }

    #[test]
    fn test_cursor_invalid_base64() {
        assert!(decode_cursor("not!!valid").is_none());
    }

    #[test]
    fn test_cursor_invalid_json() {
        assert!(decode_cursor(&URL_SAFE_NO_PAD.encode(b"not json")).is_none());
    }

    // --- validate_query ---

    #[test]
    fn test_default_limit() {
        assert_eq!(validate_query(&make_query(|_| {})).unwrap(), DEFAULT_PAGE_SIZE);
    }

    #[test]
    fn test_limit_clamped_to_max() {
        assert_eq!(validate_query(&make_query(|q| q.limit = Some(9999))).unwrap(), MAX_PAGE_SIZE);
    }

    #[test]
    fn test_limit_clamped_to_min() {
        assert_eq!(validate_query(&make_query(|q| q.limit = Some(0))).unwrap(), 1);
    }

    #[test]
    fn test_invalid_tx_type() {
        assert!(validate_query(&make_query(|q| q.tx_type = Some("wire".to_string()))).is_err());
    }

    #[test]
    fn test_valid_tx_types() {
        for t in &["onramp", "offramp", "bill_payment"] {
            assert!(validate_query(&make_query(|q| q.tx_type = Some(t.to_string()))).is_ok());
        }
    }

    #[test]
    fn test_invalid_status() {
        assert!(validate_query(&make_query(|q| q.status = Some("unknown".to_string()))).is_err());
    }

    #[test]
    fn test_valid_statuses() {
        for s in &["pending", "processing", "completed", "failed", "refunded"] {
            assert!(validate_query(&make_query(|q| q.status = Some(s.to_string()))).is_ok());
        }
    }

    #[test]
    fn test_date_range_inverted() {
        let now = Utc::now();
        assert!(validate_query(&make_query(|q| {
            q.date_from = Some(now);
            q.date_to   = Some(now - Duration::days(1));
        })).is_err());
    }

    #[test]
    fn test_date_range_too_large() {
        let now = Utc::now();
        assert!(validate_query(&make_query(|q| {
            q.date_from = Some(now - Duration::days(400));
            q.date_to   = Some(now);
        })).is_err());
    }

    #[test]
    fn test_date_range_exactly_max_ok() {
        let now = Utc::now();
        assert!(validate_query(&make_query(|q| {
            q.date_from = Some(now - Duration::days(MAX_DATE_RANGE_DAYS));
            q.date_to   = Some(now);
        })).is_ok());
    }

    #[test]
    fn test_invalid_sort() {
        assert!(validate_query(&make_query(|q| q.sort = Some("random".to_string()))).is_err());
    }

    #[test]
    fn test_valid_sorts() {
        for s in &["created_asc", "created_desc", "amount_asc", "amount_desc"] {
            assert!(validate_query(&make_query(|q| q.sort = Some(s.to_string()))).is_ok());
        }
    }

    // --- cache key ---

    #[test]
    fn test_cache_key_stable() {
        let q = make_query(|q| {
            q.tx_type = Some("onramp".to_string());
            q.to_currency = Some("USD".to_string());
        });
        assert_eq!(history_cache_key(&q, 20), history_cache_key(&q, 20));
    }

    #[test]
    fn test_cache_key_differs_by_to_currency() {
        let q1 = make_query(|q| q.to_currency = Some("USD".to_string()));
        let q2 = make_query(|q| q.to_currency = Some("EUR".to_string()));
        assert_ne!(history_cache_key(&q1, 20), history_cache_key(&q2, 20));
    }

    #[test]
    fn test_cache_key_differs_by_sort() {
        let q1 = make_query(|q| q.sort = Some("created_asc".to_string()));
        let q2 = make_query(|q| q.sort = Some("amount_desc".to_string()));
        assert_ne!(history_cache_key(&q1, 20), history_cache_key(&q2, 20));
    }

    // --- sort mode ---

    #[test]
    fn test_sort_mode_defaults_to_created_desc() {
        assert_eq!(SortMode::from_str("anything"), SortMode::CreatedDesc);
        assert_eq!(SortMode::from_str("created_desc"), SortMode::CreatedDesc);
    }

    #[test]
    fn test_sort_mode_all_variants() {
        assert_eq!(SortMode::from_str("created_asc"),  SortMode::CreatedAsc);
        assert_eq!(SortMode::from_str("amount_desc"),  SortMode::AmountDesc);
        assert_eq!(SortMode::from_str("amount_asc"),   SortMode::AmountAsc);
    }
}
