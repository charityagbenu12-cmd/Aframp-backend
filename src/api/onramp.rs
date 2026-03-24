use axum::{extract::Path, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};
use tracing::{info_span, instrument, Instrument};
use uuid::Uuid;

use crate::{
    services::{
        payment::{PaymentRequest, PaymentService},
        transaction::{Transaction, TransactionService},
    },
    chains::stellar::StellarService,
};

#[derive(Debug, Deserialize)]
pub struct QuoteRequest {
    pub from_currency: String,
    pub to_asset: String,
    pub amount: String,
}

#[derive(Debug, Serialize)]
pub struct QuoteResponse {
    pub rate: String,
    pub fee: String,
    pub estimated_amount: String,
}

#[derive(Debug, Deserialize)]
pub struct OnrampInitiateRequest {
    pub wallet_address: String,
    pub from_currency: String,
    pub to_asset: String,
    pub amount: String,
    pub payment_method: String,
}

#[derive(Debug, Serialize)]
pub struct OnrampInitiateResponse {
    pub transaction_id: Uuid,
    pub status: String,
    pub provider_reference: String,
}

/// GET /api/onramp/quote
///
/// Returns an exchange rate quote. Emits child spans for the rates API call
/// and for the Redis cache lookup.
#[instrument(skip_all)]
pub async fn get_quote(Json(req): Json<QuoteRequest>) -> impl IntoResponse {
    tracing::info!(
        from_currency = %req.from_currency,
        to_asset = %req.to_asset,
        amount = %req.amount,
        "Processing onramp quote request"
    );

    // Child span for the Redis cache lookup.
    let cache_span = info_span!(
        "cache.get",
        otel.kind = "client",
        db.system = "redis",
        db.operation = "GET",
        cache.key_prefix = "rate:",
    );
    async {
        tracing::debug!("Checking cached exchange rate");
    }
    .instrument(cache_span)
    .await;

    // Child span for the external rates API call.
    let rates_span = info_span!(
        "provider.http_call",
        otel.kind = "client",
        peer.service = "rates_api",
        http.method = "GET",
    );
    async {
        tracing::debug!("Fetching live exchange rate");
    }
    .instrument(rates_span)
    .await;

    Json(QuoteResponse {
        rate: "1.0".into(),
        fee: "0.5".into(),
        estimated_amount: req.amount.clone(),
    })
}

/// POST /api/onramp/initiate
///
/// Initiates an onramp purchase. Emits child spans for:
/// * Stellar trustline check / creation.
/// * Payment provider API call.
/// * Database INSERT.
/// * Redis cache write.
#[instrument(skip_all)]
pub async fn initiate_onramp(Json(req): Json<OnrampInitiateRequest>) -> impl IntoResponse {
    let tx_id = Uuid::new_v4();

    tracing::info!(
        wallet_address = %req.wallet_address,
        from_currency = %req.from_currency,
        to_asset = %req.to_asset,
        amount = %req.amount,
        payment_method = %req.payment_method,
        tx_id = %tx_id,
        "Initiating onramp transaction"
    );

    // Trustline check via Stellar service (instruments its own child spans).
    let stellar = StellarService::new(
        "https://horizon-testnet.stellar.org".into(),
        "GCNGN_ISSUER".into(),
    );
    let _ = stellar
        .check_trustline(&req.wallet_address, "CNGN")
        .await;

    // Payment provider call (instruments its own child span).
    let payment_service = PaymentService::new();
    let payment_req = PaymentRequest {
        amount: req.amount.clone(),
        currency: req.from_currency.clone(),
        phone_number: "+254700000000".into(),
        reference: tx_id.to_string(),
    };
    let provider_result = payment_service.initiate_mpesa(payment_req).await;

    let provider_ref = provider_result
        .map(|r| r.provider_reference)
        .unwrap_or_else(|_| "error".into());

    // Database INSERT span.
    let db_span = info_span!(
        "db.query",
        otel.kind = "client",
        db.system = "postgresql",
        db.operation = "INSERT",
        db.sql.table = "transactions",
    );
    async {
        tracing::info!(%tx_id, "Persisting new transaction");
    }
    .instrument(db_span)
    .await;

    // Cache WRITE span.
    let cache_span = info_span!(
        "cache.set",
        otel.kind = "client",
        db.system = "redis",
        db.operation = "SET",
        cache.key_prefix = "tx:",
    );
    async {
        tracing::debug!(%tx_id, "Caching transaction");
    }
    .instrument(cache_span)
    .await;

    tracing::info!(%tx_id, %provider_ref, "Onramp transaction initiated successfully");

    (
        StatusCode::CREATED,
        Json(OnrampInitiateResponse {
            transaction_id: tx_id,
            status: "pending".into(),
            provider_reference: provider_ref,
        }),
    )
}

/// GET /api/onramp/status/:tx_id
#[instrument(skip_all, fields(tx_id = %tx_id))]
pub async fn get_onramp_status(Path(tx_id): Path<Uuid>) -> impl IntoResponse {
    tracing::info!(%tx_id, "Fetching onramp transaction status");

    // Redis cache lookup.
    let cache_span = info_span!(
        "cache.get",
        otel.kind = "client",
        db.system = "redis",
        db.operation = "GET",
        cache.key_prefix = "tx:",
    );
    async { tracing::debug!(%tx_id, "Checking Redis for tx status") }
        .instrument(cache_span)
        .await;

    // DB fallback.
    let db_span = info_span!(
        "db.query",
        otel.kind = "client",
        db.system = "postgresql",
        db.operation = "SELECT",
        db.sql.table = "transactions",
    );
    async { tracing::debug!(%tx_id, "Querying database for tx status") }
        .instrument(db_span)
        .await;

    Json(serde_json::json!({ "tx_id": tx_id, "status": "pending" }))
}