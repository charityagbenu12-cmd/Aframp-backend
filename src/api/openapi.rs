//! OpenAPI / Swagger documentation.
//!
//! Routes:
//!   GET /docs              — Swagger UI (non-production only)
//!   GET /docs/openapi.json — Raw OpenAPI 3.0 JSON (all environments)

use axum::{routing::get, Router};
use serde::{Deserialize, Serialize};
use utoipa::{
    openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme},
    Modify, OpenApi, ToSchema,
};
use utoipa_swagger_ui::SwaggerUi;

// ─── Security Modifier ───────────────────────────────────────────────────────

struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "bearerAuth",
                SecurityScheme::Http(
                    HttpBuilder::new()
                        .scheme(HttpAuthScheme::Bearer)
                        .bearer_format("JWT")
                        .build(),
                ),
            );
        }
    }
}

// ─── Shared Schemas ──────────────────────────────────────────────────────────

/// Standard error response returned by all API endpoints on failure.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ApiErrorResponse {
    pub error: ApiErrorDetail,
}

/// Detail block inside an API error response.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ApiErrorDetail {
    /// Machine-readable error code e.g. "TRUSTLINE_REQUIRED"
    pub code: String,
    /// Human-readable error description
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

/// Transaction status used across onramp, offramp, and bill payment flows.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum TransactionStatus {
    Pending,
    Processing,
    Completed,
    Failed,
    Refunded,
}

/// Supported blockchain chains.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum Chain {
    Stellar,
}

/// Pagination query parameters.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct PaginationQuery {
    #[serde(default = "default_page")]
    pub page: u32,
    #[serde(default = "default_limit")]
    pub limit: u32,
}

fn default_page() -> u32 {
    1
}
fn default_limit() -> u32 {
    20
}

// ─── Onramp Schemas ──────────────────────────────────────────────────────────

/// Request body for POST /api/onramp/quote
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct OnrampQuoteRequest {
    pub amount_ngn: String,
    pub wallet_address: String,
    pub provider: String,
    pub chain: Chain,
}

/// Fee breakdown inside a quote response.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct QuoteFeeSummary {
    pub platform_fee_ngn: String,
    pub provider_fee_ngn: String,
    pub total_fee_ngn: String,
    pub platform_fee_pct: String,
    pub provider_fee_pct: String,
}

/// Response for POST /api/onramp/quote
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct OnrampQuoteResponse {
    pub quote_id: String,
    pub expires_at: String,
    pub expires_in_seconds: i64,
    pub amount_ngn: String,
    pub amount_cngn: String,
    pub fees: QuoteFeeSummary,
    pub trustline_required: bool,
    pub liquidity_available: bool,
}

/// Request body for POST /api/onramp/initiate
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct OnrampInitiateRequest {
    pub quote_id: String,
    pub wallet_address: String,
}

/// Response for POST /api/onramp/initiate
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct OnrampInitiateResponse {
    pub transaction_id: String,
    pub status: TransactionStatus,
    pub payment_reference: String,
    pub amount_ngn: String,
}

/// Response for GET /api/onramp/status/:tx_id
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct OnrampStatusResponse {
    pub transaction_id: String,
    pub status: TransactionStatus,
    pub amount_ngn: String,
    pub amount_cngn: String,
    pub wallet_address: String,
    pub stellar_tx_hash: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

// ─── Offramp Schemas ─────────────────────────────────────────────────────────

/// Request body for POST /api/offramp/quote
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct OfframpQuoteRequest {
    pub amount_cngn: String,
    pub wallet_address: String,
    pub provider: String,
}

/// Response for POST /api/offramp/quote
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct OfframpQuoteResponse {
    pub quote_id: String,
    pub expires_at: String,
    pub expires_in_seconds: i64,
    pub amount_cngn: String,
    pub fees: QuoteFeeSummary,
    pub amount_ngn_after_fees: String,
    pub collection_address: String,
}

/// Request body for POST /api/offramp/initiate
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct OfframpInitiateRequest {
    pub quote_id: String,
    pub wallet_address: String,
    pub bank_account_number: Option<String>,
    pub bank_code: Option<String>,
}

/// Response for POST /api/offramp/initiate
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct OfframpInitiateResponse {
    pub transaction_id: String,
    pub status: TransactionStatus,
    pub collection_address: String,
    pub amount_cngn: String,
    pub memo: String,
}

/// Response for GET /api/offramp/status/:tx_id
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct OfframpStatusResponse {
    pub transaction_id: String,
    pub status: TransactionStatus,
    pub amount_cngn: String,
    pub amount_ngn: String,
    pub stellar_tx_hash: Option<String>,
    pub payout_reference: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

// ─── Bills Schemas ───────────────────────────────────────────────────────────

/// A single bill payment provider.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct BillProvider {
    pub id: String,
    pub name: String,
    pub category: String,
    pub status: String,
}

/// Response for GET /api/bills/providers
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct BillProvidersResponse {
    pub providers: Vec<BillProvider>,
    pub total: u32,
}

/// Request body for POST /api/bills/pay
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct BillPayRequest {
    pub provider_id: String,
    pub customer_id: String,
    pub amount_ngn: String,
    pub wallet_address: String,
}

/// Response for POST /api/bills/pay
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct BillPayResponse {
    pub transaction_id: String,
    pub status: TransactionStatus,
    pub reference: String,
    pub amount_ngn: String,
    pub amount_cngn: String,
}

// ─── Rates Schemas ───────────────────────────────────────────────────────────

/// A single exchange rate entry.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct RateEntry {
    pub pair: String,
    pub base_currency: String,
    pub quote_currency: String,
    pub rate: String,
    pub inverse_rate: String,
    pub last_updated: String,
    pub source: String,
}

// ─── Fees Schemas ────────────────────────────────────────────────────────────

/// Fee detail for a single flow direction.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct FeeDetail {
    pub platform_fee_pct: String,
    pub provider_fee_pct: String,
    pub minimum_fee_ngn: String,
}

/// Response for GET /api/fees
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct FeeStructureResponse {
    pub onramp: FeeDetail,
    pub offramp: FeeDetail,
}

// ─── Wallet Schemas ──────────────────────────────────────────────────────────

/// Response for GET /api/wallet/balance
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct WalletBalanceResponse {
    pub wallet_address: String,
    pub xlm_balance: String,
    pub cngn_balance: String,
    pub has_cngn_trustline: bool,
    pub last_updated: String,
}

// ─── Batch Schemas ───────────────────────────────────────────────────────────

/// A single transfer item within a batch cNGN transfer request.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct CngnTransferItem {
    pub destination_wallet: String,
    pub amount_cngn: String,
    pub memo: Option<String>,
}

/// Request body for POST /api/batch/cngn-transfer
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct BatchCngnTransferRequest {
    pub source_wallet: String,
    pub transfers: Vec<CngnTransferItem>,
}

/// A single fiat payout item within a batch fiat payout request.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct FiatPayoutItem {
    pub bank_account_number: String,
    pub bank_code: String,
    pub amount_ngn: String,
    pub reference: Option<String>,
}

/// Request body for POST /api/batch/fiat-payout
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct BatchFiatPayoutRequest {
    pub payouts: Vec<FiatPayoutItem>,
}

/// Response for POST /api/batch/cngn-transfer and POST /api/batch/fiat-payout
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct BatchCreateResponse {
    pub batch_id: String,
    pub status: String,
    pub total_items: u32,
    pub created_at: String,
}

/// Status of an individual item within a batch.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct BatchItemStatus {
    pub item_id: String,
    pub status: String,
    pub destination: String,
    pub amount: String,
    pub stellar_tx_hash: Option<String>,
    pub failure_reason: Option<String>,
}

/// Response for GET /api/batch/:batch_id
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct BatchStatusResponse {
    pub batch_id: String,
    pub batch_type: String,
    pub status: String,
    pub total_count: u32,
    pub success_count: u32,
    pub failed_count: u32,
    pub pending_count: u32,
    pub items: Vec<BatchItemStatus>,
    pub created_at: String,
    pub completed_at: Option<String>,
}

// ─── Admin / Scopes Schemas ──────────────────────────────────────────────────

/// A platform scope definition.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ScopeDefinition {
    pub name: String,
    pub description: String,
    pub category: String,
    pub applicable_consumer_types: Vec<String>,
}

/// Response for GET /api/admin/scopes
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ScopesListResponse {
    pub scopes: Vec<ScopeDefinition>,
    pub total: u32,
}

/// Scopes currently assigned to an API key.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct KeyScopesResponse {
    pub key_id: String,
    pub consumer_id: String,
    pub consumer_type: String,
    pub scopes: Vec<String>,
}

/// Request body for PATCH /api/admin/consumers/:consumer_id/keys/:key_id/scopes
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct UpdateScopesRequest {
    /// Complete scope list to assign — replaces all existing scopes for this key.
    pub scopes: Vec<String>,
}

// ─── OpenAPI Document ────────────────────────────────────────────────────────

/// Root OpenAPI document generated from all annotated schemas and paths.
#[derive(OpenApi)]
#[openapi(
    info(
        title = "Aframp API",
        version = "0.1.0",
        description = "
# Aframp API

Platform API for NGN ↔ cNGN onramp/offramp, bill payments, exchange rates, and wallet management.

## Authentication

All authenticated endpoints require a JWT bearer token:

```
Authorization: Bearer <your_jwt_token>
```

## Quick Start

1. Request a quote: `POST /api/onramp/quote`
2. Initiate the transaction: `POST /api/onramp/initiate`
3. Poll status: `GET /api/onramp/status/:tx_id`

Your Stellar wallet must have an active cNGN trustline before receiving cNGN.
See the cNGN Integration Guide in `/docs/cngn/` for setup instructions.
",
        contact(name = "Aframp Engineering"),
        license(name = "Proprietary")
    ),
    components(schemas(
        ApiErrorResponse,
        ApiErrorDetail,
        TransactionStatus,
        Chain,
        PaginationQuery,
        QuoteFeeSummary,
        OnrampQuoteRequest,
        OnrampQuoteResponse,
        OnrampInitiateRequest,
        OnrampInitiateResponse,
        OnrampStatusResponse,
        OfframpQuoteRequest,
        OfframpQuoteResponse,
        OfframpInitiateRequest,
        OfframpInitiateResponse,
        OfframpStatusResponse,
        BillProvider,
        BillProvidersResponse,
        BillPayRequest,
        BillPayResponse,
        RateEntry,
        FeeDetail,
        FeeStructureResponse,
        WalletBalanceResponse,
        CngnTransferItem,
        BatchCngnTransferRequest,
        FiatPayoutItem,
        BatchFiatPayoutRequest,
        BatchCreateResponse,
        BatchItemStatus,
        BatchStatusResponse,
        ScopeDefinition,
        ScopesListResponse,
        KeyScopesResponse,
        UpdateScopesRequest,
    )),
    tags(
        (name = "onramp", description = "NGN to cNGN conversion (fiat to crypto)"),
        (name = "offramp", description = "cNGN to NGN conversion (crypto to fiat)"),
        (name = "bills", description = "Bill payment services"),
        (name = "rates", description = "Exchange rates and fees"),
        (name = "wallet", description = "Wallet balance and trustline management"),
        (name = "batch", description = "Batch transaction processing"),
        (name = "admin", description = "Administrative endpoints — require admin authentication"),
    ),
    modifiers(&SecurityAddon),
    servers(
        (url = "/", description = "Current environment"),
        (url = "http://localhost:8000", description = "Local development"),
    )
)]
pub struct ApiDoc;

// ─── Route Builder ───────────────────────────────────────────────────────────

/// Build the Axum router for OpenAPI documentation endpoints.
///
/// - `GET /docs/openapi.json` is always mounted.
/// - `GET /docs` (Swagger UI) is only mounted in non-production environments.
pub fn openapi_routes() -> Router {
    let environment = std::env::var("ENVIRONMENT").unwrap_or_else(|_| "development".to_string());
    let serve_ui = environment != "production";

    let openapi = ApiDoc::openapi();

    if serve_ui {
        Router::new().merge(SwaggerUi::new("/docs").url("/docs/openapi.json", openapi))
    } else {
        // In production only serve the raw JSON at /docs/openapi.json
        let spec_json = openapi
            .to_json()
            .unwrap_or_else(|_| "{}".to_string());
        Router::new().route(
            "/docs/openapi.json",
            get(move || {
                let json = spec_json.clone();
                async move {
                    (
                        axum::http::StatusCode::OK,
                        [("content-type", "application/json")],
                        json,
                    )
                }
            }),
        )
    }
}
