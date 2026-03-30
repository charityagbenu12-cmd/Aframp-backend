/// Public Transparency Portal — Issue #239
///
/// Provides unauthenticated, publicly-accessible endpoints that expose the
/// real-time health of cNGN reserves so that users, auditors, and regulators
/// can independently verify the collateralisation ratio.
///
/// Endpoints
/// ---------
/// GET /v1/transparency/supply   — current circulating supply + timestamp
/// GET /v1/transparency/reserves — verified fiat total from last reconciliation
/// GET /v1/transparency/documents — list of attestation report PDFs
///
/// All JSON responses carry an Ed25519 signature over the canonical payload so
/// consumers can verify data integrity without trusting the transport layer.
use axum::{
    extract::State,
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{error, info};

// ── State ────────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct TransparencyState {
    pub db: sqlx::PgPool,
    /// Ed25519 signing key bytes (32-byte seed).  Loaded from env at startup.
    pub signing_key: Arc<ed25519_dalek::SigningKey>,
}

// ── Response types ────────────────────────────────────────────────────────────

/// Collateralisation status badge.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BackingStatus {
    FullyBacked,
    OverBacked,
    UnderBacked,
    Unverified,
}

impl BackingStatus {
    fn from_ratio(ratio: f64) -> Self {
        if ratio >= 1.0 {
            if ratio > 1.0 {
                BackingStatus::OverBacked
            } else {
                BackingStatus::FullyBacked
            }
        } else {
            BackingStatus::UnderBacked
        }
    }
}

/// Signed wrapper — every public response is wrapped in this envelope so
/// downstream verifiers can check `signature` against `payload` using the
/// project's published Ed25519 public key.
#[derive(Debug, Serialize)]
pub struct SignedResponse<T: Serialize> {
    pub payload: T,
    /// Hex-encoded Ed25519 signature over the canonical JSON of `payload`.
    pub signature: String,
    /// Hex-encoded Ed25519 public key that produced `signature`.
    pub public_key: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SupplyResponse {
    pub circulating_supply: String,
    pub asset: String,
    pub network: String,
    pub stellar_explorer_url: String,
    pub last_verified: DateTime<Utc>,
    pub status: BackingStatus,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReserveBank {
    /// Anonymised label, e.g. "Partner Bank A"
    pub label: String,
    pub fiat_balance_ngn: String,
    pub currency: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReservesResponse {
    pub total_fiat_ngn: String,
    pub circulating_supply: String,
    pub collateralisation_ratio: String,
    pub status: BackingStatus,
    pub banks: Vec<ReserveBank>,
    pub last_reconciliation: DateTime<Utc>,
    pub last_verified: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuditDocument {
    pub id: String,
    pub title: String,
    pub period: String,
    pub auditor: String,
    pub published_at: DateTime<Utc>,
    pub download_url: String,
    pub sha256_checksum: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DocumentsResponse {
    pub documents: Vec<AuditDocument>,
    pub last_verified: DateTime<Utc>,
}

// ── DB row types ──────────────────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
struct TransparencySnapshot {
    circulating_supply: sqlx::types::BigDecimal,
    total_fiat_ngn: sqlx::types::BigDecimal,
    collateralisation_ratio: sqlx::types::BigDecimal,
    snapshot_at: DateTime<Utc>,
}

#[derive(sqlx::FromRow)]
struct ReserveBankRow {
    label: String,
    fiat_balance_ngn: sqlx::types::BigDecimal,
    currency: String,
}

#[derive(sqlx::FromRow)]
struct AuditDocumentRow {
    id: uuid::Uuid,
    title: String,
    period: String,
    auditor: String,
    published_at: DateTime<Utc>,
    download_url: String,
    sha256_checksum: String,
}

// ── Signing helper ────────────────────────────────────────────────────────────

fn sign_payload<T: Serialize>(
    payload: &T,
    key: &ed25519_dalek::SigningKey,
) -> Result<SignedResponse<T>, serde_json::Error>
where
    T: Serialize + Clone,
{
    use ed25519_dalek::Signer;

    let canonical = serde_json::to_vec(payload)?;
    let sig = key.sign(&canonical);
    let vk = key.verifying_key();

    Ok(SignedResponse {
        payload: serde_json::from_slice(&canonical)?,
        signature: hex::encode(sig.to_bytes()),
        public_key: hex::encode(vk.to_bytes()),
    })
}

// ── Cache-control helper ──────────────────────────────────────────────────────

/// Adds `Cache-Control: public, max-age=60` so CDN/Cloudflare caches for 60 s.
fn cached_json<T: Serialize>(body: T) -> Response {
    (
        StatusCode::OK,
        [
            (header::CACHE_CONTROL, "public, max-age=60, stale-while-revalidate=30"),
            (header::CONTENT_TYPE, "application/json"),
        ],
        Json(body),
    )
        .into_response()
}

fn error_response(code: StatusCode, message: &str) -> Response {
    (code, Json(serde_json::json!({ "error": message }))).into_response()
}

// ── Handlers ──────────────────────────────────────────────────────────────────

/// GET /v1/transparency/supply
///
/// Returns the current circulating supply of cNGN and a link to Stellar Expert
/// for on-chain verification.  Response is signed with the project's Ed25519 key.
pub async fn get_supply(State(state): State<Arc<TransparencyState>>) -> Response {
    info!("📊 Transparency supply endpoint accessed");

    let snap: Option<TransparencySnapshot> = sqlx::query_as(
        r#"
        SELECT circulating_supply, total_fiat_ngn, collateralisation_ratio, snapshot_at
        FROM transparency_snapshots
        ORDER BY snapshot_at DESC
        LIMIT 1
        "#,
    )
    .fetch_optional(&state.db)
    .await
    .unwrap_or(None);

    let cngn_issuer = std::env::var("CNGN_ISSUER_ADDRESS")
        .or_else(|_| std::env::var("CNGN_ISSUER_MAINNET"))
        .unwrap_or_else(|_| "GXXXXDEFAULTISSUERXXXX".to_string());

    let (supply_str, status, last_verified) = match snap {
        Some(ref s) => {
            let ratio: f64 = s
                .collateralisation_ratio
                .to_string()
                .parse()
                .unwrap_or(0.0);
            (
                s.circulating_supply.to_string(),
                BackingStatus::from_ratio(ratio),
                s.snapshot_at,
            )
        }
        None => (
            "0".to_string(),
            BackingStatus::Unverified,
            Utc::now(),
        ),
    };

    let payload = SupplyResponse {
        circulating_supply: supply_str,
        asset: "cNGN".to_string(),
        network: "Stellar".to_string(),
        stellar_explorer_url: format!(
            "https://stellar.expert/explorer/public/asset/cNGN-{}",
            cngn_issuer
        ),
        last_verified,
        status,
    };

    match sign_payload(&payload, &state.signing_key) {
        Ok(signed) => cached_json(signed),
        Err(e) => {
            error!("Failed to sign supply payload: {}", e);
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "Failed to sign response")
        }
    }
}

/// GET /v1/transparency/reserves
///
/// Returns the verified fiat total from the last Reconciliation Deep Check,
/// the collateralisation ratio, and an anonymised per-bank breakdown.
pub async fn get_reserves(State(state): State<Arc<TransparencyState>>) -> Response {
    info!("🏦 Transparency reserves endpoint accessed");

    let snap: Option<TransparencySnapshot> = sqlx::query_as(
        r#"
        SELECT circulating_supply, total_fiat_ngn, collateralisation_ratio, snapshot_at
        FROM transparency_snapshots
        ORDER BY snapshot_at DESC
        LIMIT 1
        "#,
    )
    .fetch_optional(&state.db)
    .await
    .unwrap_or(None);

    let banks: Vec<ReserveBankRow> = sqlx::query_as(
        r#"
        SELECT label, fiat_balance_ngn, currency
        FROM transparency_reserve_banks
        ORDER BY label
        "#,
    )
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    let (total_fiat, supply, ratio, last_recon) = match snap {
        Some(ref s) => (
            s.total_fiat_ngn.to_string(),
            s.circulating_supply.to_string(),
            s.collateralisation_ratio.to_string(),
            s.snapshot_at,
        ),
        None => (
            "0".to_string(),
            "0".to_string(),
            "0".to_string(),
            Utc::now(),
        ),
    };

    let ratio_f64: f64 = ratio.parse().unwrap_or(0.0);
    let status = BackingStatus::from_ratio(ratio_f64);

    let payload = ReservesResponse {
        total_fiat_ngn: total_fiat,
        circulating_supply: supply,
        collateralisation_ratio: ratio,
        status,
        banks: banks
            .into_iter()
            .map(|b| ReserveBank {
                label: b.label,
                fiat_balance_ngn: b.fiat_balance_ngn.to_string(),
                currency: b.currency,
            })
            .collect(),
        last_reconciliation: last_recon,
        last_verified: Utc::now(),
    };

    match sign_payload(&payload, &state.signing_key) {
        Ok(signed) => cached_json(signed),
        Err(e) => {
            error!("Failed to sign reserves payload: {}", e);
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "Failed to sign response")
        }
    }
}

/// GET /v1/transparency/documents
///
/// Lists available attestation report PDFs from third-party accounting firms.
pub async fn get_documents(State(state): State<Arc<TransparencyState>>) -> Response {
    info!("📄 Transparency documents endpoint accessed");

    let rows: Vec<AuditDocumentRow> = sqlx::query_as(
        r#"
        SELECT id, title, period, auditor, published_at, download_url, sha256_checksum
        FROM transparency_audit_documents
        ORDER BY published_at DESC
        "#,
    )
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    let payload = DocumentsResponse {
        documents: rows
            .into_iter()
            .map(|r| AuditDocument {
                id: r.id.to_string(),
                title: r.title,
                period: r.period,
                auditor: r.auditor,
                published_at: r.published_at,
                download_url: r.download_url,
                sha256_checksum: r.sha256_checksum,
            })
            .collect(),
        last_verified: Utc::now(),
    };

    match sign_payload(&payload, &state.signing_key) {
        Ok(signed) => cached_json(signed),
        Err(e) => {
            error!("Failed to sign documents payload: {}", e);
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "Failed to sign response")
        }
    }
}

// ── Router ────────────────────────────────────────────────────────────────────

pub fn transparency_routes(state: Arc<TransparencyState>) -> Router {
    Router::new()
        .route("/v1/transparency/supply", get(get_supply))
        .route("/v1/transparency/reserves", get(get_reserves))
        .route("/v1/transparency/documents", get(get_documents))
        .with_state(state)
}

// ── Key loading helper ────────────────────────────────────────────────────────

/// Load the Ed25519 signing key from `TRANSPARENCY_SIGNING_KEY_HEX` env var
/// (64 hex chars = 32-byte seed).  Falls back to a deterministic dev key so
/// the server still starts in development without the env var set.
pub fn load_signing_key() -> Arc<ed25519_dalek::SigningKey> {
    use ed25519_dalek::SigningKey;

    let key = if let Ok(hex_seed) = std::env::var("TRANSPARENCY_SIGNING_KEY_HEX") {
        let bytes = hex::decode(hex_seed.trim()).expect(
            "TRANSPARENCY_SIGNING_KEY_HEX must be 64 hex chars (32-byte Ed25519 seed)",
        );
        let arr: [u8; 32] = bytes
            .try_into()
            .expect("TRANSPARENCY_SIGNING_KEY_HEX must decode to exactly 32 bytes");
        SigningKey::from_bytes(&arr)
    } else {
        tracing::warn!(
            "TRANSPARENCY_SIGNING_KEY_HEX not set — using insecure dev key. \
             Set this env var in production."
        );
        // Deterministic dev key — all zeros seed
        SigningKey::from_bytes(&[0u8; 32])
    };

    Arc::new(key)
}
