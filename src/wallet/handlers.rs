use crate::wallet::{
    backup::{backup_health, create_backup_challenge, verify_backup_challenge},
    metrics::WalletMetrics,
    models::*,
    portfolio::{PortfolioService, PortfolioBalances},
    recovery::{generate_challenge, is_valid_stellar_pubkey, verify_stellar_signature},
    repository::{
        CreateStatementRecord, InsertHistoryEntry, PortfolioRepository, StatementRepository,
        TransactionHistoryRepository, WalletRegistryRepository,
    },
};
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use tracing::{error, info, warn};
use uuid::Uuid;

pub struct WalletAppState {
    pub repo: Arc<WalletRegistryRepository>,
    pub history_repo: Arc<TransactionHistoryRepository>,
    pub portfolio_repo: Arc<PortfolioRepository>,
    pub statement_repo: Arc<StatementRepository>,
    pub metrics: Arc<WalletMetrics>,
    pub jwt_secret: String,
    pub max_wallets_per_user: i64,
    pub challenge_ttl_secs: i64,
    pub recovery_attack_threshold: i64,
    pub unconfirmed_backup_alert_threshold: i64,
}

fn extract_ip(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-forwarded-for")
        .or_else(|| headers.get("x-real-ip"))
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(',').next().unwrap_or(s).trim().to_string())
}

fn extract_user_id(headers: &HeaderMap) -> Option<Uuid> {
    headers
        .get("x-user-id")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| Uuid::parse_str(s).ok())
}

// POST /api/wallet/auth/challenge
pub async fn generate_auth_challenge(
    State(state): State<Arc<WalletAppState>>,
    Json(req): Json<AuthChallengeRequest>,
) -> impl IntoResponse {
    if !is_valid_stellar_pubkey(&req.stellar_public_key) {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "invalid_public_key"}))).into_response();
    }
    let challenge = generate_challenge();
    match state
        .repo
        .create_challenge(&req.stellar_public_key, &challenge, state.challenge_ttl_secs)
        .await
    {
        Ok(c) => {
            state.metrics.auth_challenges_issued.inc();
            (StatusCode::OK, Json(json!({
                "challenge_id": c.id,
                "challenge": c.challenge,
                "expires_at": c.expires_at
            }))).into_response()
        }
        Err(e) => {
            error!(error = %e, "Failed to create challenge");
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "internal_error"}))).into_response()
        }
    }
}

// POST /api/wallet/auth/verify
pub async fn verify_auth_challenge(
    State(state): State<Arc<WalletAppState>>,
    Json(req): Json<VerifyChallengeRequest>,
) -> impl IntoResponse {
    let challenge_id = match Uuid::parse_str(&req.challenge_id) {
        Ok(id) => id,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(json!({"error": "invalid_challenge_id"}))).into_response(),
    };

    let challenge = match state.repo.consume_challenge(challenge_id).await {
        Ok(Some(c)) => c,
        Ok(None) => return (StatusCode::UNAUTHORIZED, Json(json!({"error": "invalid_or_expired_challenge"}))).into_response(),
        Err(e) => {
            error!(error = %e, "Challenge lookup failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "internal_error"}))).into_response();
        }
    };

    if challenge.stellar_public_key != req.stellar_public_key {
        return (StatusCode::UNAUTHORIZED, Json(json!({"error": "key_mismatch"}))).into_response();
    }

    match verify_stellar_signature(&req.stellar_public_key, challenge.challenge.as_bytes(), &req.signed_challenge) {
        Ok(true) => {}
        Ok(false) => {
            state.metrics.ownership_proof_failures.inc();
            return (StatusCode::UNAUTHORIZED, Json(json!({"error": "invalid_signature"}))).into_response();
        }
        Err(e) => {
            state.metrics.ownership_proof_failures.inc();
            warn!(error = %e, "Signature verification error");
            return (StatusCode::UNAUTHORIZED, Json(json!({"error": "invalid_signature"}))).into_response();
        }
    }

    let wallet = match state.repo.find_by_public_key(&req.stellar_public_key).await {
        Ok(Some(w)) => w,
        Ok(None) => return (StatusCode::NOT_FOUND, Json(json!({"error": "wallet_not_registered"}))).into_response(),
        Err(e) => {
            error!(error = %e, "Wallet lookup failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "internal_error"}))).into_response();
        }
    };

    // Issue JWT scoped to wallet
    let token = issue_wallet_jwt(&wallet.id, &req.stellar_public_key, &state.jwt_secret);
    state.metrics.auth_challenges_verified.inc();
    (StatusCode::OK, Json(json!({
        "access_token": token,
        "wallet_id": wallet.id
    }))).into_response()
}

// POST /api/wallet/register
pub async fn register_wallet(
    State(state): State<Arc<WalletAppState>>,
    headers: HeaderMap,
    Json(req): Json<RegisterWalletRequest>,
) -> impl IntoResponse {
    let user_id = match extract_user_id(&headers) {
        Some(id) => id,
        None => return (StatusCode::UNAUTHORIZED, Json(json!({"error": "unauthenticated"}))).into_response(),
    };

    if !is_valid_stellar_pubkey(&req.stellar_public_key) {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "invalid_public_key"}))).into_response();
    }

    // Check duplicate — return generic error
    if let Ok(Some(_)) = state.repo.find_by_public_key(&req.stellar_public_key).await {
        return (StatusCode::CONFLICT, Json(json!({"error": "registration_failed"}))).into_response();
    }

    // Verify ownership proof
    let challenge_id = match Uuid::parse_str(&req.challenge_id) {
        Ok(id) => id,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(json!({"error": "invalid_challenge_id"}))).into_response(),
    };
    let challenge = match state.repo.consume_challenge(challenge_id).await {
        Ok(Some(c)) => c,
        _ => return (StatusCode::UNAUTHORIZED, Json(json!({"error": "invalid_challenge"}))).into_response(),
    };

    match verify_stellar_signature(&req.stellar_public_key, challenge.challenge.as_bytes(), &req.signed_challenge) {
        Ok(true) => {}
        _ => {
            state.metrics.ownership_proof_failures.inc();
            return (StatusCode::UNAUTHORIZED, Json(json!({"error": "invalid_signature"}))).into_response();
        }
    }

    // Enforce max wallet count
    let count = state.repo.count_active_wallets(user_id).await.unwrap_or(0);
    if count >= state.max_wallets_per_user {
        return (StatusCode::UNPROCESSABLE_ENTITY, Json(json!({"error": "max_wallets_reached"}))).into_response();
    }

    let ip = extract_ip(&headers);
    let wallet_type = req.wallet_type.as_deref().unwrap_or("personal");
    match state
        .repo
        .create(user_id, &req.stellar_public_key, req.wallet_label.as_deref(), wallet_type, ip.as_deref(), 0)
        .await
    {
        Ok(wallet) => {
            let _ = state.repo.upsert_metadata(wallet.id, "testnet").await;
            state.metrics.wallet_registrations.inc();
            info!(wallet_id = %wallet.id, pubkey = %wallet.stellar_public_key, "Wallet registered");
            (StatusCode::CREATED, Json(json!({
                "wallet_id": wallet.id,
                "stellar_public_key": wallet.stellar_public_key,
                "status": wallet.status
            }))).into_response()
        }
        Err(e) => {
            error!(error = %e, "Wallet creation failed");
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "internal_error"}))).into_response()
        }
    }
}

// GET /api/wallet
pub async fn list_wallets(
    State(state): State<Arc<WalletAppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let user_id = match extract_user_id(&headers) {
        Some(id) => id,
        None => return (StatusCode::UNAUTHORIZED, Json(json!({"error": "unauthenticated"}))).into_response(),
    };
    match state.repo.find_by_user(user_id).await {
        Ok(wallets) => (StatusCode::OK, Json(json!({"wallets": wallets}))).into_response(),
        Err(e) => {
            error!(error = %e, "List wallets failed");
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "internal_error"}))).into_response()
        }
    }
}

// GET /api/wallet/:wallet_id/activation-status
pub async fn get_activation_status(
    State(state): State<Arc<WalletAppState>>,
    Path(wallet_id): Path<Uuid>,
) -> impl IntoResponse {
    let meta = match state.repo.get_metadata(wallet_id).await {
        Ok(Some(m)) => m,
        Ok(None) => return (StatusCode::NOT_FOUND, Json(json!({"error": "not_found"}))).into_response(),
        Err(e) => {
            error!(error = %e, "Metadata fetch failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "internal_error"}))).into_response();
        }
    };
    (StatusCode::OK, Json(json!({
        "wallet_id": wallet_id,
        "account_created_on_stellar": meta.account_created_on_stellar,
        "min_xlm_balance_met": meta.min_xlm_balance_met,
        "xlm_balance": meta.xlm_balance,
        "cngn_trustline_active": meta.cngn_trustline_active,
        "last_synced_at": meta.last_horizon_sync_at
    }))).into_response()
}

// POST /api/wallet/:wallet_id/set-primary
pub async fn set_primary_wallet(
    State(state): State<Arc<WalletAppState>>,
    headers: HeaderMap,
    Path(wallet_id): Path<Uuid>,
) -> impl IntoResponse {
    let user_id = match extract_user_id(&headers) {
        Some(id) => id,
        None => return (StatusCode::UNAUTHORIZED, Json(json!({"error": "unauthenticated"}))).into_response(),
    };
    match state.repo.set_primary(user_id, wallet_id).await {
        Ok(_) => (StatusCode::OK, Json(json!({"success": true}))).into_response(),
        Err(e) => {
            error!(error = %e, "Set primary failed");
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "internal_error"}))).into_response()
        }
    }
}

// POST /api/wallet/:wallet_id/backup/confirm
pub async fn confirm_backup(
    State(state): State<Arc<WalletAppState>>,
    Path(wallet_id): Path<Uuid>,
) -> impl IntoResponse {
    match state.repo.confirm_backup(wallet_id).await {
        Ok(confirmation) => {
            state.metrics.backup_confirmations.inc();
            (StatusCode::OK, Json(json!({
                "wallet_id": wallet_id,
                "confirmed_at": confirmation.confirmed_at
            }))).into_response()
        }
        Err(e) => {
            error!(error = %e, "Backup confirm failed");
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "internal_error"}))).into_response()
        }
    }
}

// GET /api/wallet/:wallet_id/backup/status
pub async fn get_backup_status(
    State(state): State<Arc<WalletAppState>>,
    Path(wallet_id): Path<Uuid>,
) -> impl IntoResponse {
    let confirmation = state.repo.get_backup_status(wallet_id).await.unwrap_or(None);
    let (confirmed, days_ago) = match &confirmation {
        Some(c) => {
            let days = (Utc::now() - c.confirmed_at).num_days();
            (true, Some(days))
        }
        None => (false, None),
    };
    let health = backup_health(confirmed, days_ago, 30);
    (StatusCode::OK, Json(json!({
        "wallet_id": wallet_id,
        "backup_confirmed": confirmed,
        "confirmed_at": confirmation.as_ref().map(|c| c.confirmed_at),
        "health": health,
        "active_recovery_methods": if confirmed { vec!["mnemonic"] } else { vec![] as Vec<&str> }
    }))).into_response()
}

// POST /api/wallet/recover/initiate
pub async fn initiate_mnemonic_recovery(
    State(state): State<Arc<WalletAppState>>,
    headers: HeaderMap,
    Json(req): Json<RecoverWalletRequest>,
) -> impl IntoResponse {
    let ip = extract_ip(&headers).unwrap_or_else(|| "unknown".to_string());

    // Rate limiting / cooloff
    if let Ok(Some(cooloff)) = state.repo.get_cooloff(&ip).await {
        return (StatusCode::TOO_MANY_REQUESTS, Json(json!({
            "error": "rate_limited",
            "retry_after": cooloff
        }))).into_response();
    }

    if !is_valid_stellar_pubkey(&req.recovered_public_key) {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "invalid_public_key"}))).into_response();
    }

    // Verify ownership proof
    let valid = verify_stellar_signature(
        &req.recovered_public_key,
        req.challenge.as_bytes(),
        &req.ownership_proof_signature,
    )
    .unwrap_or(false);

    let session = state.repo.create_recovery_session("mnemonic", Some(&ip)).await;
    state.metrics.recovery_initiations.with_label_values(&["mnemonic"]).inc();

    if !valid {
        state.metrics.recovery_failures.inc();
        // Progressive cooloff: count recent failures
        let attempts = state.repo.count_recent_attempts(&ip, 3600).await.unwrap_or(0);
        let cooloff_secs = match attempts {
            0..=1 => 60,
            2..=3 => 300,
            _ => 1800,
        };
        let cooloff_until = Utc::now() + Duration::seconds(cooloff_secs);
        let _ = state.repo.record_recovery_attempt(&ip, Some(&req.recovered_public_key), false, Some(cooloff_until)).await;
        if let Ok(s) = &session {
            let _ = state.repo.complete_recovery_session(s.id, &req.recovered_public_key, false, Some("invalid_signature")).await;
        }
        return (StatusCode::UNAUTHORIZED, Json(json!({"error": "invalid_ownership_proof"}))).into_response();
    }

    let _ = state.repo.record_recovery_attempt(&ip, Some(&req.recovered_public_key), true, None).await;
    if let Ok(s) = &session {
        let _ = state.repo.complete_recovery_session(s.id, &req.recovered_public_key, true, None).await;
    }
    state.metrics.recovery_successes.with_label_values(&["mnemonic"]).inc();

    info!(pubkey = %req.recovered_public_key, ip = %ip, "Mnemonic recovery completed");
    (StatusCode::OK, Json(json!({
        "recovered_public_key": req.recovered_public_key,
        "message": "Ownership verified. Re-link wallet to your account via /api/wallet/register."
    }))).into_response()
}

// POST /api/wallet/:wallet_id/recovery/guardians
pub async fn set_guardians(
    State(state): State<Arc<WalletAppState>>,
    Path(wallet_id): Path<Uuid>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let guardians_raw = match body.get("guardians").and_then(|v| v.as_array()) {
        Some(g) => g.clone(),
        None => return (StatusCode::BAD_REQUEST, Json(json!({"error": "guardians_required"}))).into_response(),
    };
    let guardians: Vec<(Option<Uuid>, Option<String>)> = guardians_raw
        .iter()
        .map(|g| {
            let uid = g.get("user_id").and_then(|v| v.as_str()).and_then(|s| Uuid::parse_str(s).ok());
            let email = g.get("email").and_then(|v| v.as_str()).map(String::from);
            (uid, email)
        })
        .collect();

    match state.repo.set_guardians(wallet_id, &guardians).await {
        Ok(_) => (StatusCode::OK, Json(json!({"success": true, "guardian_count": guardians.len()}))).into_response(),
        Err(e) => {
            error!(error = %e, "Set guardians failed");
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "internal_error"}))).into_response()
        }
    }
}

// POST /api/wallet/recover/social/initiate
pub async fn initiate_social_recovery(
    State(state): State<Arc<WalletAppState>>,
    Json(req): Json<InitiateSocialRecoveryRequest>,
) -> impl IntoResponse {
    let guardians = match state.repo.get_guardians(req.wallet_id).await {
        Ok(g) if !g.is_empty() => g,
        _ => return (StatusCode::BAD_REQUEST, Json(json!({"error": "no_guardians_configured"}))).into_response(),
    };
    let threshold = ((guardians.len() as f32 * 0.6).ceil() as i32).max(2);
    match state.repo.create_social_recovery_request(req.wallet_id, threshold).await {
        Ok(request) => {
            state.metrics.recovery_initiations.with_label_values(&["social"]).inc();
            (StatusCode::OK, Json(json!({
                "recovery_id": request.id,
                "threshold_required": threshold,
                "guardian_count": guardians.len(),
                "expires_at": request.expires_at
            }))).into_response()
        }
        Err(e) => {
            error!(error = %e, "Social recovery initiation failed");
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "internal_error"}))).into_response()
        }
    }
}

// POST /api/wallet/recover/social/guardian-approval/:recovery_id
pub async fn guardian_approval(
    State(state): State<Arc<WalletAppState>>,
    Path(recovery_id): Path<Uuid>,
    headers: HeaderMap,
    Json(req): Json<GuardianApprovalRequest>,
) -> impl IntoResponse {
    let guardian_id = match extract_user_id(&headers) {
        Some(id) => id,
        None => return (StatusCode::UNAUTHORIZED, Json(json!({"error": "unauthenticated"}))).into_response(),
    };

    // Find guardian record
    let guardians_for_wallet: Vec<crate::wallet::models::WalletGuardian> = vec![]; // simplified
    let _ = guardians_for_wallet;

    match state.repo.add_guardian_approval(recovery_id, guardian_id, &req.signature).await {
        Ok(shares_collected) => {
            state.metrics.guardian_approvals.inc();
            // Check if threshold met (we'd need to fetch the request — simplified here)
            (StatusCode::OK, Json(json!({
                "shares_collected": shares_collected,
                "message": "Approval recorded"
            }))).into_response()
        }
        Err(e) => {
            error!(error = %e, "Guardian approval failed");
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "internal_error"}))).into_response()
        }
    }
}

// POST /api/wallet/migrate
pub async fn migrate_wallet(
    State(state): State<Arc<WalletAppState>>,
    headers: HeaderMap,
    Json(req): Json<MigrateWalletRequest>,
) -> impl IntoResponse {
    let user_id = match extract_user_id(&headers) {
        Some(id) => id,
        None => return (StatusCode::UNAUTHORIZED, Json(json!({"error": "unauthenticated"}))).into_response(),
    };

    // Verify old wallet ownership
    let old_wallet = match state.repo.find_by_id(req.old_wallet_id).await {
        Ok(Some(w)) if w.user_account_id == user_id => w,
        _ => return (StatusCode::NOT_FOUND, Json(json!({"error": "wallet_not_found"}))).into_response(),
    };

    // Verify dual signatures
    let old_valid = verify_stellar_signature(
        &old_wallet.stellar_public_key,
        req.migration_challenge.as_bytes(),
        &req.old_wallet_signature,
    ).unwrap_or(false);

    let new_valid = verify_stellar_signature(
        &req.new_stellar_public_key,
        req.migration_challenge.as_bytes(),
        &req.new_wallet_signature,
    ).unwrap_or(false);

    if !old_valid || !new_valid {
        return (StatusCode::UNAUTHORIZED, Json(json!({"error": "invalid_dual_signature"}))).into_response();
    }

    if !is_valid_stellar_pubkey(&req.new_stellar_public_key) {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "invalid_new_public_key"}))).into_response();
    }

    // Register new wallet
    let new_wallet = match state.repo.create(user_id, &req.new_stellar_public_key, None, "personal", None, old_wallet.kyc_tier_at_registration).await {
        Ok(w) => w,
        Err(e) => {
            error!(error = %e, "New wallet creation failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "internal_error"}))).into_response();
        }
    };

    match state.repo.create_migration(req.old_wallet_id, new_wallet.id, &req.old_wallet_signature, &req.new_wallet_signature).await {
        Ok(migration) => {
            let _ = state.repo.complete_migration(migration.id).await;
            (StatusCode::OK, Json(json!({
                "migration_id": migration.id,
                "new_wallet_id": new_wallet.id,
                "status": "completed"
            }))).into_response()
        }
        Err(e) => {
            error!(error = %e, "Migration record failed");
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "internal_error"}))).into_response()
        }
    }
}

// GET /api/wallet/:wallet_id/history
pub async fn get_wallet_history(
    State(state): State<Arc<WalletAppState>>,
    Path(wallet_id): Path<Uuid>,
    Query(query): Query<HistoryQuery>,
) -> impl IntoResponse {
    match state.history_repo.list_paginated(wallet_id, &query).await {
        Ok((entries, next_cursor)) => {
            use sqlx::types::BigDecimal;
            use std::str::FromStr;
            let zero = BigDecimal::from(0);
            let total_credits = entries.iter()
                .filter(|e| e.direction == "credit")
                .fold(zero.clone(), |acc, e| acc + &e.amount);
            let total_debits = entries.iter()
                .filter(|e| e.direction == "debit")
                .fold(zero, |acc, e| acc + &e.amount);
            (StatusCode::OK, Json(json!({
                "entries": entries,
                "next_cursor": next_cursor,
                "total_credits": total_credits.to_string(),
                "total_debits": total_debits.to_string()
            }))).into_response()
        }
        Err(e) => {
            error!(error = %e, "History fetch failed");
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "internal_error"}))).into_response()
        }
    }
}

// POST /api/wallet/statements/generate
pub async fn generate_statement(
    State(state): State<Arc<WalletAppState>>,
    headers: HeaderMap,
    Json(req): Json<GenerateStatementRequest>,
) -> impl IntoResponse {
    let user_id = match extract_user_id(&headers) {
        Some(id) => id,
        None => return (StatusCode::UNAUTHORIZED, Json(json!({"error": "unauthenticated"}))).into_response(),
    };

    let format = req.format.as_deref().unwrap_or("pdf").to_string();
    match state.statement_repo.create(&CreateStatementRecord {
        user_account_id: user_id,
        wallet_id: req.wallet_id,
        statement_type: req.statement_type.clone(),
        date_from: req.date_from,
        date_to: req.date_to,
        format,
    }).await {
        Ok(stmt) => {
            state.metrics.statement_generations.with_label_values(&[&req.statement_type]).inc();
            (StatusCode::ACCEPTED, Json(json!({
                "statement_id": stmt.id,
                "status": stmt.status,
                "message": "Statement generation queued"
            }))).into_response()
        }
        Err(e) => {
            error!(error = %e, "Statement creation failed");
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "internal_error"}))).into_response()
        }
    }
}

// GET /api/wallet/statements/:statement_id
pub async fn get_statement(
    State(state): State<Arc<WalletAppState>>,
    Path(statement_id): Path<Uuid>,
) -> impl IntoResponse {
    match state.statement_repo.find_by_id(statement_id).await {
        Ok(Some(stmt)) => (StatusCode::OK, Json(json!(stmt))).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, Json(json!({"error": "not_found"}))).into_response(),
        Err(e) => {
            error!(error = %e, "Statement fetch failed");
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "internal_error"}))).into_response()
        }
    }
}

// GET /api/wallet/statements
pub async fn list_statements(
    State(state): State<Arc<WalletAppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let user_id = match extract_user_id(&headers) {
        Some(id) => id,
        None => return (StatusCode::UNAUTHORIZED, Json(json!({"error": "unauthenticated"}))).into_response(),
    };
    match state.statement_repo.list_for_user(user_id).await {
        Ok(stmts) => (StatusCode::OK, Json(json!({"statements": stmts}))).into_response(),
        Err(e) => {
            error!(error = %e, "List statements failed");
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "internal_error"}))).into_response()
        }
    }
}

// GET /api/wallet/portfolio/balances
pub async fn get_portfolio_balances(
    State(state): State<Arc<WalletAppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    (StatusCode::OK, Json(json!({"message": "Portfolio balances endpoint - requires stellar client integration"}))).into_response()
}

// GET /api/wallet/portfolio/allocation
pub async fn get_portfolio_allocation(
    State(state): State<Arc<WalletAppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    (StatusCode::OK, Json(json!({"message": "Portfolio allocation endpoint"}))).into_response()
}

fn issue_wallet_jwt(wallet_id: &Uuid, pubkey: &str, secret: &str) -> String {
    use jsonwebtoken::{encode, EncodingKey, Header};
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize)]
    struct Claims {
        sub: String,
        wallet_id: String,
        pubkey: String,
        exp: usize,
    }

    let exp = (Utc::now() + Duration::hours(24)).timestamp() as usize;
    let claims = Claims {
        sub: wallet_id.to_string(),
        wallet_id: wallet_id.to_string(),
        pubkey: pubkey.to_string(),
        exp,
    };
    encode(&Header::default(), &claims, &EncodingKey::from_secret(secret.as_bytes()))
        .unwrap_or_else(|_| "token_error".to_string())
}
