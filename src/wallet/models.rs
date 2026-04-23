use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct WalletRecord {
    pub id: Uuid,
    pub user_account_id: Uuid,
    pub stellar_public_key: String,
    pub wallet_label: Option<String>,
    pub wallet_type: String,
    pub status: String,
    pub is_primary: bool,
    pub kyc_tier_at_registration: i32,
    pub registration_ip: Option<String>,
    pub last_activity_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct WalletMetadata {
    pub wallet_id: Uuid,
    pub network: String,
    pub account_created_on_stellar: bool,
    pub min_xlm_balance_met: bool,
    pub cngn_trustline_active: bool,
    pub xlm_balance: Option<sqlx::types::BigDecimal>,
    pub last_horizon_sync_at: Option<DateTime<Utc>>,
    pub horizon_cursor: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct WalletAuthChallenge {
    pub id: Uuid,
    pub stellar_public_key: String,
    pub challenge: String,
    pub used: bool,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct BackupConfirmation {
    pub id: Uuid,
    pub wallet_id: Uuid,
    pub confirmed_at: DateTime<Utc>,
    pub confirmation_method: String,
    pub last_reminder_sent_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct RecoverySession {
    pub id: Uuid,
    pub recovered_public_key: Option<String>,
    pub recovery_method: String,
    pub status: String,
    pub ip_address: Option<String>,
    pub failure_reason: Option<String>,
    pub initiated_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct WalletGuardian {
    pub id: Uuid,
    pub wallet_id: Uuid,
    pub guardian_user_id: Option<Uuid>,
    pub guardian_email: Option<String>,
    pub share_index: i32,
    pub status: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct SocialRecoveryRequest {
    pub id: Uuid,
    pub wallet_id: Uuid,
    pub status: String,
    pub threshold_required: i32,
    pub shares_collected: i32,
    pub initiated_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct WalletMigration {
    pub id: Uuid,
    pub old_wallet_id: Uuid,
    pub new_wallet_id: Uuid,
    pub status: String,
    pub old_wallet_signature: String,
    pub new_wallet_signature: String,
    pub initiated_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct TransactionHistoryEntry {
    pub id: Uuid,
    pub wallet_id: Uuid,
    pub entry_type: String,
    pub direction: String,
    pub asset_code: String,
    pub asset_issuer: Option<String>,
    pub amount: sqlx::types::BigDecimal,
    pub fiat_equivalent: Option<sqlx::types::BigDecimal>,
    pub fiat_currency: Option<String>,
    pub exchange_rate: Option<sqlx::types::BigDecimal>,
    pub counterparty: Option<String>,
    pub platform_transaction_id: Option<Uuid>,
    pub stellar_transaction_hash: Option<String>,
    pub parent_entry_id: Option<Uuid>,
    pub status: String,
    pub description: Option<String>,
    pub failure_reason: Option<String>,
    pub horizon_cursor: Option<String>,
    pub confirmed_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct PortfolioSnapshot {
    pub id: Uuid,
    pub user_account_id: Uuid,
    pub snapshot_at: DateTime<Utc>,
    pub total_value_fiat: sqlx::types::BigDecimal,
    pub fiat_currency: String,
    pub asset_breakdown: serde_json::Value,
    pub exchange_rates_applied: serde_json::Value,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct FinancialStatement {
    pub id: Uuid,
    pub user_account_id: Uuid,
    pub wallet_id: Option<Uuid>,
    pub statement_type: String,
    pub date_from: chrono::NaiveDate,
    pub date_to: chrono::NaiveDate,
    pub status: String,
    pub format: String,
    pub file_url: Option<String>,
    pub verification_code: Option<String>,
    pub download_expires_at: Option<DateTime<Utc>>,
    pub generated_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

// Request/Response DTOs
#[derive(Debug, Deserialize)]
pub struct RegisterWalletRequest {
    pub stellar_public_key: String,
    pub signed_challenge: String,
    pub challenge_id: String,
    pub wallet_label: Option<String>,
    pub wallet_type: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RegisterWalletResponse {
    pub wallet_id: Uuid,
    pub stellar_public_key: String,
    pub status: String,
}

#[derive(Debug, Deserialize)]
pub struct AuthChallengeRequest {
    pub stellar_public_key: String,
}

#[derive(Debug, Serialize)]
pub struct AuthChallengeResponse {
    pub challenge_id: String,
    pub challenge: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct VerifyChallengeRequest {
    pub stellar_public_key: String,
    pub challenge_id: String,
    pub signed_challenge: String,
}

#[derive(Debug, Serialize)]
pub struct VerifyChallengeResponse {
    pub access_token: String,
    pub wallet_id: Uuid,
}

#[derive(Debug, Deserialize)]
pub struct RecoverWalletRequest {
    pub recovered_public_key: String,
    pub ownership_proof_signature: String,
    pub challenge: String,
}

#[derive(Debug, Deserialize)]
pub struct InitiateSocialRecoveryRequest {
    pub wallet_id: Uuid,
}

#[derive(Debug, Deserialize)]
pub struct GuardianApprovalRequest {
    pub share: String,
    pub signature: String,
}

#[derive(Debug, Deserialize)]
pub struct MigrateWalletRequest {
    pub old_wallet_id: Uuid,
    pub new_stellar_public_key: String,
    pub old_wallet_signature: String,
    pub new_wallet_signature: String,
    pub migration_challenge: String,
}

#[derive(Debug, Deserialize)]
pub struct HistoryQuery {
    pub cursor: Option<String>,
    pub limit: Option<i64>,
    pub entry_type: Option<String>,
    pub direction: Option<String>,
    pub asset_code: Option<String>,
    pub status: Option<String>,
    pub date_from: Option<DateTime<Utc>>,
    pub date_to: Option<DateTime<Utc>>,
    pub sort: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct HistoryPage {
    pub entries: Vec<TransactionHistoryEntry>,
    pub next_cursor: Option<String>,
    pub total_credits: sqlx::types::BigDecimal,
    pub total_debits: sqlx::types::BigDecimal,
}

#[derive(Debug, Deserialize)]
pub struct GenerateStatementRequest {
    pub wallet_id: Option<Uuid>,
    pub statement_type: String,
    pub date_from: chrono::NaiveDate,
    pub date_to: chrono::NaiveDate,
    pub format: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ExportHistoryRequest {
    pub date_from: chrono::NaiveDate,
    pub date_to: chrono::NaiveDate,
    pub format: Option<String>,
}
