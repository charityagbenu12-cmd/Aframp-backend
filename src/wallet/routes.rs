use crate::wallet::handlers::*;
use axum::{
    routing::{get, patch, post},
    Router,
};
use std::sync::Arc;

pub fn wallet_routes(state: Arc<WalletAppState>) -> Router {
    Router::new()
        // Auth
        .route("/api/wallet/auth/challenge", post(generate_auth_challenge))
        .route("/api/wallet/auth/verify", post(verify_auth_challenge))
        // Registration & management
        .route("/api/wallet/register", post(register_wallet))
        .route("/api/wallet", get(list_wallets))
        .route("/api/wallet/:wallet_id/activation-status", get(get_activation_status))
        .route("/api/wallet/:wallet_id/set-primary", post(set_primary_wallet))
        // Backup
        .route("/api/wallet/:wallet_id/backup/confirm", post(confirm_backup))
        .route("/api/wallet/:wallet_id/backup/status", get(get_backup_status))
        // Recovery
        .route("/api/wallet/recover/initiate", post(initiate_mnemonic_recovery))
        .route("/api/wallet/:wallet_id/recovery/guardians", post(set_guardians))
        .route("/api/wallet/recover/social/initiate", post(initiate_social_recovery))
        .route("/api/wallet/recover/social/guardian-approval/:recovery_id", post(guardian_approval))
        .route("/api/wallet/migrate", post(migrate_wallet))
        // History
        .route("/api/wallet/:wallet_id/history", get(get_wallet_history))
        // Statements
        .route("/api/wallet/statements/generate", post(generate_statement))
        .route("/api/wallet/statements/:statement_id", get(get_statement))
        .route("/api/wallet/statements", get(list_statements))
        // Portfolio
        .route("/api/wallet/portfolio/balances", get(get_portfolio_balances))
        .route("/api/wallet/portfolio/allocation", get(get_portfolio_allocation))
        .with_state(state)
}
