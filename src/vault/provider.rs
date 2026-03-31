use crate::vault::types::{ReserveBalance, VaultResult, VaultTransaction};
use async_trait::async_trait;

/// Abstraction over different custodian / banking APIs.
///
/// Implement this trait for each banking partner (e.g. Providus, Sterling, mock).
/// The `VaultService` depends only on this interface, keeping custodian-specific
/// HTTP/auth logic fully isolated.
#[async_trait]
pub trait BalanceProvider: Send + Sync {
    /// Human-readable name of this provider (used in logs and metrics).
    fn name(&self) -> &'static str;

    /// Fetch the current available and ledger balances for `account_id`.
    async fn get_balance(&self, account_id: &str) -> VaultResult<ReserveBalance>;

    /// List recent transactions for `account_id`.
    /// `limit` caps the number of records returned.
    async fn list_transactions(
        &self,
        account_id: &str,
        limit: u32,
    ) -> VaultResult<Vec<VaultTransaction>>;
}
