use crate::vault::{
    provider::BalanceProvider,
    types::{
        AccountType, ReserveBalance, TransactionDirection, TransactionStatus, VaultResult,
        VaultTransaction,
    },
};
use async_trait::async_trait;
use chrono::Utc;
use rust_decimal_macros::dec;

/// In-memory mock provider for development and integration tests.
/// Returns deterministic data; never makes real HTTP calls.
pub struct MockBalanceProvider {
    pub account_id: String,
    pub account_type: AccountType,
}

#[async_trait]
impl BalanceProvider for MockBalanceProvider {
    fn name(&self) -> &'static str {
        "mock"
    }

    async fn get_balance(&self, _account_id: &str) -> VaultResult<ReserveBalance> {
        Ok(ReserveBalance {
            account_id: self.account_id.clone(),
            account_type: self.account_type.clone(),
            available_balance: dec!(10_000_000.00),
            ledger_balance: dec!(10_250_000.00),
            currency: "NGN".to_string(),
            fetched_at: Utc::now(),
        })
    }

    async fn list_transactions(
        &self,
        account_id: &str,
        limit: u32,
    ) -> VaultResult<Vec<VaultTransaction>> {
        let txns: Vec<VaultTransaction> = (0..limit.min(3))
            .map(|i| VaultTransaction {
                id: format!("mock_txn_{}", i),
                account_id: account_id.to_string(),
                direction: if i % 2 == 0 {
                    TransactionDirection::Inbound
                } else {
                    TransactionDirection::Outbound
                },
                amount: dec!(500_000.00),
                currency: "NGN".to_string(),
                narration: Some(format!("Mock transaction {}", i)),
                reference: format!("REF{:06}", i),
                status: TransactionStatus::Settled,
                created_at: Utc::now(),
            })
            .collect();
        Ok(txns)
    }
}
