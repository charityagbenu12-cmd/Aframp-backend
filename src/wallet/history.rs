use crate::chains::stellar::client::StellarClient;
use crate::wallet::repository::{InsertHistoryEntry, TransactionHistoryRepository};
use anyhow::Result;
use sqlx::types::BigDecimal;
use std::str::FromStr;
use tracing::{info, warn};
use uuid::Uuid;

/// Sync Stellar Horizon transactions for a wallet into the history table.
pub struct StellarHistorySyncer {
    stellar_client: StellarClient,
    repo: TransactionHistoryRepository,
}

impl StellarHistorySyncer {
    pub fn new(stellar_client: StellarClient, repo: TransactionHistoryRepository) -> Self {
        Self { stellar_client, repo }
    }

    pub async fn sync_wallet(&self, wallet_id: Uuid, address: &str) -> Result<usize> {
        let cursor = self.repo.get_sync_cursor(wallet_id).await?;
        let page = self
            .stellar_client
            .list_account_transactions(address, 200, cursor.as_deref())
            .await?;

        let mut synced = 0;
        let mut last_cursor = cursor.clone();

        for tx in &page.records {
            // Skip if already stored (deduplication)
            if self.repo.exists_by_stellar_hash(wallet_id, &tx.hash).await? {
                continue;
            }

            let ops = self
                .stellar_client
                .get_transaction_operations(&tx.hash)
                .await
                .unwrap_or_default();

            for op in &ops {
                if let Some(entry) = map_operation_to_entry(wallet_id, address, op, &tx.hash, tx.paging_token.as_deref()) {
                    if let Err(e) = self.repo.insert(&entry).await {
                        warn!(wallet_id = %wallet_id, hash = %tx.hash, error = %e, "Failed to insert history entry");
                    } else {
                        synced += 1;
                    }
                }
            }

            last_cursor = tx.paging_token.clone().or(last_cursor);
        }

        if let Some(cursor) = last_cursor {
            self.repo.update_sync_cursor(wallet_id, &cursor).await?;
        }

        info!(wallet_id = %wallet_id, synced, "Stellar history sync complete");
        Ok(synced)
    }
}

fn map_operation_to_entry(
    wallet_id: Uuid,
    wallet_address: &str,
    op: &serde_json::Value,
    tx_hash: &str,
    cursor: Option<&str>,
) -> Option<InsertHistoryEntry> {
    let op_type = op.get("type")?.as_str()?;
    let (entry_type, direction, asset_code, asset_issuer, amount, counterparty) = match op_type {
        "payment" => {
            let to = op.get("to")?.as_str()?;
            let from = op.get("from")?.as_str()?;
            let direction = if to == wallet_address { "credit" } else { "debit" };
            let counterparty = if direction == "credit" { from } else { to };
            let asset_type = op.get("asset_type")?.as_str()?;
            let (code, issuer) = if asset_type == "native" {
                ("XLM".to_string(), None)
            } else {
                (
                    op.get("asset_code")?.as_str()?.to_string(),
                    op.get("asset_issuer").and_then(|v| v.as_str()).map(String::from),
                )
            };
            let amount = op.get("amount")?.as_str()?.to_string();
            ("payment", direction, code, issuer, amount, counterparty.to_string())
        }
        "change_trust" => {
            let code = op.get("asset_code")?.as_str()?.to_string();
            let issuer = op.get("asset_issuer").and_then(|v| v.as_str()).map(String::from);
            ("trustline-establishment", "debit", code, issuer, "0".to_string(), String::new())
        }
        "create_account" => {
            let funder = op.get("funder")?.as_str()?;
            let direction = if funder == wallet_address { "debit" } else { "credit" };
            let amount = op.get("starting_balance")?.as_str()?.to_string();
            ("account-funding", direction, "XLM".to_string(), None, amount, funder.to_string())
        }
        _ => return None,
    };

    let amount_bd = BigDecimal::from_str(&amount).unwrap_or_default();
    Some(InsertHistoryEntry {
        wallet_id,
        entry_type: entry_type.to_string(),
        direction: direction.to_string(),
        asset_code,
        asset_issuer,
        amount: amount_bd,
        fiat_equivalent: None,
        fiat_currency: None,
        exchange_rate: None,
        counterparty: if counterparty.is_empty() { None } else { Some(counterparty) },
        platform_transaction_id: None,
        stellar_transaction_hash: Some(tx_hash.to_string()),
        parent_entry_id: None,
        status: Some("confirmed".to_string()),
        description: Some(format!("Stellar {} operation", op_type)),
        failure_reason: None,
        horizon_cursor: cursor.map(String::from),
        confirmed_at: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_map_payment_operation_credit() {
        let wallet = "GCJRI5CIWK5IU67Q6DGA7QW52JDKRO7JEAHQKFNDUJUPEZGURDBX3LDX";
        let op = serde_json::json!({
            "type": "payment",
            "to": wallet,
            "from": "GOTHER",
            "asset_type": "native",
            "amount": "10.0000000"
        });
        let entry = map_operation_to_entry(
            Uuid::new_v4(),
            wallet,
            &op,
            "hash123",
            Some("cursor1"),
        );
        assert!(entry.is_some());
        let e = entry.unwrap();
        assert_eq!(e.direction, "credit");
        assert_eq!(e.asset_code, "XLM");
    }

    #[test]
    fn test_map_unknown_operation_returns_none() {
        let op = serde_json::json!({"type": "manage_offer"});
        let entry = map_operation_to_entry(Uuid::new_v4(), "GADDR", &op, "hash", None);
        assert!(entry.is_none());
    }
}
