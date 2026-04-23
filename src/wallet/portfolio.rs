use crate::chains::stellar::client::StellarClient;
use crate::wallet::repository::{InsertPortfolioSnapshot, PortfolioRepository};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use sqlx::types::BigDecimal;
use std::collections::HashMap;
use std::str::FromStr;
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
pub struct AssetHolding {
    pub asset_code: String,
    pub asset_issuer: Option<String>,
    pub balance: String,
    pub fiat_value: Option<String>,
    pub fiat_currency: String,
    pub trustline_active: bool,
    pub platform_supported: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PortfolioBalances {
    pub assets: Vec<AssetHolding>,
    pub total_fiat_value: String,
    pub fiat_currency: String,
    pub per_wallet: HashMap<String, Vec<AssetHolding>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PortfolioPerformance {
    pub period_days: i64,
    pub start_value: String,
    pub end_value: String,
    pub net_change: String,
    pub pct_change: f64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AssetAllocation {
    pub asset_code: String,
    pub fiat_value: String,
    pub percentage: f64,
    pub high_concentration: bool,
}

const PLATFORM_SUPPORTED_ASSETS: &[&str] = &["cNGN", "XLM", "USDC"];
const HIGH_CONCENTRATION_THRESHOLD: f64 = 80.0;

pub struct PortfolioService {
    stellar_client: StellarClient,
    repo: PortfolioRepository,
}

impl PortfolioService {
    pub fn new(stellar_client: StellarClient, repo: PortfolioRepository) -> Self {
        Self { stellar_client, repo }
    }

    /// Aggregate balances across all wallet addresses for a user.
    pub async fn aggregate_balances(
        &self,
        wallet_addresses: &[(Uuid, String)],
        fiat_currency: &str,
        exchange_rates: &HashMap<String, f64>,
    ) -> Result<PortfolioBalances> {
        let mut totals: HashMap<String, (Option<String>, BigDecimal)> = HashMap::new();
        let mut per_wallet: HashMap<String, Vec<AssetHolding>> = HashMap::new();

        for (wallet_id, address) in wallet_addresses {
            let account = match self.stellar_client.get_account(address).await {
                Ok(a) => a,
                Err(_) => continue,
            };

            let mut wallet_holdings = Vec::new();
            for balance in &account.balances {
                let code = if balance.asset_type == "native" {
                    "XLM".to_string()
                } else {
                    balance.asset_code.clone().unwrap_or_default()
                };
                let issuer = balance.asset_issuer.clone();
                let bal: BigDecimal = balance.balance.parse().unwrap_or_default();
                let rate = exchange_rates.get(&code).copied().unwrap_or(0.0);
                let fiat_val = if rate > 0.0 {
                    let v: f64 = bal.to_string().parse().unwrap_or(0.0) * rate;
                    Some(format!("{:.2}", v))
                } else {
                    None
                };

                wallet_holdings.push(AssetHolding {
                    asset_code: code.clone(),
                    asset_issuer: issuer.clone(),
                    balance: balance.balance.clone(),
                    fiat_value: fiat_val,
                    fiat_currency: fiat_currency.to_string(),
                    trustline_active: balance.asset_type != "native",
                    platform_supported: PLATFORM_SUPPORTED_ASSETS.contains(&code.as_str()),
                });

                let entry = totals.entry(code).or_insert((issuer, BigDecimal::from(0)));
                entry.1 += &bal;
            }
            per_wallet.insert(wallet_id.to_string(), wallet_holdings);
        }

        let mut assets = Vec::new();
        let mut total_fiat = 0.0f64;
        for (code, (issuer, bal)) in &totals {
            let rate = exchange_rates.get(code.as_str()).copied().unwrap_or(0.0);
            let bal_f: f64 = bal.to_string().parse().unwrap_or(0.0);
            let fiat_val = bal_f * rate;
            total_fiat += fiat_val;
            assets.push(AssetHolding {
                asset_code: code.clone(),
                asset_issuer: issuer.clone(),
                balance: bal.to_string(),
                fiat_value: Some(format!("{:.2}", fiat_val)),
                fiat_currency: fiat_currency.to_string(),
                trustline_active: code != "XLM",
                platform_supported: PLATFORM_SUPPORTED_ASSETS.contains(&code.as_str()),
            });
        }

        Ok(PortfolioBalances {
            assets,
            total_fiat_value: format!("{:.2}", total_fiat),
            fiat_currency: fiat_currency.to_string(),
            per_wallet,
        })
    }

    /// Compute asset allocation percentages.
    pub fn compute_allocation(balances: &PortfolioBalances) -> Vec<AssetAllocation> {
        let total: f64 = balances.total_fiat_value.parse().unwrap_or(0.0);
        balances
            .assets
            .iter()
            .map(|a| {
                let val: f64 = a.fiat_value.as_deref().unwrap_or("0").parse().unwrap_or(0.0);
                let pct = if total > 0.0 { val / total * 100.0 } else { 0.0 };
                AssetAllocation {
                    asset_code: a.asset_code.clone(),
                    fiat_value: a.fiat_value.clone().unwrap_or_default(),
                    percentage: pct,
                    high_concentration: a.asset_code != "XLM" && pct > HIGH_CONCENTRATION_THRESHOLD,
                }
            })
            .collect()
    }

    /// Compute performance between two snapshots.
    pub fn compute_performance(
        start_value: &str,
        end_value: &str,
        period_days: i64,
    ) -> PortfolioPerformance {
        let start: f64 = start_value.parse().unwrap_or(0.0);
        let end: f64 = end_value.parse().unwrap_or(0.0);
        let net = end - start;
        let pct = if start > 0.0 { net / start * 100.0 } else { 0.0 };
        PortfolioPerformance {
            period_days,
            start_value: start_value.to_string(),
            end_value: end_value.to_string(),
            net_change: format!("{:.2}", net),
            pct_change: pct,
        }
    }

    /// Persist a daily portfolio snapshot.
    pub async fn save_snapshot(
        &self,
        user_id: Uuid,
        balances: &PortfolioBalances,
        exchange_rates: &HashMap<String, f64>,
    ) -> Result<()> {
        let asset_breakdown = serde_json::to_value(&balances.assets)?;
        let rates = serde_json::to_value(exchange_rates)?;
        let total: BigDecimal = balances.total_fiat_value.parse().unwrap_or_default();
        self.repo
            .save_snapshot(&InsertPortfolioSnapshot {
                user_account_id: user_id,
                total_value_fiat: total,
                fiat_currency: balances.fiat_currency.clone(),
                asset_breakdown,
                exchange_rates_applied: rates,
            })
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_allocation() {
        let balances = PortfolioBalances {
            assets: vec![
                AssetHolding {
                    asset_code: "cNGN".to_string(),
                    asset_issuer: None,
                    balance: "1000".to_string(),
                    fiat_value: Some("900.00".to_string()),
                    fiat_currency: "NGN".to_string(),
                    trustline_active: true,
                    platform_supported: true,
                },
                AssetHolding {
                    asset_code: "XLM".to_string(),
                    asset_issuer: None,
                    balance: "10".to_string(),
                    fiat_value: Some("100.00".to_string()),
                    fiat_currency: "NGN".to_string(),
                    trustline_active: false,
                    platform_supported: true,
                },
            ],
            total_fiat_value: "1000.00".to_string(),
            fiat_currency: "NGN".to_string(),
            per_wallet: HashMap::new(),
        };
        let alloc = PortfolioService::compute_allocation(&balances);
        assert_eq!(alloc.len(), 2);
        let cngn = alloc.iter().find(|a| a.asset_code == "cNGN").unwrap();
        assert!((cngn.percentage - 90.0).abs() < 0.01);
        assert!(cngn.high_concentration); // >80% non-XLM
    }

    #[test]
    fn test_compute_performance() {
        let perf = PortfolioService::compute_performance("1000.00", "1100.00", 30);
        assert!((perf.pct_change - 10.0).abs() < 0.01);
        assert_eq!(perf.net_change, "100.00");
    }
}
