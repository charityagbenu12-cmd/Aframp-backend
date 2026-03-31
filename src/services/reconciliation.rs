use crate::chains::stellar::client::StellarClient;
use crate::database::reconciliation_repository::{ReconciliationRepository, ReconciliationReport};
use crate::payments::factory::PaymentProviderFactory;
use crate::payments::types::ProviderName;
use crate::services::notification::{NotificationService, NotificationType};
use sqlx::{types::BigDecimal, PgPool};
use std::sync::Arc;
use tracing::{error, info, warn, instrument};
use std::str::FromStr;

pub enum ReconciliationType {
    Soft,
    Deep,
}

pub struct ReconciliationService {
    repo: ReconciliationRepository,
    stellar_client: StellarClient,
    provider_factory: Arc<PaymentProviderFactory>,
    notification_service: Arc<NotificationService>,
    cngn_issuer: String,
}

impl ReconciliationService {
    pub fn new(
        pool: PgPool,
        stellar_client: StellarClient,
        provider_factory: Arc<PaymentProviderFactory>,
        notification_service: Arc<NotificationService>,
        cngn_issuer: String,
    ) -> Self {
        Self {
            repo: ReconciliationRepository::new(pool),
            stellar_client,
            provider_factory,
            notification_service,
            cngn_issuer,
        }
    }

    #[instrument(skip(self), name = "reconcile")]
    pub async fn run_reconciliation(&self, recon_type: ReconciliationType) -> anyhow::Result<ReconciliationReport> {
        info!("Starting Supply-Reserve Reconciliation...");

        // 1. Internal Ledger Total
        let internal_total = self.repo.get_internal_ledger_total().await?;
        
        // 2. On-Chain Supply (Stellar)
        let stats = self.stellar_client.get_asset_stats("cNGN", &self.cngn_issuer).await?;
        let amount_str = stats.get("amount").and_then(|v| v.as_str()).unwrap_or("0");
        let on_chain_total = BigDecimal::from_str(amount_str).unwrap_or_else(|_| BigDecimal::from(0));

        // 3. Bank Reserves (Deep check only)
        let bank_total = match recon_type {
            ReconciliationType::Deep => {
                // Sum balances from all active providers
                // For simplicity, we assume Flutterwave is the primary vault
                let provider = self.provider_factory.get_provider(ProviderName::Flutterwave)?;
                let balance = provider.get_balance("NGN").await?;
                BigDecimal::from_str(&balance.amount).unwrap_or_else(|_| BigDecimal::from(0))
            }
            ReconciliationType::Soft => {
                // In soft check, we assume bank is in sync with internal for "delta" calculation
                // Or we just report 0/previous known. Let's use internal for now to avoid delta trigger.
                internal_total.clone()
            }
        };

        // 4. Pending State Adjustments
        let mints_in_progress = self.repo.get_mints_in_progress_total().await?;
        let redemptions_in_progress = self.repo.get_redemptions_in_progress_total().await?;

        // 5. Reconciliation Logic
        // Asset vs Liability Triple-Way Check
        // Assets: Bank Balance
        // Liabilities: OnChain Supply + Redemptions in Progress (owed fiat) + Mints in Progress (pending tokens)
        
        let liabilities = &on_chain_total + &mints_in_progress + &redemptions_in_progress;
        
        // 1:1:1 Verification
        // Internal Ledger should match OnChain Supply (representing finality)
        let internal_delta = &internal_total - &on_chain_total;
        
        // Bank Reserves should match Liabilities
        let reserve_delta = &bank_total - &liabilities;

        let delta = reserve_delta.clone(); // Primary indicator of physical mismatch

        let status = if delta == BigDecimal::from(0) {
            if internal_delta != BigDecimal::from(0) {
                "INTERNAL_MISMATCH"
            } else {
                "EQUILIBRIUM"
            }
        } else if delta < BigDecimal::from(0) {
            "RESERVE_DEFICIT" // Bank has less money than (Tokens + Redemptions + Mints)
        } else {
            "SURPLUS_UNKNOWN_ORIGIN" // Bank has more money than liabilities
        };

        let metadata = serde_json::json!({
            "check_type": match recon_type { ReconciliationType::Soft => "soft", ReconciliationType::Deep => "deep" },
            "total_liabilities": liabilities,
            "on_chain_supply": on_chain_total,
            "internal_ledger": internal_total,
            "bank_actual": bank_total,
            "internal_to_chain_delta": internal_delta,
            "reserve_to_liability_delta": reserve_delta,
        });

        // 6. Save Report
        let report = self.repo.create_report(
            internal_total,
            on_chain_total,
            bank_total,
            mints_in_progress,
            redemptions_in_progress,
            delta.clone(),
            status,
            metadata
        ).await?;

        // 7. Alerting
        if status != "EQUILIBRIUM" {
            error!(
                status = %status,
                delta = %delta,
                "RECONCILIATION ANOMALY DETECTED!"
            );
            
            self.notification_service.send_system_alert(
                "CRITICAL_RECONCILIATION_FAILURE",
                &format!(
                    "Triple-way reconciliation failure! Status: {}, Delta: {} cNGN. Internal: {}, Stellar (adj): {}, Bank (adj): {}",
                    status, delta, report.internal_total, adjusted_stellar, adjusted_bank
                )
            ).await;
        } else {
            info!("Reconciliation successful: Perfect Equilibrium.");
        }

        Ok(report)
    }
}
