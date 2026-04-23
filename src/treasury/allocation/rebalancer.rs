/// Rebalancing Engine — Transfer Order Generation
///
/// Generates Transfer Orders when:
///   a) A custodian's concentration exceeds its limit (breach trigger)
///   b) A custodian's risk rating is downgraded below acceptable threshold
///
/// Strategy:
///   - Source: the over-concentrated / downgraded custodian
///   - Destination: the active custodian with the most headroom (lowest
///     concentration relative to its limit), preferring same or lower liquidity tier
///   - Amount: minimum needed to bring source back to (limit - 200 bps) buffer
use super::repository::AllocationRepository;
use super::types::*;
use std::sync::Arc;
use tracing::{info, warn};
use uuid::Uuid;

pub struct RebalancingEngine {
    repo: Arc<AllocationRepository>,
}

impl RebalancingEngine {
    pub fn new(repo: Arc<AllocationRepository>) -> Self {
        Self { repo }
    }

    /// Generate a transfer order triggered by a concentration breach.
    pub async fn generate_for_breach(
        &self,
        snapshot: &ConcentrationSnapshot,
        custodian: &CustodianInstitution,
        alert_id: Uuid,
        balances: &[(Uuid, i64)],
        custodians: &[CustodianInstitution],
    ) -> Result<Option<TransferOrder>, String> {
        let total_kobo: i64 = balances.iter().map(|(_, b)| b).sum();
        if total_kobo == 0 {
            return Ok(None);
        }

        let source_balance = balances
            .iter()
            .find(|(id, _)| *id == custodian.id)
            .map(|(_, b)| *b)
            .unwrap_or(0);

        // Target concentration: limit minus 200 bps safety buffer
        let target_bps = (custodian.max_concentration_bps - 200).max(0);
        let target_balance = (total_kobo as f64 * target_bps as f64 / 10_000.0) as i64;
        let transfer_amount = source_balance - target_balance;

        if transfer_amount <= 0 {
            warn!(
                custodian = %custodian.public_alias,
                "Breach detected but computed transfer amount is non-positive — skipping"
            );
            return Ok(None);
        }

        // Find best destination: most headroom, same or lower liquidity tier
        let destination = self.find_best_destination(
            custodian.id,
            custodian.liquidity_tier,
            transfer_amount,
            total_kobo,
            balances,
            custodians,
        );

        let Some(dest) = destination else {
            warn!(
                custodian = %custodian.public_alias,
                "No suitable destination found for rebalancing"
            );
            return Ok(None);
        };

        let dest_balance = balances
            .iter()
            .find(|(id, _)| *id == dest.id)
            .map(|(_, b)| *b)
            .unwrap_or(0);

        let projected_from_bps =
            ((target_balance as f64 / total_kobo as f64) * 10_000.0).round() as i32;
        let projected_to_bps = (((dest_balance + transfer_amount) as f64 / total_kobo as f64)
            * 10_000.0)
            .round() as i32;

        let rationale = format!(
            "Concentration breach: {} at {:.2}% (limit {:.2}%). \
             Transfer ₦{:.2} to {} to restore compliance. \
             Projected post-transfer: {:.2}% → {:.2}%.",
            custodian.public_alias,
            snapshot.concentration_bps as f64 / 100.0,
            custodian.max_concentration_bps as f64 / 100.0,
            transfer_amount as f64 / 100.0,
            dest.public_alias,
            snapshot.concentration_bps as f64 / 100.0,
            projected_from_bps as f64 / 100.0,
        );

        let order = self
            .repo
            .insert_transfer_order(
                custodian.id,
                dest.id,
                transfer_amount,
                TransferOrderTrigger::ConcentrationBreach,
                Some(alert_id),
                &rationale,
                Some(projected_from_bps),
                Some(projected_to_bps),
                "allocation_engine",
            )
            .await
            .map_err(|e| format!("Failed to insert transfer order: {e}"))?;

        self.repo
            .log_transfer_event(
                order.id,
                "allocation_engine",
                "transfer_order.created",
                None,
                Some(TransferOrderStatus::PendingApproval),
                serde_json::json!({
                    "trigger": "concentration_breach",
                    "alert_id": alert_id,
                    "source_concentration_bps": snapshot.concentration_bps,
                    "transfer_amount_kobo": transfer_amount,
                }),
            )
            .await
            .map_err(|e| format!("Failed to log transfer event: {e}"))?;

        info!(
            order_id = %order.id,
            from = %custodian.public_alias,
            to = %dest.public_alias,
            amount_ngn = transfer_amount as f64 / 100.0,
            "Transfer order generated for concentration breach"
        );

        Ok(Some(order))
    }

    /// Generate transfer orders triggered by a risk rating downgrade.
    /// Moves the full balance out of the downgraded custodian.
    pub async fn generate_for_downgrade(
        &self,
        custodian: &CustodianInstitution,
        balances: &[(Uuid, i64)],
        custodians: &[CustodianInstitution],
    ) -> Result<Vec<TransferOrder>, String> {
        let total_kobo: i64 = balances.iter().map(|(_, b)| b).sum();
        let source_balance = balances
            .iter()
            .find(|(id, _)| *id == custodian.id)
            .map(|(_, b)| *b)
            .unwrap_or(0);

        if source_balance == 0 {
            return Ok(vec![]);
        }

        // Distribute across multiple destinations to avoid creating new breaches
        let destinations = self.find_multiple_destinations(
            custodian.id,
            custodian.liquidity_tier,
            source_balance,
            total_kobo,
            balances,
            custodians,
        );

        if destinations.is_empty() {
            warn!(
                custodian = %custodian.public_alias,
                "No destinations available for downgrade rebalancing"
            );
            return Ok(vec![]);
        }

        let mut orders = Vec::new();
        let per_dest = source_balance / destinations.len() as i64;
        let remainder = source_balance % destinations.len() as i64;

        for (i, dest) in destinations.iter().enumerate() {
            let amount = if i == 0 { per_dest + remainder } else { per_dest };
            if amount <= 0 {
                continue;
            }

            let dest_balance = balances
                .iter()
                .find(|(id, _)| *id == dest.id)
                .map(|(_, b)| *b)
                .unwrap_or(0);

            let projected_to_bps = (((dest_balance + amount) as f64 / total_kobo as f64)
                * 10_000.0)
                .round() as i32;

            let rationale = format!(
                "Risk rating downgrade: {} rated {:?}. \
                 Emergency transfer of ₦{:.2} to {} to reduce exposure.",
                custodian.public_alias,
                custodian.risk_rating,
                amount as f64 / 100.0,
                dest.public_alias,
            );

            let order = self
                .repo
                .insert_transfer_order(
                    custodian.id,
                    dest.id,
                    amount,
                    TransferOrderTrigger::RiskRatingDowngrade,
                    None,
                    &rationale,
                    Some(0), // source will be drained
                    Some(projected_to_bps),
                    "allocation_engine",
                )
                .await
                .map_err(|e| format!("Failed to insert transfer order: {e}"))?;

            self.repo
                .log_transfer_event(
                    order.id,
                    "allocation_engine",
                    "transfer_order.created",
                    None,
                    Some(TransferOrderStatus::PendingApproval),
                    serde_json::json!({
                        "trigger": "risk_rating_downgrade",
                        "new_rating": format!("{:?}", custodian.risk_rating),
                        "amount_kobo": amount,
                    }),
                )
                .await
                .map_err(|e| format!("Failed to log transfer event: {e}"))?;

            orders.push(order);
        }

        info!(
            custodian = %custodian.public_alias,
            orders_created = orders.len(),
            "Transfer orders generated for risk rating downgrade"
        );

        Ok(orders)
    }

    // ── Destination selection helpers ─────────────────────────────────────────

    /// Find the single best destination: most headroom, same or lower tier.
    fn find_best_destination<'a>(
        &self,
        exclude_id: Uuid,
        source_tier: i16,
        transfer_amount: i64,
        total_kobo: i64,
        balances: &[(Uuid, i64)],
        custodians: &'a [CustodianInstitution],
    ) -> Option<&'a CustodianInstitution> {
        custodians
            .iter()
            .filter(|c| {
                c.id != exclude_id
                    && c.is_active
                    && c.liquidity_tier <= source_tier
            })
            .filter(|c| {
                // Ensure the transfer won't breach the destination's limit
                let dest_balance = balances
                    .iter()
                    .find(|(id, _)| *id == c.id)
                    .map(|(_, b)| *b)
                    .unwrap_or(0);
                let new_bps = ((dest_balance + transfer_amount) as f64 / total_kobo as f64
                    * 10_000.0) as i32;
                new_bps <= c.max_concentration_bps
            })
            .max_by_key(|c| {
                // Headroom = max_concentration_bps - current_concentration_bps
                let dest_balance = balances
                    .iter()
                    .find(|(id, _)| *id == c.id)
                    .map(|(_, b)| *b)
                    .unwrap_or(0);
                let current_bps =
                    (dest_balance as f64 / total_kobo as f64 * 10_000.0) as i32;
                c.max_concentration_bps - current_bps
            })
    }

    /// Find up to 3 destinations for distributing a large balance.
    fn find_multiple_destinations<'a>(
        &self,
        exclude_id: Uuid,
        source_tier: i16,
        _total_transfer: i64,
        total_kobo: i64,
        balances: &[(Uuid, i64)],
        custodians: &'a [CustodianInstitution],
    ) -> Vec<&'a CustodianInstitution> {
        let mut candidates: Vec<&CustodianInstitution> = custodians
            .iter()
            .filter(|c| c.id != exclude_id && c.is_active && c.liquidity_tier <= source_tier)
            .collect();

        // Sort by headroom descending
        candidates.sort_by(|a, b| {
            let headroom = |c: &CustodianInstitution| {
                let bal = balances
                    .iter()
                    .find(|(id, _)| *id == c.id)
                    .map(|(_, b)| *b)
                    .unwrap_or(0);
                let bps = (bal as f64 / total_kobo as f64 * 10_000.0) as i32;
                c.max_concentration_bps - bps
            };
            headroom(b).cmp(&headroom(a))
        });

        candidates.into_iter().take(3).collect()
    }
}
