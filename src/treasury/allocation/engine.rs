/// Smart Treasury Allocation Engine — Core Logic
///
/// Responsibilities:
///   1. Compute concentration % per custodian after each balance update
///   2. Detect breaches and fire alerts
///   3. Calculate daily RWA across all reserve holdings
///   4. Verify PoR: sum(custodian balances) == on-chain cNGN supply
///   5. Trigger rebalancing recommendations on breach or rating downgrade
use super::alerts::ConcentrationAlertService;
use super::rebalancer::RebalancingEngine;
use super::repository::AllocationRepository;
use super::types::*;
use crate::audit::models::{AuditActorType, AuditEventCategory, AuditOutcome, PendingAuditEntry};
use crate::audit::writer::AuditWriter;
use chrono::{NaiveDate, Utc};
use sqlx::PgPool;
use std::sync::Arc;
use tracing::{error, info, warn};
use uuid::Uuid;

/// Tolerance for PoR mismatch (0.01% of total supply in kobo).
const POR_TOLERANCE_BPS: i64 = 1; // 0.01%

pub struct AllocationEngine {
    repo: Arc<AllocationRepository>,
    alert_svc: ConcentrationAlertService,
    rebalancer: RebalancingEngine,
    audit: Option<AuditWriter>,
}

impl AllocationEngine {
    pub fn new(db: PgPool, audit: Option<AuditWriter>) -> Self {
        let repo = Arc::new(AllocationRepository::new(db));
        let alert_svc = ConcentrationAlertService::new(Arc::clone(&repo));
        let rebalancer = RebalancingEngine::new(Arc::clone(&repo));
        Self { repo, alert_svc, rebalancer, audit }
    }

    // ── Public API ────────────────────────────────────────────────────────────

    /// Record a new balance snapshot for a custodian, then run the full
    /// concentration check + alert + rebalance pipeline.
    pub async fn record_and_evaluate(
        &self,
        req: RecordAllocationRequest,
        operator_id: &str,
    ) -> Result<ConcentrationSnapshot, String> {
        // 1. Persist the allocation
        let _alloc = self
            .repo
            .record_allocation(
                req.custodian_id,
                req.balance_kobo,
                req.source.as_deref().unwrap_or("manual_entry"),
                req.statement_hash.as_deref(),
                req.notes.as_deref(),
            )
            .await
            .map_err(|e| format!("Failed to record allocation: {e}"))?;

        // 2. Recompute concentrations for all custodians
        let snapshot = self.recompute_concentrations(req.custodian_id).await?;

        // 3. Refresh public materialised view
        if let Err(e) = self.repo.refresh_public_dashboard().await {
            warn!(error = %e, "Failed to refresh public dashboard view");
        }

        // 4. Audit log
        self.write_audit(
            "treasury.allocation.recorded",
            AuditEventCategory::FinancialTransaction,
            operator_id,
            &format!("custodian:{}", req.custodian_id),
            AuditOutcome::Success,
            None,
        )
        .await;

        Ok(snapshot)
    }

    /// Recompute concentration for a specific custodian and evaluate alerts.
    async fn recompute_concentrations(
        &self,
        target_custodian_id: Uuid,
    ) -> Result<ConcentrationSnapshot, String> {
        let custodians = self
            .repo
            .list_active_custodians()
            .await
            .map_err(|e| format!("Failed to list custodians: {e}"))?;

        let balances = self
            .repo
            .latest_balances()
            .await
            .map_err(|e| format!("Failed to fetch balances: {e}"))?;

        let total_reserves_kobo: i64 = balances.iter().map(|(_, b)| b).sum();

        let mut target_snapshot = None;

        for custodian in &custodians {
            let balance_kobo = balances
                .iter()
                .find(|(id, _)| *id == custodian.id)
                .map(|(_, b)| *b)
                .unwrap_or(0);

            let concentration_bps = if total_reserves_kobo > 0 {
                ((balance_kobo as f64 / total_reserves_kobo as f64) * 10_000.0).round() as i32
            } else {
                0
            };

            let snapshot = self
                .repo
                .insert_concentration_snapshot(
                    custodian.id,
                    balance_kobo,
                    total_reserves_kobo,
                    concentration_bps,
                    custodian.max_concentration_bps,
                    custodian.liquidity_tier,
                )
                .await
                .map_err(|e| format!("Failed to insert concentration snapshot: {e}"))?;

            // Evaluate alert for this custodian
            if let Some(alert) = self.alert_svc.evaluate(&snapshot, custodian).await {
                // Auto-generate rebalancing recommendation on breach
                if let Err(e) = self
                    .rebalancer
                    .generate_for_breach(&snapshot, custodian, alert.id, &balances, &custodians)
                    .await
                {
                    warn!(error = %e, "Failed to generate rebalance recommendation");
                }
            }

            if custodian.id == target_custodian_id {
                target_snapshot = Some(snapshot);
            }
        }

        target_snapshot.ok_or_else(|| "Target custodian not found".to_string())
    }

    /// Build the internal allocation monitor dashboard.
    pub async fn allocation_monitor(&self) -> Result<AllocationMonitorResponse, String> {
        let custodians = self
            .repo
            .list_active_custodians()
            .await
            .map_err(|e| format!("Failed to list custodians: {e}"))?;

        let snapshots = self
            .repo
            .latest_concentration_snapshots()
            .await
            .map_err(|e| format!("Failed to fetch snapshots: {e}"))?;

        let rwa = self
            .repo
            .latest_rwa_snapshot()
            .await
            .map_err(|e| format!("Failed to fetch RWA: {e}"))?;

        let total_reserves_kobo: i64 = snapshots.iter().map(|s| s.balance_kobo).sum();
        let onchain_supply_kobo = rwa.as_ref().map(|r| r.onchain_supply_kobo).unwrap_or(0);

        let peg_coverage_pct = if onchain_supply_kobo > 0 {
            (total_reserves_kobo as f64 / onchain_supply_kobo as f64) * 100.0
        } else {
            0.0
        };

        let mut entries = Vec::with_capacity(custodians.len());
        let mut active_breaches = 0usize;

        for custodian in &custodians {
            let snap = snapshots.iter().find(|s| s.custodian_id == custodian.id);
            let (balance_kobo, concentration_bps, is_breached, snapshot_at) = snap
                .map(|s| (s.balance_kobo, s.concentration_bps, s.is_breached, s.snapshot_at))
                .unwrap_or((0, 0, false, Utc::now()));

            if is_breached {
                active_breaches += 1;
            }

            entries.push(AllocationMonitorEntry {
                custodian_id: custodian.id,
                public_alias: custodian.public_alias.clone(),
                internal_name: custodian.internal_name.clone(),
                institution_type: custodian.institution_type,
                liquidity_tier: custodian.liquidity_tier,
                balance_kobo,
                balance_ngn: balance_kobo as f64 / 100.0,
                concentration_bps,
                concentration_pct: concentration_bps as f64 / 100.0,
                max_concentration_bps: custodian.max_concentration_bps,
                is_breached,
                risk_rating: custodian.risk_rating,
                snapshot_at,
            });
        }

        Ok(AllocationMonitorResponse {
            entries,
            total_reserves_kobo,
            total_reserves_ngn: total_reserves_kobo as f64 / 100.0,
            onchain_supply_kobo,
            peg_coverage_pct,
            active_breaches,
            generated_at: Utc::now(),
        })
    }

    /// Daily RWA calculation.
    /// RWA = Σ (balance_kobo × risk_weight_bps / 10_000) per institution type.
    pub async fn calculate_daily_rwa(
        &self,
        onchain_supply_kobo: i64,
        date: NaiveDate,
    ) -> Result<RwaDailySnapshot, String> {
        let custodians = self
            .repo
            .list_active_custodians()
            .await
            .map_err(|e| format!("Failed to list custodians: {e}"))?;

        let balances = self
            .repo
            .latest_balances()
            .await
            .map_err(|e| format!("Failed to fetch balances: {e}"))?;

        let mut total_reserves_kobo: i64 = 0;
        let mut total_rwa_kobo: i64 = 0;
        let mut tier1_kobo: i64 = 0;
        let mut tier2_kobo: i64 = 0;
        let mut tier3_kobo: i64 = 0;
        let mut breakdown: std::collections::HashMap<String, serde_json::Value> =
            std::collections::HashMap::new();

        for custodian in &custodians {
            let balance = balances
                .iter()
                .find(|(id, _)| *id == custodian.id)
                .map(|(_, b)| *b)
                .unwrap_or(0);

            let rw_bps = custodian.institution_type.risk_weight_bps() as i64;
            let rwa = (balance * rw_bps) / 10_000;

            total_reserves_kobo += balance;
            total_rwa_kobo += rwa;

            match custodian.liquidity_tier {
                1 => tier1_kobo += balance,
                2 => tier2_kobo += balance,
                3 => tier3_kobo += balance,
                _ => {}
            }

            breakdown.insert(
                custodian.public_alias.clone(),
                serde_json::json!({
                    "balance_kobo": balance,
                    "rwa_kobo": rwa,
                    "risk_weight_bps": rw_bps,
                    "institution_type": format!("{:?}", custodian.institution_type),
                    "liquidity_tier": custodian.liquidity_tier,
                }),
            );
        }

        let peg_coverage_bps = if onchain_supply_kobo > 0 {
            ((total_reserves_kobo as f64 / onchain_supply_kobo as f64) * 10_000.0).round() as i32
        } else {
            0
        };

        // PoR integrity check
        self.verify_por(total_reserves_kobo, onchain_supply_kobo);

        let snapshot = self
            .repo
            .upsert_rwa_snapshot(
                date,
                total_reserves_kobo,
                total_rwa_kobo,
                onchain_supply_kobo,
                peg_coverage_bps,
                tier1_kobo,
                tier2_kobo,
                tier3_kobo,
                serde_json::to_value(breakdown).unwrap_or_default(),
            )
            .await
            .map_err(|e| format!("Failed to upsert RWA snapshot: {e}"))?;

        info!(
            date = %date,
            total_reserves_ngn = total_reserves_kobo as f64 / 100.0,
            total_rwa_ngn = total_rwa_kobo as f64 / 100.0,
            peg_coverage_bps,
            "Daily RWA calculation complete"
        );

        Ok(snapshot)
    }

    /// Proof-of-Reserves integrity check.
    /// Verifies that sum(custodian balances) ≈ on-chain cNGN supply.
    pub fn verify_por(&self, total_reserves_kobo: i64, onchain_supply_kobo: i64) {
        if onchain_supply_kobo == 0 {
            warn!("PoR check skipped: on-chain supply is zero");
            return;
        }

        let diff = (total_reserves_kobo - onchain_supply_kobo).abs();
        let tolerance = (onchain_supply_kobo * POR_TOLERANCE_BPS) / 10_000;

        if diff > tolerance {
            error!(
                reserves_kobo = total_reserves_kobo,
                supply_kobo = onchain_supply_kobo,
                diff_kobo = diff,
                tolerance_kobo = tolerance,
                "🚨 PoR MISMATCH: reserve sum does not match on-chain supply"
            );
        } else {
            info!(
                reserves_kobo = total_reserves_kobo,
                supply_kobo = onchain_supply_kobo,
                "PoR check passed: reserves match on-chain supply within tolerance"
            );
        }
    }

    /// Handle a risk rating downgrade — trigger rebalancing if required.
    pub async fn handle_rating_downgrade(
        &self,
        custodian_id: Uuid,
        new_rating: RiskRating,
        operator_id: &str,
    ) -> Result<Vec<TransferOrder>, String> {
        self.repo
            .update_risk_rating(custodian_id, new_rating)
            .await
            .map_err(|e| format!("Failed to update risk rating: {e}"))?;

        self.write_audit(
            "treasury.custodian.rating_downgraded",
            AuditEventCategory::SystemEvent,
            operator_id,
            &format!("custodian:{custodian_id}"),
            AuditOutcome::Success,
            None,
        )
        .await;

        if !new_rating.requires_rebalance() {
            return Ok(vec![]);
        }

        warn!(
            custodian_id = %custodian_id,
            rating = ?new_rating,
            "Risk rating downgrade requires rebalancing"
        );

        let custodian = self
            .repo
            .get_custodian(custodian_id)
            .await
            .map_err(|e| format!("Custodian not found: {e}"))?;

        let custodians = self
            .repo
            .list_active_custodians()
            .await
            .map_err(|e| format!("Failed to list custodians: {e}"))?;

        let balances = self
            .repo
            .latest_balances()
            .await
            .map_err(|e| format!("Failed to fetch balances: {e}"))?;

        let orders = self
            .rebalancer
            .generate_for_downgrade(&custodian, &balances, &custodians)
            .await?;

        Ok(orders)
    }

    // ── Handler-facing accessors ──────────────────────────────────────────────

    /// List unresolved concentration alerts.
    pub async fn unresolved_alerts(&self) -> Result<Vec<ConcentrationAlert>, String> {
        self.repo
            .list_unresolved_alerts()
            .await
            .map_err(|e| format!("Failed to fetch alerts: {e}"))
    }

    /// Latest RWA daily snapshot.
    pub async fn latest_rwa(&self) -> Result<Option<RwaDailySnapshot>, String> {
        self.repo
            .latest_rwa_snapshot()
            .await
            .map_err(|e| format!("Failed to fetch RWA snapshot: {e}"))
    }

    /// List transfer orders with optional status filter and pagination.
    pub async fn list_orders(
        &self,
        status: Option<TransferOrderStatus>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<TransferOrder>, String> {
        self.repo
            .list_transfer_orders(status, limit, offset)
            .await
            .map_err(|e| format!("Failed to list transfer orders: {e}"))
    }

    /// Fetch a single transfer order by ID.
    pub async fn get_order(&self, id: Uuid) -> Result<TransferOrder, String> {
        self.repo
            .get_transfer_order(id)
            .await
            .map_err(|e| format!("Transfer order not found: {e}"))
    }

    /// Approve or reject a transfer order.
    pub async fn decide_order(
        &self,
        id: Uuid,
        req: TransferOrderDecisionRequest,
        operator_id: &str,
    ) -> Result<TransferOrder, String> {
        let order = self.get_order(id).await?;

        if order.status != TransferOrderStatus::PendingApproval {
            return Err(format!(
                "Order is in {:?} state — only pending_approval orders can be decided",
                order.status
            ));
        }

        let (new_status, approved_by, rejection_reason) = match req.action.as_str() {
            "approve" => (TransferOrderStatus::Approved, Some(operator_id), None),
            "reject" => (
                TransferOrderStatus::Rejected,
                None,
                Some(req.rejection_reason.as_deref().unwrap_or("No reason provided")),
            ),
            other => return Err(format!("Unknown action '{other}' — use 'approve' or 'reject'")),
        };

        let updated = self
            .repo
            .update_transfer_order_status(id, new_status, approved_by, rejection_reason, None)
            .await
            .map_err(|e| format!("Failed to update order status: {e}"))?;

        self.repo
            .log_transfer_event(
                id,
                operator_id,
                &format!("transfer_order.{}", req.action),
                Some(TransferOrderStatus::PendingApproval),
                Some(new_status),
                serde_json::json!({ "operator": operator_id }),
            )
            .await
            .map_err(|e| format!("Failed to log audit event: {e}"))?;

        self.write_audit(
            &format!("treasury.transfer_order.{}", req.action),
            AuditEventCategory::FinancialTransaction,
            operator_id,
            &format!("transfer_order:{id}"),
            AuditOutcome::Success,
            None,
        )
        .await;

        Ok(updated)
    }

    /// Mark an approved/executing transfer order as completed.
    pub async fn complete_order(
        &self,
        id: Uuid,
        req: CompleteTransferRequest,
        operator_id: &str,
    ) -> Result<TransferOrder, String> {
        let order = self.get_order(id).await?;

        if !matches!(
            order.status,
            TransferOrderStatus::Approved | TransferOrderStatus::Executing
        ) {
            return Err(format!(
                "Order is in {:?} state — only approved/executing orders can be completed",
                order.status
            ));
        }

        let updated = self
            .repo
            .update_transfer_order_status(
                id,
                TransferOrderStatus::Completed,
                None,
                None,
                Some(&req.bank_reference),
            )
            .await
            .map_err(|e| format!("Failed to complete order: {e}"))?;

        self.repo
            .log_transfer_event(
                id,
                operator_id,
                "transfer_order.completed",
                Some(order.status),
                Some(TransferOrderStatus::Completed),
                serde_json::json!({ "bank_reference": req.bank_reference }),
            )
            .await
            .map_err(|e| format!("Failed to log audit event: {e}"))?;

        // After completion, re-run concentration checks to resolve any open alerts
        if let Err(e) = self.recompute_concentrations(order.from_custodian_id).await {
            tracing::warn!(error = %e, "Post-completion concentration recheck failed");
        }

        Ok(updated)
    }

    /// Public transparency dashboard — sanitised, no internal names or account refs.
    pub async fn public_dashboard(&self) -> Result<PublicReserveResponse, String> {
        let rows = self
            .repo
            .public_dashboard_rows()
            .await
            .map_err(|e| format!("Failed to fetch public dashboard: {e}"))?;

        let rwa = self
            .repo
            .latest_rwa_snapshot()
            .await
            .map_err(|e| format!("Failed to fetch RWA: {e}"))?;

        let total_kobo = rwa.as_ref().map(|r| r.total_reserves_kobo).unwrap_or(0);
        let onchain_supply_kobo = rwa.as_ref().map(|r| r.onchain_supply_kobo).unwrap_or(0);

        let peg_coverage_bps = rwa.as_ref().map(|r| r.peg_coverage_bps).unwrap_or(0);
        let peg_status = if peg_coverage_bps >= 10_000 {
            "fully_backed"
        } else if peg_coverage_bps >= 9_500 {
            "adequately_backed"
        } else {
            "under_review"
        }
        .to_string();

        let (tier1_kobo, tier2_kobo, tier3_kobo) = rwa
            .as_ref()
            .map(|r| (r.tier1_kobo, r.tier2_kobo, r.tier3_kobo))
            .unwrap_or((0, 0, 0));

        let to_pct = |kobo: i64| -> f64 {
            if total_kobo == 0 { 0.0 } else { kobo as f64 / total_kobo as f64 * 100.0 }
        };

        let last_updated = rows
            .iter()
            .map(|r| r.snapshot_at)
            .max()
            .unwrap_or_else(Utc::now);

        let holdings = rows
            .into_iter()
            .map(|r| PublicDashboardEntry {
                institution_alias: r.institution_alias,
                institution_type: r.institution_type,
                liquidity_tier: r.liquidity_tier,
                liquidity_tier_label: LiquidityTier::from_i16(r.liquidity_tier)
                    .map(|t| t.label().to_string())
                    .unwrap_or_default(),
                concentration_pct: r
                    .concentration_pct
                    .map(|d| {
                        use std::str::FromStr;
                        f64::from_str(&d.to_string()).unwrap_or(0.0)
                    })
                    .unwrap_or(0.0),
                max_concentration_pct: r
                    .max_concentration_pct
                    .map(|d| {
                        use std::str::FromStr;
                        f64::from_str(&d.to_string()).unwrap_or(0.0)
                    })
                    .unwrap_or(0.0),
                is_breached: r.is_breached,
                snapshot_at: r.snapshot_at,
            })
            .collect::<Vec<_>>();

        let total_institutions = holdings.len();

        Ok(PublicReserveResponse {
            holdings,
            total_institutions,
            tier1_pct: to_pct(tier1_kobo),
            tier2_pct: to_pct(tier2_kobo),
            tier3_pct: to_pct(tier3_kobo),
            peg_status,
            last_updated,
        })
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    async fn write_audit(
        &self,
        event_type: &str,
        category: AuditEventCategory,
        actor_id: &str,
        resource_id: &str,
        outcome: AuditOutcome,
        failure_reason: Option<String>,
    ) {
        if let Some(audit) = &self.audit {
            audit
                .write(PendingAuditEntry {
                    event_type: event_type.to_string(),
                    event_category: category,
                    actor_type: AuditActorType::Admin,
                    actor_id: Some(actor_id.to_string()),
                    actor_ip: None,
                    actor_consumer_type: Some("treasury".to_string()),
                    session_id: None,
                    target_resource_type: Some("treasury_allocation".to_string()),
                    target_resource_id: Some(resource_id.to_string()),
                    request_method: "POST".to_string(),
                    request_path: "/treasury/allocation".to_string(),
                    request_body_hash: None,
                    response_status: if outcome == AuditOutcome::Success { 200 } else { 500 },
                    response_latency_ms: 0,
                    outcome,
                    failure_reason,
                    environment: std::env::var("APP_ENV")
                        .unwrap_or_else(|_| "production".to_string()),
                })
                .await;
        }
    }
}
