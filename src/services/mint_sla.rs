/// Mint SLA Service — Core Escalation Logic
///
/// Owns the full SLA state machine for stalled mint requests:
///   1. Query all PENDING / PARTIALLY_APPROVED requests with their SLA state
///   2. For each, compute elapsed time and determine the required action
///   3. Execute the action atomically (DB update + audit log + notification)
///   4. Return a cycle summary for observability
///
/// # SLA Thresholds
///   WARNING    : 4 hours  — reminder to Tier-1 approver
///   ESCALATION : 12 hours — notify Tier-2 manager, grant visibility
///   EXPIRATION : 24 hours — mark request EXPIRED, block Stellar submission
///
/// # Idempotency
///   Every action is guarded by `WHERE stage = <expected_stage>` so
///   concurrent or repeated runs cannot double-fire a threshold.
use crate::database::mint_request_repository::MintRequestRepository;
use crate::services::mint_sla_notifier::MintSlaNotifier;
use crate::services::mint_timebound_guard::MintTimeboundGuard;
use chrono::{Duration, Utc};
use serde_json::json;
use sqlx::PgPool;
use std::sync::Arc;
use tracing::{error, info, warn};
use uuid::Uuid;

// ── SLA thresholds ────────────────────────────────────────────────────────────
pub const SLA_WARNING_HOURS: i64 = 4;
pub const SLA_ESCALATION_HOURS: i64 = 12;
pub const SLA_EXPIRATION_HOURS: i64 = 24;

// ── Types ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlaAction {
    None,
    Warn,
    Escalate,
    Expire,
}

impl SlaAction {
    pub fn from_elapsed_hours(hours: i64, current_stage: &str) -> Self {
        match (hours, current_stage) {
            // Already expired — nothing to do
            (_, "expired") | (_, "resolved") => Self::None,
            // Expiration threshold
            (h, _) if h >= SLA_EXPIRATION_HOURS => Self::Expire,
            // Escalation threshold — only if not already escalated/expired
            (h, stage) if h >= SLA_ESCALATION_HOURS && stage != "escalated" => Self::Escalate,
            // Warning threshold — only if still in pending stage
            (h, "pending") if h >= SLA_WARNING_HOURS => Self::Warn,
            _ => Self::None,
        }
    }
}

/// Summary returned after each worker cycle.
#[derive(Debug, Default)]
pub struct SlaCycleSummary {
    pub warned: usize,
    pub escalated: usize,
    pub expired: usize,
    pub resolved: usize,
    pub errors: usize,
}

/// A stalled request row joined with its SLA state.
#[derive(Debug, sqlx::FromRow)]
pub struct StalledRequest {
    pub mint_request_id: Uuid,
    pub status: String,
    pub submitted_by: String,
    pub amount_ngn: bigdecimal::BigDecimal,
    pub approval_tier: i16,
    pub created_at: chrono::DateTime<Utc>,
    pub expires_at: chrono::DateTime<Utc>,
    pub sla_stage: String,
    pub warned_at: Option<chrono::DateTime<Utc>>,
    pub escalated_at: Option<chrono::DateTime<Utc>>,
    pub escalated_to: Option<String>,
}

// ── Service ───────────────────────────────────────────────────────────────────

pub struct MintSlaService {
    db: PgPool,
    repo: Arc<MintRequestRepository>,
    notifier: MintSlaNotifier,
    timebound_guard: MintTimeboundGuard,
}

impl MintSlaService {
    pub fn new(db: PgPool, http: reqwest::Client) -> Self {
        let repo = Arc::new(MintRequestRepository::new(db.clone()));
        let notifier = MintSlaNotifier::new(http);
        let timebound_guard = MintTimeboundGuard::new(db.clone());
        Self { db, repo, notifier, timebound_guard }
    }

    /// Run one full SLA evaluation cycle.
    pub async fn run_cycle(&self, run_id: Uuid) -> Result<SlaCycleSummary, String> {
        let mut summary = SlaCycleSummary::default();
        let now = Utc::now();

        // 0. Detect any Stellar timebound windows that have expired
        match self.timebound_guard.detect_timeouts().await {
            Ok(n) if n > 0 => info!(count = n, "Stellar timeout failures detected and marked"),
            Ok(_) => {}
            Err(e) => error!(error = %e, "Timebound timeout detection failed"),
        }

        // 1. Fetch all stalled requests (PENDING or PARTIALLY_APPROVED)
        //    joined with their SLA state, excluding already-terminal SLA rows.
        let stalled = self
            .fetch_stalled_requests()
            .await
            .map_err(|e| format!("Failed to fetch stalled requests: {e}"))?;

        for req in stalled {
            // Resolve any request that has left the pending state since last run
            if !matches!(req.status.as_str(), "pending_approval" | "partially_approved") {
                if let Err(e) = self.resolve_sla(&req, run_id).await {
                    error!(mint_request_id = %req.mint_request_id, error = %e, "Failed to resolve SLA");
                    summary.errors += 1;
                } else {
                    summary.resolved += 1;
                }
                continue;
            }

            // Auto-expire if past the hard deadline (belt-and-suspenders)
            if now > req.expires_at && req.sla_stage != "expired" {
                if let Err(e) = self.expire_request(&req, run_id).await {
                    error!(mint_request_id = %req.mint_request_id, error = %e, "Failed to expire request");
                    summary.errors += 1;
                } else {
                    summary.expired += 1;
                }
                continue;
            }

            let elapsed_hours = (now - req.created_at).num_hours();
            let action = SlaAction::from_elapsed_hours(elapsed_hours, &req.sla_stage);

            match action {
                SlaAction::None => {}
                SlaAction::Warn => {
                    match self.send_warning(&req, elapsed_hours, run_id).await {
                        Ok(_) => summary.warned += 1,
                        Err(e) => {
                            error!(mint_request_id = %req.mint_request_id, error = %e, "SLA warning failed");
                            summary.errors += 1;
                        }
                    }
                }
                SlaAction::Escalate => {
                    match self.escalate(&req, elapsed_hours, run_id).await {
                        Ok(_) => summary.escalated += 1,
                        Err(e) => {
                            error!(mint_request_id = %req.mint_request_id, error = %e, "SLA escalation failed");
                            summary.errors += 1;
                        }
                    }
                }
                SlaAction::Expire => {
                    match self.expire_request(&req, run_id).await {
                        Ok(_) => summary.expired += 1,
                        Err(e) => {
                            error!(mint_request_id = %req.mint_request_id, error = %e, "SLA expiration failed");
                            summary.errors += 1;
                        }
                    }
                }
            }
        }

        Ok(summary)
    }

    // ── SLA actions ───────────────────────────────────────────────────────────

    /// Send a 4-hour inactivity reminder to the Tier-1 approver.
    async fn send_warning(
        &self,
        req: &StalledRequest,
        elapsed_hours: i64,
        run_id: Uuid,
    ) -> Result<(), String> {
        // Idempotent DB update: only fires if stage is still 'pending'
        let updated = sqlx::query!(
            r#"
            UPDATE mint_sla_state
               SET stage = 'warned', warned_at = NOW(), last_worker_run_id = $2
             WHERE mint_request_id = $1
               AND stage = 'pending'
            "#,
            req.mint_request_id,
            run_id,
        )
        .execute(&self.db)
        .await
        .map_err(|e| format!("DB update failed: {e}"))?;

        if updated.rows_affected() == 0 {
            // Another worker run already fired this — skip silently
            return Ok(());
        }

        // Append to escalation log
        self.log_escalation(
            req.mint_request_id,
            "sla_warning_sent",
            elapsed_hours,
            run_id,
            json!({
                "tier1_approver": req.submitted_by,
                "elapsed_hours": elapsed_hours,
                "amount_ngn": req.amount_ngn.to_string(),
            }),
        )
        .await?;

        // Append to mint audit log
        self.repo
            .append_audit(
                req.mint_request_id,
                "sla_worker",
                None,
                "sla_warning_sent",
                Some(&req.sla_stage),
                Some("warned"),
                json!({ "elapsed_hours": elapsed_hours, "run_id": run_id }),
            )
            .await
            .map_err(|e| format!("Audit log failed: {e}"))?;

        // Dispatch notifications (non-blocking)
        self.notifier
            .send_warning(req, elapsed_hours)
            .await;

        info!(
            mint_request_id = %req.mint_request_id,
            elapsed_hours,
            "SLA warning sent"
        );
        Ok(())
    }

    /// Escalate to Tier-2 manager at 12 hours.
    async fn escalate(
        &self,
        req: &StalledRequest,
        elapsed_hours: i64,
        run_id: Uuid,
    ) -> Result<(), String> {
        let tier2_manager = self.resolve_tier2_manager(req).await;

        let updated = sqlx::query!(
            r#"
            UPDATE mint_sla_state
               SET stage = 'escalated',
                   escalated_at = NOW(),
                   escalated_to = $3,
                   last_worker_run_id = $2
             WHERE mint_request_id = $1
               AND stage IN ('pending', 'warned')
            "#,
            req.mint_request_id,
            run_id,
            tier2_manager.as_deref(),
        )
        .execute(&self.db)
        .await
        .map_err(|e| format!("DB update failed: {e}"))?;

        if updated.rows_affected() == 0 {
            return Ok(());
        }

        self.log_escalation(
            req.mint_request_id,
            "sla_escalated",
            elapsed_hours,
            run_id,
            json!({
                "escalated_to": tier2_manager,
                "elapsed_hours": elapsed_hours,
                "approval_tier": req.approval_tier,
                "amount_ngn": req.amount_ngn.to_string(),
            }),
        )
        .await?;

        self.repo
            .append_audit(
                req.mint_request_id,
                "sla_worker",
                None,
                "sla_escalated",
                Some(&req.sla_stage),
                Some("escalated"),
                json!({
                    "escalated_to": tier2_manager,
                    "elapsed_hours": elapsed_hours,
                    "run_id": run_id,
                }),
            )
            .await
            .map_err(|e| format!("Audit log failed: {e}"))?;

        self.notifier
            .send_escalation(req, elapsed_hours, tier2_manager.as_deref())
            .await;

        warn!(
            mint_request_id = %req.mint_request_id,
            elapsed_hours,
            escalated_to = ?tier2_manager,
            "SLA escalation fired"
        );
        Ok(())
    }

    /// Auto-expire a request at 24 hours.
    /// Marks the mint_request status as 'expired' and the SLA stage as 'expired'.
    /// EXPIRED requests cannot be re-approved without fresh re-submission (#123).
    async fn expire_request(
        &self,
        req: &StalledRequest,
        run_id: Uuid,
    ) -> Result<(), String> {
        let elapsed_hours = (Utc::now() - req.created_at).num_hours();

        // Atomic: update both tables in a transaction
        let mut tx = self.db.begin().await.map_err(|e| format!("TX begin failed: {e}"))?;

        // 1. Expire the mint request itself (guard: only if still in pending state)
        let req_updated = sqlx::query!(
            r#"
            UPDATE mint_requests
               SET status = 'expired', updated_at = NOW()
             WHERE id = $1
               AND status IN ('pending_approval', 'partially_approved')
            "#,
            req.mint_request_id,
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("mint_requests update failed: {e}"))?;

        if req_updated.rows_affected() == 0 {
            // Already transitioned — nothing to do
            tx.rollback().await.ok();
            return Ok(());
        }

        // 2. Update SLA state
        sqlx::query!(
            r#"
            UPDATE mint_sla_state
               SET stage = 'expired', expired_at = NOW(), last_worker_run_id = $2
             WHERE mint_request_id = $1
               AND stage NOT IN ('expired', 'resolved')
            "#,
            req.mint_request_id,
            run_id,
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("SLA state update failed: {e}"))?;

        // 3. Append to mint audit log
        sqlx::query!(
            r#"
            INSERT INTO mint_audit_log
                (mint_request_id, actor_id, event_type, from_status, to_status, payload)
            VALUES ($1, 'sla_worker', 'sla_expired', $2, 'expired', $3)
            "#,
            req.mint_request_id,
            req.status,
            json!({ "elapsed_hours": elapsed_hours, "run_id": run_id }),
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("Audit log failed: {e}"))?;

        // 4. Append to escalation log
        sqlx::query!(
            r#"
            INSERT INTO mint_escalation_log
                (mint_request_id, action, elapsed_hours, notified_targets, metadata, worker_run_id)
            VALUES ($1, 'sla_expired', $2, '[]', $3, $4)
            "#,
            req.mint_request_id,
            elapsed_hours as f64,
            json!({ "amount_ngn": req.amount_ngn.to_string() }),
            run_id,
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("Escalation log failed: {e}"))?;

        tx.commit().await.map_err(|e| format!("TX commit failed: {e}"))?;

        self.notifier.send_expiration(req, elapsed_hours).await;

        error!(
            mint_request_id = %req.mint_request_id,
            elapsed_hours,
            "Mint request auto-expired by SLA worker"
        );
        Ok(())
    }

    /// Mark SLA as resolved when the request leaves the pending state.
    async fn resolve_sla(&self, req: &StalledRequest, run_id: Uuid) -> Result<(), String> {
        sqlx::query!(
            r#"
            UPDATE mint_sla_state
               SET stage = 'resolved', resolved_at = NOW(), last_worker_run_id = $2
             WHERE mint_request_id = $1
               AND stage NOT IN ('expired', 'resolved')
            "#,
            req.mint_request_id,
            run_id,
        )
        .execute(&self.db)
        .await
        .map_err(|e| format!("SLA resolve failed: {e}"))?;
        Ok(())
    }

    // ── Queries ───────────────────────────────────────────────────────────────

    async fn fetch_stalled_requests(&self) -> Result<Vec<StalledRequest>, sqlx::Error> {
        sqlx::query_as!(
            StalledRequest,
            r#"
            SELECT
                mr.id            AS mint_request_id,
                mr.status,
                mr.submitted_by,
                mr.amount_ngn,
                mr.approval_tier,
                mr.created_at,
                mr.expires_at,
                ss.stage         AS sla_stage,
                ss.warned_at,
                ss.escalated_at,
                ss.escalated_to
            FROM mint_requests mr
            JOIN mint_sla_state ss ON ss.mint_request_id = mr.id
            WHERE (
                mr.status IN ('pending_approval', 'partially_approved')
                OR ss.stage NOT IN ('expired', 'resolved')
            )
            AND ss.stage NOT IN ('expired', 'resolved')
            ORDER BY mr.created_at ASC
            "#
        )
        .fetch_all(&self.db)
        .await
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// Resolve the Tier-2 manager for a given request.
    /// In production this would query an RBAC/directory service.
    /// Falls back to the TIER2_MANAGER_ID env var.
    async fn resolve_tier2_manager(&self, _req: &StalledRequest) -> Option<String> {
        std::env::var("TIER2_MANAGER_ID").ok()
    }

    async fn log_escalation(
        &self,
        mint_request_id: Uuid,
        action: &str,
        elapsed_hours: i64,
        run_id: Uuid,
        metadata: serde_json::Value,
    ) -> Result<(), String> {
        sqlx::query!(
            r#"
            INSERT INTO mint_escalation_log
                (mint_request_id, action, elapsed_hours, notified_targets, metadata, worker_run_id)
            VALUES ($1, $2::escalation_action, $3, '[]', $4, $5)
            "#,
            mint_request_id,
            action,
            elapsed_hours as f64,
            metadata,
            run_id,
        )
        .execute(&self.db)
        .await
        .map_err(|e| format!("Escalation log insert failed: {e}"))?;
        Ok(())
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sla_action_none_before_warning_threshold() {
        assert_eq!(SlaAction::from_elapsed_hours(3, "pending"), SlaAction::None);
    }

    #[test]
    fn sla_action_warn_at_4h() {
        assert_eq!(SlaAction::from_elapsed_hours(4, "pending"), SlaAction::Warn);
        assert_eq!(SlaAction::from_elapsed_hours(11, "pending"), SlaAction::Warn);
    }

    #[test]
    fn sla_action_no_double_warn_if_already_warned() {
        // Already warned — should escalate, not warn again
        assert_eq!(SlaAction::from_elapsed_hours(5, "warned"), SlaAction::None);
    }

    #[test]
    fn sla_action_escalate_at_12h() {
        assert_eq!(SlaAction::from_elapsed_hours(12, "warned"), SlaAction::Escalate);
        assert_eq!(SlaAction::from_elapsed_hours(23, "warned"), SlaAction::Escalate);
        // Also escalates if warning was skipped (e.g. worker was down)
        assert_eq!(SlaAction::from_elapsed_hours(12, "pending"), SlaAction::Escalate);
    }

    #[test]
    fn sla_action_no_double_escalate() {
        assert_eq!(SlaAction::from_elapsed_hours(15, "escalated"), SlaAction::None);
    }

    #[test]
    fn sla_action_expire_at_24h() {
        assert_eq!(SlaAction::from_elapsed_hours(24, "escalated"), SlaAction::Expire);
        assert_eq!(SlaAction::from_elapsed_hours(48, "warned"), SlaAction::Expire);
        assert_eq!(SlaAction::from_elapsed_hours(24, "pending"), SlaAction::Expire);
    }

    #[test]
    fn sla_action_none_if_already_expired() {
        assert_eq!(SlaAction::from_elapsed_hours(48, "expired"), SlaAction::None);
        assert_eq!(SlaAction::from_elapsed_hours(48, "resolved"), SlaAction::None);
    }
}
