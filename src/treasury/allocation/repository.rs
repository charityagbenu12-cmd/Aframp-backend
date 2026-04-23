/// Database repository for the Smart Treasury Allocation Engine.
/// All queries use sqlx with compile-time checked macros where possible.
use super::types::*;
use chrono::{NaiveDate, Utc};
use sqlx::PgPool;
use uuid::Uuid;

pub struct AllocationRepository {
    db: PgPool,
}

impl AllocationRepository {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    // ── Custodian Institutions ────────────────────────────────────────────────

    pub async fn list_active_custodians(&self) -> Result<Vec<CustodianInstitution>, sqlx::Error> {
        sqlx::query_as!(
            CustodianInstitution,
            r#"
            SELECT id, public_alias, internal_name,
                   institution_type AS "institution_type: InstitutionType",
                   liquidity_tier, max_concentration_bps,
                   risk_rating AS "risk_rating: RiskRating",
                   cbn_bank_code, is_active, created_at, updated_at
            FROM custodian_institutions
            WHERE is_active = TRUE
            ORDER BY liquidity_tier ASC, public_alias ASC
            "#
        )
        .fetch_all(&self.db)
        .await
    }

    pub async fn get_custodian(&self, id: Uuid) -> Result<CustodianInstitution, sqlx::Error> {
        sqlx::query_as!(
            CustodianInstitution,
            r#"
            SELECT id, public_alias, internal_name,
                   institution_type AS "institution_type: InstitutionType",
                   liquidity_tier, max_concentration_bps,
                   risk_rating AS "risk_rating: RiskRating",
                   cbn_bank_code, is_active, created_at, updated_at
            FROM custodian_institutions WHERE id = $1
            "#,
            id
        )
        .fetch_one(&self.db)
        .await
    }

    pub async fn update_risk_rating(
        &self,
        id: Uuid,
        rating: RiskRating,
    ) -> Result<(), sqlx::Error> {
        sqlx::query!(
            r#"
            UPDATE custodian_institutions
            SET risk_rating = $2::risk_rating, updated_at = NOW()
            WHERE id = $1
            "#,
            id,
            rating as RiskRating,
        )
        .execute(&self.db)
        .await?;
        Ok(())
    }

    // ── Reserve Allocations ───────────────────────────────────────────────────

    /// Insert a new balance snapshot and supersede the previous one.
    pub async fn record_allocation(
        &self,
        custodian_id: Uuid,
        balance_kobo: i64,
        source: &str,
        statement_hash: Option<&str>,
        notes: Option<&str>,
    ) -> Result<ReserveAllocation, sqlx::Error> {
        let mut tx = self.db.begin().await?;

        // Supersede previous confirmed snapshot for this custodian
        sqlx::query!(
            r#"
            UPDATE reserve_allocations
            SET status = 'superseded'::allocation_status
            WHERE custodian_id = $1
              AND status = 'confirmed'::allocation_status
            "#,
            custodian_id
        )
        .execute(&mut *tx)
        .await?;

        let row = sqlx::query_as!(
            ReserveAllocation,
            r#"
            INSERT INTO reserve_allocations
                (custodian_id, balance_kobo, source, statement_hash, notes, status)
            VALUES ($1, $2, $3, $4, $5, 'confirmed'::allocation_status)
            RETURNING id, custodian_id, balance_kobo, snapshot_at,
                      status AS "status: AllocationStatus",
                      source, statement_hash, confirmed_by, confirmed_at, notes, created_at
            "#,
            custodian_id,
            balance_kobo,
            source,
            statement_hash,
            notes,
        )
        .fetch_one(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(row)
    }

    /// Fetch the latest confirmed balance for each active custodian.
    pub async fn latest_balances(&self) -> Result<Vec<(Uuid, i64)>, sqlx::Error> {
        let rows = sqlx::query!(
            r#"
            SELECT DISTINCT ON (custodian_id) custodian_id, balance_kobo
            FROM reserve_allocations
            WHERE status = 'confirmed'::allocation_status
            ORDER BY custodian_id, snapshot_at DESC
            "#
        )
        .fetch_all(&self.db)
        .await?;

        Ok(rows.into_iter().map(|r| (r.custodian_id, r.balance_kobo)).collect())
    }

    // ── Concentration Snapshots ───────────────────────────────────────────────

    pub async fn insert_concentration_snapshot(
        &self,
        custodian_id: Uuid,
        balance_kobo: i64,
        total_reserves_kobo: i64,
        concentration_bps: i32,
        max_concentration_bps: i32,
        liquidity_tier: i16,
    ) -> Result<ConcentrationSnapshot, sqlx::Error> {
        sqlx::query_as!(
            ConcentrationSnapshot,
            r#"
            INSERT INTO concentration_snapshots
                (custodian_id, balance_kobo, total_reserves_kobo,
                 concentration_bps, max_concentration_bps, liquidity_tier)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING id, custodian_id, snapshot_at, balance_kobo, total_reserves_kobo,
                      concentration_bps, max_concentration_bps, is_breached,
                      liquidity_tier, created_at
            "#,
            custodian_id,
            balance_kobo,
            total_reserves_kobo,
            concentration_bps,
            max_concentration_bps,
            liquidity_tier,
        )
        .fetch_one(&self.db)
        .await
    }

    /// Latest concentration snapshot per custodian (for the monitor dashboard).
    pub async fn latest_concentration_snapshots(
        &self,
    ) -> Result<Vec<ConcentrationSnapshot>, sqlx::Error> {
        sqlx::query_as!(
            ConcentrationSnapshot,
            r#"
            SELECT DISTINCT ON (custodian_id)
                id, custodian_id, snapshot_at, balance_kobo, total_reserves_kobo,
                concentration_bps, max_concentration_bps, is_breached,
                liquidity_tier, created_at
            FROM concentration_snapshots
            ORDER BY custodian_id, snapshot_at DESC
            "#
        )
        .fetch_all(&self.db)
        .await
    }

    pub async fn active_breaches(&self) -> Result<Vec<ConcentrationSnapshot>, sqlx::Error> {
        sqlx::query_as!(
            ConcentrationSnapshot,
            r#"
            SELECT DISTINCT ON (custodian_id)
                id, custodian_id, snapshot_at, balance_kobo, total_reserves_kobo,
                concentration_bps, max_concentration_bps, is_breached,
                liquidity_tier, created_at
            FROM concentration_snapshots
            WHERE is_breached = TRUE
            ORDER BY custodian_id, snapshot_at DESC
            "#
        )
        .fetch_all(&self.db)
        .await
    }

    // ── Concentration Alerts ──────────────────────────────────────────────────

    pub async fn insert_alert(
        &self,
        custodian_id: Uuid,
        snapshot_id: Uuid,
        severity: AlertSeverity,
        concentration_bps: i32,
        max_allowed_bps: i32,
        message: &str,
    ) -> Result<ConcentrationAlert, sqlx::Error> {
        sqlx::query_as!(
            ConcentrationAlert,
            r#"
            INSERT INTO concentration_alerts
                (custodian_id, snapshot_id, severity, concentration_bps,
                 max_allowed_bps, message)
            VALUES ($1, $2, $3::alert_severity, $4, $5, $6)
            RETURNING id, custodian_id, snapshot_id,
                      severity AS "severity: AlertSeverity",
                      concentration_bps, max_allowed_bps, excess_bps, message,
                      acknowledged_by, acknowledged_at, resolved_at, created_at
            "#,
            custodian_id,
            snapshot_id,
            severity as AlertSeverity,
            concentration_bps,
            max_allowed_bps,
            message,
        )
        .fetch_one(&self.db)
        .await
    }

    pub async fn list_unresolved_alerts(&self) -> Result<Vec<ConcentrationAlert>, sqlx::Error> {
        sqlx::query_as!(
            ConcentrationAlert,
            r#"
            SELECT id, custodian_id, snapshot_id,
                   severity AS "severity: AlertSeverity",
                   concentration_bps, max_allowed_bps, excess_bps, message,
                   acknowledged_by, acknowledged_at, resolved_at, created_at
            FROM concentration_alerts
            WHERE resolved_at IS NULL
            ORDER BY created_at DESC
            "#
        )
        .fetch_all(&self.db)
        .await
    }

    pub async fn resolve_alert(&self, alert_id: Uuid) -> Result<(), sqlx::Error> {
        sqlx::query!(
            "UPDATE concentration_alerts SET resolved_at = NOW() WHERE id = $1",
            alert_id
        )
        .execute(&self.db)
        .await?;
        Ok(())
    }

    // ── RWA Daily Snapshots ───────────────────────────────────────────────────

    pub async fn upsert_rwa_snapshot(
        &self,
        date: NaiveDate,
        total_reserves_kobo: i64,
        total_rwa_kobo: i64,
        onchain_supply_kobo: i64,
        peg_coverage_bps: i32,
        tier1_kobo: i64,
        tier2_kobo: i64,
        tier3_kobo: i64,
        rwa_breakdown: serde_json::Value,
    ) -> Result<RwaDailySnapshot, sqlx::Error> {
        sqlx::query_as!(
            RwaDailySnapshot,
            r#"
            INSERT INTO rwa_daily_snapshots
                (snapshot_date, total_reserves_kobo, total_rwa_kobo, onchain_supply_kobo,
                 peg_coverage_bps, tier1_kobo, tier2_kobo, tier3_kobo, rwa_breakdown)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            ON CONFLICT (snapshot_date) DO UPDATE SET
                total_reserves_kobo = EXCLUDED.total_reserves_kobo,
                total_rwa_kobo      = EXCLUDED.total_rwa_kobo,
                onchain_supply_kobo = EXCLUDED.onchain_supply_kobo,
                peg_coverage_bps    = EXCLUDED.peg_coverage_bps,
                tier1_kobo          = EXCLUDED.tier1_kobo,
                tier2_kobo          = EXCLUDED.tier2_kobo,
                tier3_kobo          = EXCLUDED.tier3_kobo,
                rwa_breakdown       = EXCLUDED.rwa_breakdown
            RETURNING id, snapshot_date, total_reserves_kobo, total_rwa_kobo,
                      onchain_supply_kobo, peg_coverage_bps, tier1_kobo, tier2_kobo,
                      tier3_kobo, rwa_breakdown, calculated_by, created_at
            "#,
            date,
            total_reserves_kobo,
            total_rwa_kobo,
            onchain_supply_kobo,
            peg_coverage_bps,
            tier1_kobo,
            tier2_kobo,
            tier3_kobo,
            rwa_breakdown,
        )
        .fetch_one(&self.db)
        .await
    }

    pub async fn latest_rwa_snapshot(&self) -> Result<Option<RwaDailySnapshot>, sqlx::Error> {
        sqlx::query_as!(
            RwaDailySnapshot,
            r#"
            SELECT id, snapshot_date, total_reserves_kobo, total_rwa_kobo,
                   onchain_supply_kobo, peg_coverage_bps, tier1_kobo, tier2_kobo,
                   tier3_kobo, rwa_breakdown, calculated_by, created_at
            FROM rwa_daily_snapshots
            ORDER BY snapshot_date DESC
            LIMIT 1
            "#
        )
        .fetch_optional(&self.db)
        .await
    }

    // ── Transfer Orders ───────────────────────────────────────────────────────

    pub async fn insert_transfer_order(
        &self,
        from_custodian_id: Uuid,
        to_custodian_id: Uuid,
        amount_kobo: i64,
        trigger: TransferOrderTrigger,
        trigger_ref_id: Option<Uuid>,
        rationale: &str,
        projected_from_bps: Option<i32>,
        projected_to_bps: Option<i32>,
        requested_by: &str,
    ) -> Result<TransferOrder, sqlx::Error> {
        sqlx::query_as!(
            TransferOrder,
            r#"
            INSERT INTO transfer_orders
                (from_custodian_id, to_custodian_id, amount_kobo, trigger,
                 trigger_ref_id, rationale, projected_from_bps, projected_to_bps,
                 requested_by)
            VALUES ($1, $2, $3, $4::transfer_order_trigger, $5, $6, $7, $8, $9)
            RETURNING id, from_custodian_id, to_custodian_id, amount_kobo,
                      trigger AS "trigger: TransferOrderTrigger",
                      trigger_ref_id, status AS "status: TransferOrderStatus",
                      rationale, projected_from_bps, projected_to_bps,
                      requested_by, approved_by, approved_at, rejection_reason,
                      executed_at, bank_reference, completed_at, created_at, updated_at
            "#,
            from_custodian_id,
            to_custodian_id,
            amount_kobo,
            trigger as TransferOrderTrigger,
            trigger_ref_id,
            rationale,
            projected_from_bps,
            projected_to_bps,
            requested_by,
        )
        .fetch_one(&self.db)
        .await
    }

    pub async fn get_transfer_order(&self, id: Uuid) -> Result<TransferOrder, sqlx::Error> {
        sqlx::query_as!(
            TransferOrder,
            r#"
            SELECT id, from_custodian_id, to_custodian_id, amount_kobo,
                   trigger AS "trigger: TransferOrderTrigger",
                   trigger_ref_id, status AS "status: TransferOrderStatus",
                   rationale, projected_from_bps, projected_to_bps,
                   requested_by, approved_by, approved_at, rejection_reason,
                   executed_at, bank_reference, completed_at, created_at, updated_at
            FROM transfer_orders WHERE id = $1
            "#,
            id
        )
        .fetch_one(&self.db)
        .await
    }

    pub async fn list_transfer_orders(
        &self,
        status: Option<TransferOrderStatus>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<TransferOrder>, sqlx::Error> {
        sqlx::query_as!(
            TransferOrder,
            r#"
            SELECT id, from_custodian_id, to_custodian_id, amount_kobo,
                   trigger AS "trigger: TransferOrderTrigger",
                   trigger_ref_id, status AS "status: TransferOrderStatus",
                   rationale, projected_from_bps, projected_to_bps,
                   requested_by, approved_by, approved_at, rejection_reason,
                   executed_at, bank_reference, completed_at, created_at, updated_at
            FROM transfer_orders
            WHERE ($1::transfer_order_status IS NULL OR status = $1)
            ORDER BY created_at DESC
            LIMIT $2 OFFSET $3
            "#,
            status as Option<TransferOrderStatus>,
            limit,
            offset,
        )
        .fetch_all(&self.db)
        .await
    }

    pub async fn update_transfer_order_status(
        &self,
        id: Uuid,
        new_status: TransferOrderStatus,
        approved_by: Option<&str>,
        rejection_reason: Option<&str>,
        bank_reference: Option<&str>,
    ) -> Result<TransferOrder, sqlx::Error> {
        sqlx::query_as!(
            TransferOrder,
            r#"
            UPDATE transfer_orders SET
                status           = $2::transfer_order_status,
                approved_by      = COALESCE($3, approved_by),
                approved_at      = CASE WHEN $2 = 'approved' THEN NOW() ELSE approved_at END,
                rejection_reason = COALESCE($4, rejection_reason),
                bank_reference   = COALESCE($5, bank_reference),
                executed_at      = CASE WHEN $2 = 'executing' THEN NOW() ELSE executed_at END,
                completed_at     = CASE WHEN $2 = 'completed' THEN NOW() ELSE completed_at END
            WHERE id = $1
            RETURNING id, from_custodian_id, to_custodian_id, amount_kobo,
                      trigger AS "trigger: TransferOrderTrigger",
                      trigger_ref_id, status AS "status: TransferOrderStatus",
                      rationale, projected_from_bps, projected_to_bps,
                      requested_by, approved_by, approved_at, rejection_reason,
                      executed_at, bank_reference, completed_at, created_at, updated_at
            "#,
            id,
            new_status as TransferOrderStatus,
            approved_by,
            rejection_reason,
            bank_reference,
        )
        .fetch_one(&self.db)
        .await
    }

    /// Append an entry to the transfer order audit log.
    pub async fn log_transfer_event(
        &self,
        order_id: Uuid,
        actor_id: &str,
        event_type: &str,
        old_status: Option<TransferOrderStatus>,
        new_status: Option<TransferOrderStatus>,
        metadata: serde_json::Value,
    ) -> Result<(), sqlx::Error> {
        sqlx::query!(
            r#"
            INSERT INTO transfer_order_audit_log
                (order_id, actor_id, event_type, old_status, new_status, metadata)
            VALUES ($1, $2, $3, $4::transfer_order_status, $5::transfer_order_status, $6)
            "#,
            order_id,
            actor_id,
            event_type,
            old_status as Option<TransferOrderStatus>,
            new_status as Option<TransferOrderStatus>,
            metadata,
        )
        .execute(&self.db)
        .await?;
        Ok(())
    }

    /// Refresh the public materialised view (called after each reconciliation).
    pub async fn refresh_public_dashboard(&self) -> Result<(), sqlx::Error> {
        sqlx::query!(
            "REFRESH MATERIALIZED VIEW CONCURRENTLY public_reserve_dashboard"
        )
        .execute(&self.db)
        .await?;
        Ok(())
    }

    /// Fetch the public dashboard rows (sanitised).
    pub async fn public_dashboard_rows(&self) -> Result<Vec<PublicDashboardRow>, sqlx::Error> {
        sqlx::query_as!(
            PublicDashboardRow,
            r#"
            SELECT institution_alias, institution_type AS "institution_type: InstitutionType",
                   liquidity_tier, concentration_pct, max_concentration_pct,
                   is_breached, snapshot_at
            FROM public_reserve_dashboard
            ORDER BY liquidity_tier ASC, concentration_pct DESC
            "#
        )
        .fetch_all(&self.db)
        .await
    }
}

/// Row returned from the public_reserve_dashboard materialised view.
#[derive(Debug, sqlx::FromRow)]
pub struct PublicDashboardRow {
    pub institution_alias: String,
    pub institution_type: InstitutionType,
    pub liquidity_tier: i16,
    pub concentration_pct: Option<rust_decimal::Decimal>,
    pub max_concentration_pct: Option<rust_decimal::Decimal>,
    pub is_breached: bool,
    pub snapshot_at: DateTime<Utc>,
}

use chrono::DateTime;
use chrono::Utc;
