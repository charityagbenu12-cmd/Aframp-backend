//! Database repository for the corridor router.

use crate::corridors::router::models::*;
use crate::compliance_registry::models::CorridorStatus;
use crate::database::error::DatabaseError;
use chrono::Utc;
use rust_decimal::Decimal;
use sqlx::PgPool;
use uuid::Uuid;

pub struct CorridorRouterRepository {
    pool: PgPool,
}

impl CorridorRouterRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    // -----------------------------------------------------------------------
    // Corridor CRUD
    // -----------------------------------------------------------------------

    pub async fn create(&self, req: &CreateCorridorConfigRequest) -> Result<CorridorConfig, DatabaseError> {
        let risk_score = req.risk_score.unwrap_or(50);
        let kyc_tier = req.required_kyc_tier.clone().unwrap_or_else(|| "basic".to_string());
        let config = req.config.clone().unwrap_or(serde_json::json!({}));

        let row = sqlx::query_as!(
            CorridorConfig,
            r#"
            INSERT INTO payment_corridors (
                source_country, destination_country, source_currency, destination_currency,
                min_transfer_amount, max_transfer_amount, delivery_methods, bridge_asset,
                risk_score, required_kyc_tier, display_name, estimated_minutes,
                is_featured, config
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
            RETURNING
                id, source_country, destination_country, source_currency, destination_currency,
                status AS "status: CorridorStatus",
                status_reason,
                min_transfer_amount, max_transfer_amount,
                COALESCE(delivery_methods, '{}') AS "delivery_methods!: Vec<String>",
                bridge_asset,
                risk_score AS "risk_score!: i16",
                required_kyc_tier AS "required_kyc_tier!",
                display_name, estimated_minutes,
                is_featured AS "is_featured!",
                config AS "config!",
                created_at, updated_at, updated_by
            "#,
            req.source_country,
            req.destination_country,
            req.source_currency,
            req.destination_currency,
            req.min_transfer_amount,
            req.max_transfer_amount,
            &req.delivery_methods,
            req.bridge_asset,
            risk_score,
            kyc_tier,
            req.display_name,
            req.estimated_minutes,
            req.is_featured.unwrap_or(false),
            config,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(row)
    }

    pub async fn get_by_id(&self, id: Uuid) -> Result<Option<CorridorConfig>, DatabaseError> {
        let row = sqlx::query_as!(
            CorridorConfig,
            r#"
            SELECT
                id, source_country, destination_country, source_currency, destination_currency,
                status AS "status: CorridorStatus",
                status_reason,
                min_transfer_amount, max_transfer_amount,
                COALESCE(delivery_methods, '{}') AS "delivery_methods!: Vec<String>",
                bridge_asset,
                risk_score AS "risk_score!: i16",
                required_kyc_tier AS "required_kyc_tier!",
                display_name, estimated_minutes,
                is_featured AS "is_featured!",
                config AS "config!",
                created_at, updated_at, updated_by
            FROM payment_corridors WHERE id = $1
            "#,
            id,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(row)
    }

    /// Look up an active corridor by country/currency pair.
    pub async fn find_active(
        &self,
        source_country: &str,
        destination_country: &str,
        source_currency: &str,
        destination_currency: &str,
    ) -> Result<Option<CorridorConfig>, DatabaseError> {
        let row = sqlx::query_as!(
            CorridorConfig,
            r#"
            SELECT
                id, source_country, destination_country, source_currency, destination_currency,
                status AS "status: CorridorStatus",
                status_reason,
                min_transfer_amount, max_transfer_amount,
                COALESCE(delivery_methods, '{}') AS "delivery_methods!: Vec<String>",
                bridge_asset,
                risk_score AS "risk_score!: i16",
                required_kyc_tier AS "required_kyc_tier!",
                display_name, estimated_minutes,
                is_featured AS "is_featured!",
                config AS "config!",
                created_at, updated_at, updated_by
            FROM payment_corridors
            WHERE source_country = $1
              AND destination_country = $2
              AND source_currency = $3
              AND destination_currency = $4
              AND status = 'active'
            LIMIT 1
            "#,
            source_country,
            destination_country,
            source_currency,
            destination_currency,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(row)
    }

    pub async fn list_all(&self) -> Result<Vec<CorridorConfig>, DatabaseError> {
        let rows = sqlx::query_as!(
            CorridorConfig,
            r#"
            SELECT
                id, source_country, destination_country, source_currency, destination_currency,
                status AS "status: CorridorStatus",
                status_reason,
                min_transfer_amount, max_transfer_amount,
                COALESCE(delivery_methods, '{}') AS "delivery_methods!: Vec<String>",
                bridge_asset,
                risk_score AS "risk_score!: i16",
                required_kyc_tier AS "required_kyc_tier!",
                display_name, estimated_minutes,
                is_featured AS "is_featured!",
                config AS "config!",
                created_at, updated_at, updated_by
            FROM payment_corridors
            ORDER BY is_featured DESC, source_country, destination_country
            "#,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(rows)
    }

    pub async fn update_config(
        &self,
        id: Uuid,
        req: &UpdateCorridorConfigRequest,
        updated_by: Option<Uuid>,
    ) -> Result<CorridorConfig, DatabaseError> {
        let row = sqlx::query_as!(
            CorridorConfig,
            r#"
            UPDATE payment_corridors SET
                min_transfer_amount = COALESCE($2, min_transfer_amount),
                max_transfer_amount = COALESCE($3, max_transfer_amount),
                delivery_methods    = COALESCE($4, delivery_methods),
                bridge_asset        = COALESCE($5, bridge_asset),
                risk_score          = COALESCE($6, risk_score),
                required_kyc_tier   = COALESCE($7, required_kyc_tier),
                display_name        = COALESCE($8, display_name),
                estimated_minutes   = COALESCE($9, estimated_minutes),
                is_featured         = COALESCE($10, is_featured),
                config              = COALESCE($11, config),
                updated_by          = $12,
                updated_at          = NOW()
            WHERE id = $1
            RETURNING
                id, source_country, destination_country, source_currency, destination_currency,
                status AS "status: CorridorStatus",
                status_reason,
                min_transfer_amount, max_transfer_amount,
                COALESCE(delivery_methods, '{}') AS "delivery_methods!: Vec<String>",
                bridge_asset,
                risk_score AS "risk_score!: i16",
                required_kyc_tier AS "required_kyc_tier!",
                display_name, estimated_minutes,
                is_featured AS "is_featured!",
                config AS "config!",
                created_at, updated_at, updated_by
            "#,
            id,
            req.min_transfer_amount,
            req.max_transfer_amount,
            req.delivery_methods.as_deref(),
            req.bridge_asset,
            req.risk_score,
            req.required_kyc_tier,
            req.display_name,
            req.estimated_minutes,
            req.is_featured,
            req.config,
            updated_by,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(row)
    }

    /// Kill-switch: enable or disable a corridor instantly.
    pub async fn toggle(
        &self,
        id: Uuid,
        enabled: bool,
        reason: Option<String>,
        updated_by: Option<Uuid>,
    ) -> Result<CorridorConfig, DatabaseError> {
        let new_status = if enabled {
            "active"
        } else {
            "suspended"
        };

        let row = sqlx::query_as!(
            CorridorConfig,
            r#"
            UPDATE payment_corridors SET
                status       = $2::corridor_status,
                status_reason = $3,
                updated_by   = $4,
                updated_at   = NOW()
            WHERE id = $1
            RETURNING
                id, source_country, destination_country, source_currency, destination_currency,
                status AS "status: CorridorStatus",
                status_reason,
                min_transfer_amount, max_transfer_amount,
                COALESCE(delivery_methods, '{}') AS "delivery_methods!: Vec<String>",
                bridge_asset,
                risk_score AS "risk_score!: i16",
                required_kyc_tier AS "required_kyc_tier!",
                display_name, estimated_minutes,
                is_featured AS "is_featured!",
                config AS "config!",
                created_at, updated_at, updated_by
            "#,
            id,
            new_status,
            reason,
            updated_by,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(row)
    }

    // -----------------------------------------------------------------------
    // Route hops
    // -----------------------------------------------------------------------

    pub async fn get_hops(&self, corridor_id: Uuid) -> Result<Vec<RouteHop>, DatabaseError> {
        let rows = sqlx::query_as!(
            RouteHop,
            r#"
            SELECT id, corridor_id, hop_order AS "hop_order!: i16",
                   from_asset, to_asset, provider,
                   is_active AS "is_active!", created_at
            FROM corridor_route_hops
            WHERE corridor_id = $1 AND is_active = true
            ORDER BY hop_order
            "#,
            corridor_id,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(rows)
    }

    pub async fn upsert_hop(
        &self,
        corridor_id: Uuid,
        hop_order: i16,
        from_asset: &str,
        to_asset: &str,
        provider: Option<&str>,
    ) -> Result<RouteHop, DatabaseError> {
        let row = sqlx::query_as!(
            RouteHop,
            r#"
            INSERT INTO corridor_route_hops (corridor_id, hop_order, from_asset, to_asset, provider)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (corridor_id, hop_order) DO UPDATE SET
                from_asset = EXCLUDED.from_asset,
                to_asset   = EXCLUDED.to_asset,
                provider   = EXCLUDED.provider,
                is_active  = true
            RETURNING id, corridor_id, hop_order AS "hop_order!: i16",
                      from_asset, to_asset, provider,
                      is_active AS "is_active!", created_at
            "#,
            corridor_id,
            hop_order,
            from_asset,
            to_asset,
            provider,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(row)
    }

    // -----------------------------------------------------------------------
    // Health tracking
    // -----------------------------------------------------------------------

    /// Record a transaction outcome into the current hourly health bucket.
    pub async fn record_health_event(&self, event: &HealthEvent) -> Result<(), DatabaseError> {
        let bucket = Utc::now()
            .date_naive()
            .and_hms_opt(Utc::now().hour(), 0, 0)
            .map(|dt| dt.and_utc())
            .unwrap_or_else(Utc::now);

        sqlx::query!(
            r#"
            INSERT INTO corridor_health (corridor_id, bucket_start, total_attempts, successful, failed, total_volume)
            VALUES ($1, $2, 1, $3, $4, $5)
            ON CONFLICT (corridor_id, bucket_start) DO UPDATE SET
                total_attempts = corridor_health.total_attempts + 1,
                successful     = corridor_health.successful + EXCLUDED.successful,
                failed         = corridor_health.failed + EXCLUDED.failed,
                total_volume   = corridor_health.total_volume + EXCLUDED.total_volume,
                updated_at     = NOW()
            "#,
            event.corridor_id,
            bucket,
            if event.success { 1_i32 } else { 0_i32 },
            if event.success { 0_i32 } else { 1_i32 },
            event.amount,
        )
        .execute(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(())
    }

    /// Get 24-hour health summary for a corridor.
    pub async fn get_health_summary(
        &self,
        corridor_id: Uuid,
    ) -> Result<CorridorHealthSummary, DatabaseError> {
        let corridor = self
            .get_by_id(corridor_id)
            .await?
            .ok_or_else(|| DatabaseError::new(crate::database::error::DatabaseErrorKind::NotFound {
                entity: "PaymentCorridor".to_string(),
                id: corridor_id.to_string(),
            }))?;

        let agg = sqlx::query!(
            r#"
            SELECT
                COALESCE(SUM(total_attempts), 0)::BIGINT AS total,
                COALESCE(SUM(successful), 0)::BIGINT     AS success_count,
                COALESCE(SUM(total_volume), 0)           AS volume,
                AVG(avg_latency_ms)::INT                 AS avg_latency
            FROM corridor_health
            WHERE corridor_id = $1
              AND bucket_start >= NOW() - INTERVAL '24 hours'
            "#,
            corridor_id,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?;

        let total = agg.total.unwrap_or(0);
        let success_count = agg.success_count.unwrap_or(0);
        let success_rate = if total > 0 {
            success_count as f64 / total as f64
        } else {
            1.0
        };

        Ok(CorridorHealthSummary {
            corridor_id,
            display_name: corridor.display_name,
            status: corridor.status,
            last_24h_success_rate: success_rate,
            last_24h_total: total,
            last_24h_volume: agg.volume.unwrap_or_default(),
            avg_latency_ms: agg.avg_latency,
            is_healthy: success_rate >= 0.95 && corridor.status.is_open(),
        })
    }

    // -----------------------------------------------------------------------
    // Audit log
    // -----------------------------------------------------------------------

    pub async fn write_audit(
        &self,
        corridor_id: Uuid,
        action: &str,
        changed_by: Option<Uuid>,
        changed_by_role: Option<&str>,
        previous: Option<serde_json::Value>,
        new: Option<serde_json::Value>,
        reason: Option<&str>,
    ) -> Result<(), DatabaseError> {
        sqlx::query!(
            r#"
            INSERT INTO corridor_audit_log
                (corridor_id, action, changed_by, changed_by_role, previous_value, new_value, reason)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            "#,
            corridor_id,
            action,
            changed_by,
            changed_by_role,
            previous,
            new,
            reason,
        )
        .execute(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(())
    }
}

// Helper: get current hour from Utc
trait UtcHour {
    fn hour(&self) -> u32;
}
impl UtcHour for chrono::DateTime<Utc> {
    fn hour(&self) -> u32 {
        use chrono::Timelike;
        chrono::Timelike::hour(self)
    }
}
