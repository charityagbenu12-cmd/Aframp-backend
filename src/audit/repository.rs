use crate::audit::models::*;
use crate::database::error::DatabaseError;
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

pub struct AuditLogRepository {
    pool: PgPool,
}

impl AuditLogRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Fetch the hash of the most recent entry (for hash chain bootstrap).
    pub async fn last_entry_hash(&self) -> Result<Option<String>, DatabaseError> {
        let row = sqlx::query_scalar!(
            "SELECT current_entry_hash FROM api_audit_logs ORDER BY created_at DESC LIMIT 1"
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?;
        Ok(row)
    }

    /// Insert a fully-formed audit log entry.
    pub async fn insert(&self, entry: &AuditLogEntry) -> Result<(), DatabaseError> {
        sqlx::query!(
            r#"
            INSERT INTO api_audit_logs (
                id, event_type, event_category, actor_type, actor_id, actor_ip,
                actor_consumer_type, session_id, target_resource_type, target_resource_id,
                request_method, request_path, request_body_hash, response_status,
                response_latency_ms, outcome, failure_reason, environment,
                previous_entry_hash, current_entry_hash, created_at
            ) VALUES (
                $1, $2, $3, $4, $5, $6::inet,
                $7, $8, $9, $10,
                $11, $12, $13, $14,
                $15, $16, $17, $18,
                $19, $20, $21
            )
            "#,
            entry.id,
            entry.event_type,
            entry.event_category as AuditEventCategory,
            entry.actor_type as AuditActorType,
            entry.actor_id,
            entry.actor_ip,
            entry.actor_consumer_type,
            entry.session_id,
            entry.target_resource_type,
            entry.target_resource_id,
            entry.request_method,
            entry.request_path,
            entry.request_body_hash,
            entry.response_status,
            entry.response_latency_ms,
            entry.outcome as AuditOutcome,
            entry.failure_reason,
            entry.environment,
            entry.previous_entry_hash,
            entry.current_entry_hash,
            entry.created_at,
        )
        .execute(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?;
        Ok(())
    }

    /// Paginated query with optional filters.
    pub async fn query(&self, filter: &AuditLogFilter) -> Result<AuditLogPage, DatabaseError> {
        // Build dynamic query — sqlx doesn't support fully dynamic queries natively,
        // so we use a query builder approach with raw SQL.
        let mut conditions: Vec<String> = Vec::new();
        let mut param_idx: i32 = 1;

        // We'll collect bind values as strings and cast in SQL for simplicity.
        // For production use, sqlx::QueryBuilder is the idiomatic approach.
        let mut where_parts: Vec<String> = Vec::new();

        if filter.event_category.is_some() {
            where_parts.push(format!("event_category = ${}", param_idx));
            param_idx += 1;
        }
        if filter.actor_id.is_some() {
            where_parts.push(format!("actor_id = ${}", param_idx));
            param_idx += 1;
        }
        if filter.actor_type.is_some() {
            where_parts.push(format!("actor_type = ${}", param_idx));
            param_idx += 1;
        }
        if filter.target_resource_type.is_some() {
            where_parts.push(format!("target_resource_type = ${}", param_idx));
            param_idx += 1;
        }
        if filter.target_resource_id.is_some() {
            where_parts.push(format!("target_resource_id = ${}", param_idx));
            param_idx += 1;
        }
        if filter.outcome.is_some() {
            where_parts.push(format!("outcome = ${}", param_idx));
            param_idx += 1;
        }
        if filter.environment.is_some() {
            where_parts.push(format!("environment = ${}", param_idx));
            param_idx += 1;
        }
        if filter.date_from.is_some() {
            where_parts.push(format!("created_at >= ${}", param_idx));
            param_idx += 1;
        }
        if filter.date_to.is_some() {
            where_parts.push(format!("created_at <= ${}", param_idx));
            param_idx += 1;
        }

        let where_clause = if where_parts.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", where_parts.join(" AND "))
        };

        let limit_offset_idx_start = param_idx;
        let sql = format!(
            "SELECT id, event_type, event_category as \"event_category: AuditEventCategory\",
                    actor_type as \"actor_type: AuditActorType\", actor_id, actor_ip::text,
                    actor_consumer_type, session_id, target_resource_type, target_resource_id,
                    request_method, request_path, request_body_hash, response_status,
                    response_latency_ms, outcome as \"outcome: AuditOutcome\", failure_reason,
                    environment, previous_entry_hash, current_entry_hash, created_at
             FROM api_audit_logs
             {} ORDER BY created_at DESC
             LIMIT ${} OFFSET ${}",
            where_clause, limit_offset_idx_start, limit_offset_idx_start + 1
        );

        let count_sql = format!(
            "SELECT COUNT(*) FROM api_audit_logs {}",
            where_clause
        );

        // Use sqlx QueryBuilder for type-safe dynamic queries
        use sqlx::QueryBuilder;
        let mut qb: QueryBuilder<sqlx::Postgres> = QueryBuilder::new(
            "SELECT id, event_type, event_category as \"event_category: AuditEventCategory\",
                    actor_type as \"actor_type: AuditActorType\", actor_id, actor_ip::text,
                    actor_consumer_type, session_id, target_resource_type, target_resource_id,
                    request_method, request_path, request_body_hash, response_status,
                    response_latency_ms, outcome as \"outcome: AuditOutcome\", failure_reason,
                    environment, previous_entry_hash, current_entry_hash, created_at
             FROM api_audit_logs"
        );

        let mut count_qb: QueryBuilder<sqlx::Postgres> =
            QueryBuilder::new("SELECT COUNT(*) FROM api_audit_logs");

        let mut first = true;
        let push_where = |qb: &mut QueryBuilder<sqlx::Postgres>, first: &mut bool| {
            if *first {
                qb.push(" WHERE ");
                *first = false;
            } else {
                qb.push(" AND ");
            }
        };

        // Re-build with QueryBuilder for actual execution
        let mut qb: QueryBuilder<sqlx::Postgres> = QueryBuilder::new(
            "SELECT id, event_type, event_category, actor_type, actor_id, actor_ip::text as actor_ip,
                    actor_consumer_type, session_id, target_resource_type, target_resource_id,
                    request_method, request_path, request_body_hash, response_status,
                    response_latency_ms, outcome, failure_reason,
                    environment, previous_entry_hash, current_entry_hash, created_at
             FROM api_audit_logs"
        );
        let mut count_qb: QueryBuilder<sqlx::Postgres> =
            QueryBuilder::new("SELECT COUNT(*) FROM api_audit_logs");

        let mut first_main = true;
        let mut first_count = true;

        if let Some(cat) = &filter.event_category {
            if first_main { qb.push(" WHERE "); first_main = false; } else { qb.push(" AND "); }
            qb.push("event_category = ").push_bind(cat.as_str());
            if first_count { count_qb.push(" WHERE "); first_count = false; } else { count_qb.push(" AND "); }
            count_qb.push("event_category = ").push_bind(cat.as_str());
        }
        if let Some(aid) = &filter.actor_id {
            if first_main { qb.push(" WHERE "); first_main = false; } else { qb.push(" AND "); }
            qb.push("actor_id = ").push_bind(aid);
            if first_count { count_qb.push(" WHERE "); first_count = false; } else { count_qb.push(" AND "); }
            count_qb.push("actor_id = ").push_bind(aid);
        }
        if let Some(at) = &filter.actor_type {
            let s = match at {
                AuditActorType::Consumer => "consumer",
                AuditActorType::Admin => "admin",
                AuditActorType::Microservice => "microservice",
                AuditActorType::System => "system",
            };
            if first_main { qb.push(" WHERE "); first_main = false; } else { qb.push(" AND "); }
            qb.push("actor_type = ").push_bind(s);
            if first_count { count_qb.push(" WHERE "); first_count = false; } else { count_qb.push(" AND "); }
            count_qb.push("actor_type = ").push_bind(s);
        }
        if let Some(trt) = &filter.target_resource_type {
            if first_main { qb.push(" WHERE "); first_main = false; } else { qb.push(" AND "); }
            qb.push("target_resource_type = ").push_bind(trt);
            if first_count { count_qb.push(" WHERE "); first_count = false; } else { count_qb.push(" AND "); }
            count_qb.push("target_resource_type = ").push_bind(trt);
        }
        if let Some(tri) = &filter.target_resource_id {
            if first_main { qb.push(" WHERE "); first_main = false; } else { qb.push(" AND "); }
            qb.push("target_resource_id = ").push_bind(tri);
            if first_count { count_qb.push(" WHERE "); first_count = false; } else { count_qb.push(" AND "); }
            count_qb.push("target_resource_id = ").push_bind(tri);
        }
        if let Some(oc) = &filter.outcome {
            let s = match oc {
                AuditOutcome::Success => "success",
                AuditOutcome::Failure => "failure",
                AuditOutcome::Partial => "partial",
            };
            if first_main { qb.push(" WHERE "); first_main = false; } else { qb.push(" AND "); }
            qb.push("outcome = ").push_bind(s);
            if first_count { count_qb.push(" WHERE "); first_count = false; } else { count_qb.push(" AND "); }
            count_qb.push("outcome = ").push_bind(s);
        }
        if let Some(env) = &filter.environment {
            if first_main { qb.push(" WHERE "); first_main = false; } else { qb.push(" AND "); }
            qb.push("environment = ").push_bind(env);
            if first_count { count_qb.push(" WHERE "); first_count = false; } else { count_qb.push(" AND "); }
            count_qb.push("environment = ").push_bind(env);
        }
        if let Some(df) = &filter.date_from {
            if first_main { qb.push(" WHERE "); first_main = false; } else { qb.push(" AND "); }
            qb.push("created_at >= ").push_bind(df);
            if first_count { count_qb.push(" WHERE "); first_count = false; } else { count_qb.push(" AND "); }
            count_qb.push("created_at >= ").push_bind(df);
        }
        if let Some(dt) = &filter.date_to {
            if first_main { qb.push(" WHERE "); first_main = false; } else { qb.push(" AND "); }
            qb.push("created_at <= ").push_bind(dt);
            if first_count { count_qb.push(" WHERE "); first_count = false; } else { count_qb.push(" AND "); }
            count_qb.push("created_at <= ").push_bind(dt);
        }

        qb.push(" ORDER BY created_at DESC LIMIT ")
            .push_bind(filter.page_size())
            .push(" OFFSET ")
            .push_bind(filter.offset());

        let total: i64 = count_qb
            .build_query_scalar()
            .fetch_one(&self.pool)
            .await
            .map_err(DatabaseError::from_sqlx)?;

        let rows = qb
            .build_query_as::<AuditLogRow>()
            .fetch_all(&self.pool)
            .await
            .map_err(DatabaseError::from_sqlx)?;

        let entries = rows.into_iter().map(AuditLogEntry::from).collect();

        Ok(AuditLogPage {
            entries,
            total,
            page: filter.page(),
            page_size: filter.page_size(),
        })
    }

    /// Fetch a single entry by ID.
    pub async fn get_by_id(&self, id: Uuid) -> Result<Option<AuditLogEntry>, DatabaseError> {
        let row = sqlx::query_as!(
            AuditLogRow,
            r#"SELECT id, event_type,
                      event_category as "event_category: _",
                      actor_type as "actor_type: _",
                      actor_id, actor_ip::text as actor_ip,
                      actor_consumer_type, session_id,
                      target_resource_type, target_resource_id,
                      request_method, request_path, request_body_hash,
                      response_status, response_latency_ms,
                      outcome as "outcome: _",
                      failure_reason, environment,
                      previous_entry_hash, current_entry_hash, created_at
               FROM api_audit_logs WHERE id = $1"#,
            id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?;
        Ok(row.map(AuditLogEntry::from))
    }

    /// Fetch entries for export (capped at max_rows).
    pub async fn export(
        &self,
        filter: &AuditLogFilter,
        max_rows: i64,
    ) -> Result<Vec<AuditLogEntry>, DatabaseError> {
        let mut f = filter.clone();
        f.page = Some(1);
        f.page_size = Some(max_rows.min(10_000));
        let page = self.query(&f).await?;
        Ok(page.entries)
    }

    /// Verify hash chain integrity for a date range.
    pub async fn verify_hash_chain(
        &self,
        date_from: DateTime<Utc>,
        date_to: DateTime<Utc>,
    ) -> Result<HashChainVerificationResult, DatabaseError> {
        let rows = sqlx::query!(
            r#"SELECT id, current_entry_hash, previous_entry_hash,
                      event_type, actor_id, actor_ip::text as actor_ip,
                      session_id, target_resource_type, target_resource_id,
                      request_method, request_path, request_body_hash,
                      response_status, response_latency_ms,
                      outcome as "outcome: AuditOutcome",
                      failure_reason, environment,
                      event_category as "event_category: AuditEventCategory",
                      actor_type as "actor_type: AuditActorType",
                      actor_consumer_type, created_at
               FROM api_audit_logs
               WHERE created_at >= $1 AND created_at <= $2
               ORDER BY created_at ASC"#,
            date_from,
            date_to,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?;

        let total = rows.len() as i64;
        let mut tampered = Vec::new();
        let mut gaps = Vec::new();
        let mut prev_hash: Option<String> = None;

        let first_id = rows.first().map(|r| r.id);
        let last_id = rows.last().map(|r| r.id);

        for row in &rows {
            // Reconstruct the pending entry to recompute the hash
            let pending = crate::audit::models::PendingAuditEntry {
                event_type: row.event_type.clone(),
                event_category: row.event_category,
                actor_type: row.actor_type,
                actor_id: row.actor_id.clone(),
                actor_ip: row.actor_ip.clone(),
                actor_consumer_type: row.actor_consumer_type.clone(),
                session_id: row.session_id.clone(),
                target_resource_type: row.target_resource_type.clone(),
                target_resource_id: row.target_resource_id.clone(),
                request_method: row.request_method.clone(),
                request_path: row.request_path.clone(),
                request_body_hash: row.request_body_hash.clone(),
                response_status: row.response_status,
                response_latency_ms: row.response_latency_ms,
                outcome: row.outcome,
                failure_reason: row.failure_reason.clone(),
                environment: row.environment.clone(),
            };

            let ph = prev_hash.as_deref().unwrap_or("0000000000000000000000000000000000000000000000000000000000000000");
            let content = crate::audit::redaction::entry_content(&pending, row.id, &row.created_at);
            let expected = crate::audit::redaction::compute_entry_hash(ph, &content);

            if expected != row.current_entry_hash {
                tampered.push(TamperedAuditEntry {
                    entry_id: row.id,
                    expected_hash: expected,
                    actual_hash: row.current_entry_hash.clone(),
                    created_at: row.created_at,
                });
            }

            // Check previous_entry_hash linkage
            if let Some(ref stored_prev) = row.previous_entry_hash {
                if let Some(ref actual_prev) = prev_hash {
                    if stored_prev != actual_prev {
                        gaps.push(format!(
                            "Hash chain gap at entry {} (created_at: {})",
                            row.id, row.created_at
                        ));
                    }
                }
            }

            prev_hash = Some(row.current_entry_hash.clone());
        }

        Ok(HashChainVerificationResult {
            valid: tampered.is_empty() && gaps.is_empty(),
            total_checked: total,
            first_sequence_id: first_id,
            last_sequence_id: last_id,
            tampered_entries: tampered,
            gaps_detected: gaps,
            verified_at: Utc::now(),
        })
    }
}

// ── Internal row type for sqlx mapping ───────────────────────────────────────

#[derive(sqlx::FromRow)]
struct AuditLogRow {
    id: Uuid,
    event_type: String,
    event_category: AuditEventCategory,
    actor_type: AuditActorType,
    actor_id: Option<String>,
    actor_ip: Option<String>,
    actor_consumer_type: Option<String>,
    session_id: Option<String>,
    target_resource_type: Option<String>,
    target_resource_id: Option<String>,
    request_method: String,
    request_path: String,
    request_body_hash: Option<String>,
    response_status: i32,
    response_latency_ms: i64,
    outcome: AuditOutcome,
    failure_reason: Option<String>,
    environment: String,
    previous_entry_hash: Option<String>,
    current_entry_hash: String,
    created_at: DateTime<Utc>,
}

impl From<AuditLogRow> for AuditLogEntry {
    fn from(r: AuditLogRow) -> Self {
        Self {
            id: r.id,
            event_type: r.event_type,
            event_category: r.event_category,
            actor_type: r.actor_type,
            actor_id: r.actor_id,
            actor_ip: r.actor_ip,
            actor_consumer_type: r.actor_consumer_type,
            session_id: r.session_id,
            target_resource_type: r.target_resource_type,
            target_resource_id: r.target_resource_id,
            request_method: r.request_method,
            request_path: r.request_path,
            request_body_hash: r.request_body_hash,
            response_status: r.response_status,
            response_latency_ms: r.response_latency_ms,
            outcome: r.outcome,
            failure_reason: r.failure_reason,
            environment: r.environment,
            previous_entry_hash: r.previous_entry_hash,
            current_entry_hash: r.current_entry_hash,
            created_at: r.created_at,
        }
    }
}
