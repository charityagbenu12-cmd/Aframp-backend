//! Policy violation and data access audit trail.
//!
//! Every time a Restricted or Critical field is accessed, or a policy
//! violation is detected, an entry is written here.  The repository
//! persists these to the `data_classification_audit` table.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::data_classification::{policy::TransmissionContext, registry::DataField};

// ---------------------------------------------------------------------------
// Audit event types
// ---------------------------------------------------------------------------

/// The kind of audit event being recorded.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventKind {
    /// A Restricted or Critical field was accessed by an authorised actor.
    FieldAccess,
    /// A policy violation was detected (e.g., Critical field in a log line).
    PolicyViolation,
    /// A field was masked before transmission.
    FieldMasked,
    /// A field was denied transmission in a given context.
    TransmissionDenied,
    /// A retention purge was executed for a field category.
    RetentionPurge,
}

impl AuditEventKind {
    fn as_str(&self) -> &'static str {
        match self {
            AuditEventKind::FieldAccess => "field_access",
            AuditEventKind::PolicyViolation => "policy_violation",
            AuditEventKind::FieldMasked => "field_masked",
            AuditEventKind::TransmissionDenied => "transmission_denied",
            AuditEventKind::RetentionPurge => "retention_purge",
        }
    }
}

/// A single audit event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassificationAuditEvent {
    pub id: Uuid,
    pub event_kind: AuditEventKind,
    /// The field that was accessed or violated.
    pub field_name: String,
    /// The classification tier of the field.
    pub tier: String,
    /// The transmission context (log, api_response, etc.).
    pub context: String,
    /// The actor that triggered the event (wallet address, admin ID, service name).
    pub actor: Option<String>,
    /// The request ID for correlation.
    pub request_id: Option<String>,
    /// Additional detail (e.g., violation reason).
    pub detail: Option<String>,
    pub occurred_at: DateTime<Utc>,
}

impl ClassificationAuditEvent {
    pub fn field_access(
        field: DataField,
        context: TransmissionContext,
        actor: Option<String>,
        request_id: Option<String>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            event_kind: AuditEventKind::FieldAccess,
            field_name: format!("{:?}", field),
            tier: field.tier().label().to_string(),
            context: format!("{:?}", context),
            actor,
            request_id,
            detail: None,
            occurred_at: Utc::now(),
        }
    }

    pub fn policy_violation(
        field: DataField,
        context: TransmissionContext,
        reason: &str,
        actor: Option<String>,
        request_id: Option<String>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            event_kind: AuditEventKind::PolicyViolation,
            field_name: format!("{:?}", field),
            tier: field.tier().label().to_string(),
            context: format!("{:?}", context),
            actor,
            request_id,
            detail: Some(reason.to_string()),
            occurred_at: Utc::now(),
        }
    }

    pub fn transmission_denied(
        field: DataField,
        context: TransmissionContext,
        reason: &str,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            event_kind: AuditEventKind::TransmissionDenied,
            field_name: format!("{:?}", field),
            tier: field.tier().label().to_string(),
            context: format!("{:?}", context),
            actor: None,
            request_id: None,
            detail: Some(reason.to_string()),
            occurred_at: Utc::now(),
        }
    }
}

// ---------------------------------------------------------------------------
// Repository
// ---------------------------------------------------------------------------

/// Persists classification audit events to the database.
#[derive(Clone)]
pub struct ClassificationAuditRepository {
    pool: PgPool,
}

impl ClassificationAuditRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Insert an audit event.  Errors are logged but never propagated —
    /// audit failures must not break the primary request path.
    pub async fn record(&self, event: ClassificationAuditEvent) {
        let result = sqlx::query(
            r#"
            INSERT INTO data_classification_audit (
                id, event_kind, field_name, tier, context,
                actor, request_id, detail, occurred_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            "#,
        )
        .bind(event.id)
        .bind(event.event_kind.as_str())
        .bind(event.field_name)
        .bind(event.tier)
        .bind(event.context)
        .bind(event.actor)
        .bind(event.request_id)
        .bind(event.detail)
        .bind(event.occurred_at)
        .execute(&self.pool)
        .await;

        if let Err(e) = result {
            tracing::error!(
                error = %e,
                event_id = %event.id,
                "Failed to persist classification audit event"
            );
        }
    }

    /// Retrieve recent policy violations for compliance review.
    pub async fn get_violations(
        &self,
        limit: i64,
    ) -> Result<Vec<ClassificationAuditEvent>, sqlx::Error> {
        type Row = (
            Uuid,
            String,
            String,
            String,
            String,
            Option<String>,
            Option<String>,
            Option<String>,
            DateTime<Utc>,
        );
        let rows: Vec<Row> = sqlx::query_as(
                r#"
                SELECT id, event_kind, field_name, tier, context,
                       actor, request_id, detail, occurred_at
                FROM data_classification_audit
                WHERE event_kind = 'policy_violation'
                ORDER BY occurred_at DESC
                LIMIT $1
                "#,
            )
            .bind(limit)
            .fetch_all(&self.pool)
            .await?;

        Ok(rows
            .into_iter()
            .map(|(id, _kind, field_name, tier, context, actor, request_id, detail, occurred_at)| {
                ClassificationAuditEvent {
                    id,
                    event_kind: AuditEventKind::PolicyViolation,
                    field_name,
                    tier,
                    context,
                    actor,
                    request_id,
                    detail,
                    occurred_at,
                }
            })
            .collect())
    }

    /// Count violations in the last N hours — used by compliance dashboards.
    pub async fn violation_count_last_hours(&self, hours: i64) -> Result<i64, sqlx::Error> {
        let interval = format!("{} hours", hours);
        let row: (i64,) = sqlx::query_as(
            r#"
            SELECT COUNT(*)
            FROM data_classification_audit
            WHERE event_kind = 'policy_violation'
              AND occurred_at >= now() - $1::interval
            "#,
        )
        .bind(interval)
        .fetch_one(&self.pool)
        .await?;

        Ok(row.0)
    }
}

// ---------------------------------------------------------------------------
// In-process violation reporter (no DB dependency)
// ---------------------------------------------------------------------------

/// Report a policy violation to the structured log.
///
/// This is the lightweight path used in hot code paths where a DB write
/// would add unacceptable latency.  The DB-backed repository should be
/// used for compliance-critical events.
pub fn report_violation(
    field: DataField,
    context: TransmissionContext,
    reason: &str,
    request_id: Option<&str>,
) {
    tracing::error!(
        classification_event = "policy_violation",
        field = ?field,
        tier = field.tier().label(),
        context = ?context,
        reason = reason,
        request_id = request_id,
        "DATA_CLASSIFICATION_POLICY_VIOLATION"
    );
}

/// Report a field access audit event to the structured log.
pub fn report_access(
    field: DataField,
    context: TransmissionContext,
    actor: Option<&str>,
    request_id: Option<&str>,
) {
    if field.tier().requires_access_audit() {
        tracing::info!(
            classification_event = "field_access",
            field = ?field,
            tier = field.tier().label(),
            context = ?context,
            actor = actor,
            request_id = request_id,
            "DATA_CLASSIFICATION_FIELD_ACCESS"
        );
    }
}
