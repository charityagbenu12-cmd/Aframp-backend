/// Stellar Timebound Guard for Mint Transactions
///
/// Enforces two rules before any mint transaction is submitted to Stellar:
///
///   Rule 1 — SLA Guard:
///     If the internal SLA has already been breached (status = expired, or
///     sla_stage = expired), block submission entirely. No transaction should
///     hit the Stellar ledger after the internal SLA deadline.
///
///   Rule 2 — Timebound Registration:
///     Every mint transaction envelope must have a `time_bounds` window that
///     aligns with the internal `expires_at`. The guard records the exact
///     [min_time, max_time] in `mint_stellar_timebounds` for auditability.
///
///   Rule 3 — Timeout Detection:
///     The SLA worker calls `detect_timeouts()` to mark any timebound window
///     that has passed without a confirmed Stellar transaction as
///     `TIMEOUT_FAILED`, and transitions the internal record accordingly.
use chrono::{DateTime, Utc};
use serde_json::json;
use sqlx::PgPool;
use tracing::{error, info, warn};
use uuid::Uuid;

/// Maximum timebound window for a mint transaction (must be ≤ SLA expiry).
/// We use 23 hours so the window closes 1 hour before the 24-hour SLA hard limit.
const TIMEBOUND_WINDOW_SECS: u64 = 23 * 3600;

#[derive(Debug)]
pub enum TimeboundError {
    /// Internal SLA already breached — do not submit to Stellar.
    SlaBreached { reason: String },
    /// Timebound window has already passed.
    WindowExpired { expired_at: DateTime<Utc> },
    /// Database error.
    Database(String),
}

impl std::fmt::Display for TimeboundError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SlaBreached { reason } => write!(f, "SLA breached: {reason}"),
            Self::WindowExpired { expired_at } => {
                write!(f, "Timebound window expired at {expired_at}")
            }
            Self::Database(e) => write!(f, "Database error: {e}"),
        }
    }
}

/// The computed timebound window to embed in the Stellar XDR envelope.
#[derive(Debug, Clone)]
pub struct TimeboundWindow {
    /// Unix timestamp for `TimeBounds.min_time`
    pub min_time_unix: u64,
    /// Unix timestamp for `TimeBounds.max_time`
    pub max_time_unix: u64,
    /// Duration in seconds (max_time - min_time)
    pub window_secs: u64,
}

pub struct MintTimeboundGuard {
    db: PgPool,
}

impl MintTimeboundGuard {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    // ── Public API ────────────────────────────────────────────────────────────

    /// Pre-submission check.
    ///
    /// Call this BEFORE building the Stellar transaction envelope.
    /// Returns the timebound window to embed in the XDR, or an error
    /// that must block submission.
    ///
    /// On success, records the window in `mint_stellar_timebounds`.
    pub async fn assert_submittable(
        &self,
        mint_request_id: Uuid,
        sla_expires_at: DateTime<Utc>,
    ) -> Result<TimeboundWindow, TimeboundError> {
        let now = Utc::now();

        // ── Rule 1: SLA guard ─────────────────────────────────────────────────
        let sla_row = sqlx::query!(
            r#"
            SELECT mr.status, ss.stage AS sla_stage
            FROM mint_requests mr
            JOIN mint_sla_state ss ON ss.mint_request_id = mr.id
            WHERE mr.id = $1
            "#,
            mint_request_id,
        )
        .fetch_optional(&self.db)
        .await
        .map_err(|e| TimeboundError::Database(e.to_string()))?;

        if let Some(row) = sla_row {
            if row.status == "expired" || row.sla_stage == "expired" {
                error!(
                    mint_request_id = %mint_request_id,
                    status = %row.status,
                    sla_stage = %row.sla_stage,
                    "Stellar submission blocked: SLA already breached"
                );
                return Err(TimeboundError::SlaBreached {
                    reason: format!(
                        "Request status='{}', sla_stage='{}'. \
                         Expired requests cannot be submitted to Stellar.",
                        row.status, row.sla_stage
                    ),
                });
            }
        }

        // ── Rule 2: Timebound window ──────────────────────────────────────────
        // max_time = min(sla_expires_at, now + TIMEBOUND_WINDOW_SECS)
        let window_end = now + chrono::Duration::seconds(TIMEBOUND_WINDOW_SECS as i64);
        let effective_max = if sla_expires_at < window_end {
            sla_expires_at
        } else {
            window_end
        };

        if effective_max <= now {
            return Err(TimeboundError::WindowExpired {
                expired_at: effective_max,
            });
        }

        let min_time_unix = now.timestamp() as u64;
        let max_time_unix = effective_max.timestamp() as u64;
        let window_secs = max_time_unix - min_time_unix;

        // ── Persist the timebound record ──────────────────────────────────────
        sqlx::query!(
            r#"
            INSERT INTO mint_stellar_timebounds
                (mint_request_id, min_time_unix, max_time_unix, sla_expires_at)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (mint_request_id) DO UPDATE SET
                min_time_unix   = EXCLUDED.min_time_unix,
                max_time_unix   = EXCLUDED.max_time_unix,
                sla_expires_at  = EXCLUDED.sla_expires_at,
                is_timeout_failed = FALSE,
                timeout_detected_at = NULL
            "#,
            mint_request_id,
            min_time_unix as i64,
            max_time_unix as i64,
            sla_expires_at,
        )
        .execute(&self.db)
        .await
        .map_err(|e| TimeboundError::Database(e.to_string()))?;

        // Append to escalation log for auditability
        sqlx::query!(
            r#"
            INSERT INTO mint_escalation_log
                (mint_request_id, action, elapsed_hours, notified_targets, metadata)
            VALUES ($1, 'stellar_timebound_set', 0, '[]', $2)
            "#,
            mint_request_id,
            json!({
                "min_time_unix": min_time_unix,
                "max_time_unix": max_time_unix,
                "window_secs": window_secs,
                "sla_expires_at": sla_expires_at.to_rfc3339(),
            }),
        )
        .execute(&self.db)
        .await
        .map_err(|e| TimeboundError::Database(e.to_string()))?;

        info!(
            mint_request_id = %mint_request_id,
            min_time_unix,
            max_time_unix,
            window_secs,
            "Stellar timebound window registered"
        );

        Ok(TimeboundWindow {
            min_time_unix,
            max_time_unix,
            window_secs,
        })
    }

    /// Detect and mark any timebound windows that have expired without a
    /// confirmed Stellar transaction. Called by the SLA worker each cycle.
    ///
    /// For each expired-but-unconfirmed window:
    ///   - Sets `is_timeout_failed = TRUE` in `mint_stellar_timebounds`
    ///   - Transitions the mint_request to `expired` (if still pending)
    ///   - Appends `stellar_timeout_failed` to the escalation log
    pub async fn detect_timeouts(&self) -> Result<usize, String> {
        let now_unix = Utc::now().timestamp();

        // Find all windows that have passed without a stellar_tx_hash
        let expired_windows = sqlx::query!(
            r#"
            SELECT tb.mint_request_id, tb.max_time_unix, mr.status
            FROM mint_stellar_timebounds tb
            JOIN mint_requests mr ON mr.id = tb.mint_request_id
            WHERE tb.max_time_unix < $1
              AND tb.is_timeout_failed = FALSE
              AND mr.stellar_tx_hash IS NULL
              AND mr.status NOT IN ('executed', 'rejected', 'expired')
            "#,
            now_unix,
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| format!("Failed to query expired timebounds: {e}"))?;

        let count = expired_windows.len();

        for row in expired_windows {
            let mut tx = self
                .db
                .begin()
                .await
                .map_err(|e| format!("TX begin failed: {e}"))?;

            // Mark timebound as failed
            sqlx::query!(
                r#"
                UPDATE mint_stellar_timebounds
                   SET is_timeout_failed = TRUE, timeout_detected_at = NOW()
                 WHERE mint_request_id = $1
                "#,
                row.mint_request_id,
            )
            .execute(&mut *tx)
            .await
            .map_err(|e| format!("Timebound update failed: {e}"))?;

            // Transition mint request to expired
            sqlx::query!(
                r#"
                UPDATE mint_requests
                   SET status = 'expired', updated_at = NOW()
                 WHERE id = $1
                   AND status NOT IN ('executed', 'rejected', 'expired')
                "#,
                row.mint_request_id,
            )
            .execute(&mut *tx)
            .await
            .map_err(|e| format!("mint_requests update failed: {e}"))?;

            // Append to escalation log
            sqlx::query!(
                r#"
                INSERT INTO mint_escalation_log
                    (mint_request_id, action, elapsed_hours, notified_targets, metadata)
                VALUES ($1, 'stellar_timeout_failed', 0, '[]', $2)
                "#,
                row.mint_request_id,
                json!({
                    "max_time_unix": row.max_time_unix,
                    "previous_status": row.status,
                }),
            )
            .execute(&mut *tx)
            .await
            .map_err(|e| format!("Escalation log failed: {e}"))?;

            // Append to mint audit log
            sqlx::query!(
                r#"
                INSERT INTO mint_audit_log
                    (mint_request_id, actor_id, event_type, from_status, to_status, payload)
                VALUES ($1, 'sla_worker', 'stellar_timeout_failed', $2, 'expired', $3)
                "#,
                row.mint_request_id,
                row.status,
                json!({ "max_time_unix": row.max_time_unix }),
            )
            .execute(&mut *tx)
            .await
            .map_err(|e| format!("Audit log failed: {e}"))?;

            tx.commit()
                .await
                .map_err(|e| format!("TX commit failed: {e}"))?;

            warn!(
                mint_request_id = %row.mint_request_id,
                max_time_unix = row.max_time_unix,
                "Stellar timebound expired without confirmed transaction — marked TIMEOUT_FAILED"
            );
        }

        Ok(count)
    }
}

// ── Integration with CngnPaymentBuilder ──────────────────────────────────────
//
// Usage pattern in the mint execution path:
//
//   let guard = MintTimeboundGuard::new(db.clone());
//   let window = guard.assert_submittable(mint_request_id, request.expires_at).await?;
//
//   let builder = CngnPaymentBuilder::new(stellar_client)
//       .with_timeout(Duration::from_secs(window.window_secs));
//
//   let draft = builder.build_payment(source, dest, amount, memo, None).await?;
//   // The builder's build_unsigned_transaction already sets TimeBounds from
//   // the timeout field, so window.window_secs flows directly into the XDR.
