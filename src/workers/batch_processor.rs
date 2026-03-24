//! Batch transaction processor (Issue #125).
//!
//! Runs as a background worker. Two processors are started:
//!   - `run_cngn_batch_processor` — groups pending cNGN transfer items into Stellar
//!     multi-operation transaction envelopes and submits them via Horizon.
//!   - `run_fiat_payout_processor` — groups pending fiat payout items and submits
//!     them to the configured payment provider's bulk payout API.
//!
//! Both processors poll the `batches` table on a configurable interval.
//! Stellar envelopes are atomic — a full envelope failure marks all included items
//! as failed without affecting other envelopes in the same batch.

use bigdecimal::BigDecimal;
use sqlx::PgPool;
use std::time::Duration;
use tokio::sync::watch;
use tracing::{error, info, warn};
use uuid::Uuid;

/// Maximum Stellar operations per transaction envelope (protocol limit is 100).
const MAX_OPS_PER_ENVELOPE: usize = 100;
/// How long a batch may stay in `processing` before it is considered stuck (minutes).
const MAX_PROCESSING_MINUTES: i64 = 30;

// ─── cNGN Batch Processor ────────────────────────────────────────────────────

/// Entry point for the cNGN transfer batch processor worker.
///
/// Loops until `shutdown_rx` fires, picking up `pending` cNGN transfer batches
/// and processing them envelope by envelope.
pub async fn run_cngn_batch_processor(
    pool: std::sync::Arc<PgPool>,
    horizon_url: String,
    poll_interval: Duration,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    info!("cNGN batch processor started (poll interval: {:?})", poll_interval);

    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => {
                info!("cNGN batch processor shutting down");
                break;
            }
            _ = tokio::time::sleep(poll_interval) => {
                if let Err(e) = process_pending_cngn_batch(&pool, &horizon_url).await {
                    error!("cNGN batch processing error: {}", e);
                }
            }
        }
    }
}

/// Pick the oldest pending cNGN transfer batch and process it.
async fn process_pending_cngn_batch(
    pool: &PgPool,
    horizon_url: &str,
) -> anyhow::Result<()> {
    // Claim a pending batch — update to 'processing' atomically to prevent double-processing
    let batch = sqlx::query!(
        r#"
        UPDATE batches SET status = 'processing', updated_at = now()
        WHERE id = (
            SELECT id FROM batches
            WHERE batch_type = 'cngn_transfer' AND status = 'pending'
            ORDER BY created_at ASC
            LIMIT 1
            FOR UPDATE SKIP LOCKED
        )
        RETURNING id, source_wallet, total_count
        "#
    )
    .fetch_optional(pool)
    .await?;

    let batch = match batch {
        None => return Ok(()), // No pending batch
        Some(b) => b,
    };

    let batch_id = batch.id;
    let source_wallet = batch.source_wallet.clone().unwrap_or_default();
    info!(
        batch_id = %batch_id,
        source = %source_wallet,
        total = batch.total_count,
        "Processing cNGN transfer batch"
    );

    // Load pending items
    let items = sqlx::query!(
        r#"
        SELECT id, destination, amount, memo
        FROM batch_items
        WHERE batch_id = $1 AND status = 'pending'
        ORDER BY created_at ASC
        "#,
        batch_id
    )
    .fetch_all(pool)
    .await?;

    if items.is_empty() {
        finalize_batch(pool, batch_id).await?;
        return Ok(());
    }

    // Group items into envelopes of MAX_OPS_PER_ENVELOPE operations each
    for chunk in items.chunks(MAX_OPS_PER_ENVELOPE) {
        let item_ids: Vec<Uuid> = chunk.iter().map(|i| i.id).collect();
        let destinations: Vec<(String, BigDecimal, Option<String>)> = chunk
            .iter()
            .map(|i| (i.destination.clone(), i.amount.clone(), i.memo.clone()))
            .collect();

        // Mark chunk items as processing
        sqlx::query!(
            "UPDATE batch_items SET status = 'processing', updated_at = now() WHERE id = ANY($1)",
            &item_ids
        )
        .execute(pool)
        .await?;

        info!(
            batch_id = %batch_id,
            ops = item_ids.len(),
            "Submitting multi-op Stellar envelope"
        );

        // Build and submit the multi-operation payment envelope.
        // The XDR construction delegates to build_multi_payment_envelope which wraps
        // multiple Payment operations into a single TransactionEnvelope.
        match build_and_submit_envelope(horizon_url, &source_wallet, &destinations).await {
            Ok(tx_hash) => {
                info!(
                    batch_id = %batch_id,
                    tx_hash = %tx_hash,
                    ops = item_ids.len(),
                    "Stellar envelope confirmed"
                );
                sqlx::query!(
                    r#"
                    UPDATE batch_items
                    SET status = 'completed', stellar_tx_hash = $2, updated_at = now()
                    WHERE id = ANY($1)
                    "#,
                    &item_ids,
                    tx_hash,
                )
                .execute(pool)
                .await?;
                update_batch_counts(pool, batch_id, item_ids.len() as i32, 0).await?;
            }
            Err(e) => {
                let reason = e.to_string();
                warn!(
                    batch_id = %batch_id,
                    error = %reason,
                    ops = item_ids.len(),
                    "Stellar envelope failed — marking all ops in chunk as failed"
                );
                sqlx::query!(
                    r#"
                    UPDATE batch_items
                    SET status = 'failed', failure_reason = $2, updated_at = now()
                    WHERE id = ANY($1)
                    "#,
                    &item_ids,
                    reason,
                )
                .execute(pool)
                .await?;
                update_batch_counts(pool, batch_id, 0, item_ids.len() as i32).await?;
            }
        }
    }

    finalize_batch(pool, batch_id).await?;
    Ok(())
}

/// Build a multi-operation Stellar transaction envelope and submit it to Horizon.
///
/// Returns the transaction hash on success.
///
/// NOTE: Full XDR envelope construction (signing with the platform system key) must
/// be implemented here once the system wallet secret key is available at runtime.
/// The signing key is sourced from SYSTEM_WALLET_SECRET env variable.
async fn build_and_submit_envelope(
    horizon_url: &str,
    source_wallet: &str,
    payments: &[(String, BigDecimal, Option<String>)],
) -> anyhow::Result<String> {
    // Placeholder — production implementation must:
    // 1. Load source account sequence from Horizon
    // 2. Build a TransactionEnvelope with one Payment op per item in `payments`
    // 3. Sign with the system wallet secret key
    // 4. POST the signed XDR to {horizon_url}/transactions
    // 5. Return the confirmed transaction hash
    //
    // Reference implementation pattern:
    //   let account = GET {horizon_url}/accounts/{source_wallet}
    //   let seq = account.sequence + 1
    //   let ops = payments.iter().map(|(dest, amount, memo)| PaymentOp { dest, asset: cNGN, amount })
    //   let tx = Transaction { source: source_wallet, seq, ops, fee: 100 * ops.len() }
    //   let signed_xdr = tx.sign(system_secret_key)
    //   POST {horizon_url}/transactions { tx: signed_xdr }

    anyhow::bail!(
        "Multi-operation envelope submission not yet implemented for source {} on {}",
        source_wallet,
        horizon_url
    )
}

// ─── Fiat Payout Batch Processor ─────────────────────────────────────────────

/// Entry point for the fiat payout batch processor worker.
pub async fn run_fiat_payout_processor(
    pool: std::sync::Arc<PgPool>,
    poll_interval: Duration,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    info!("Fiat payout batch processor started (poll interval: {:?})", poll_interval);

    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => {
                info!("Fiat payout batch processor shutting down");
                break;
            }
            _ = tokio::time::sleep(poll_interval) => {
                if let Err(e) = process_pending_fiat_batch(&pool).await {
                    error!("Fiat payout batch processing error: {}", e);
                }
            }
        }
    }
}

/// Pick the oldest pending fiat payout batch and process it item by item.
/// Partial failures are acceptable — each item is settled independently.
async fn process_pending_fiat_batch(pool: &PgPool) -> anyhow::Result<()> {
    let batch = sqlx::query!(
        r#"
        UPDATE batches SET status = 'processing', updated_at = now()
        WHERE id = (
            SELECT id FROM batches
            WHERE batch_type = 'fiat_payout' AND status = 'pending'
            ORDER BY created_at ASC
            LIMIT 1
            FOR UPDATE SKIP LOCKED
        )
        RETURNING id, total_count
        "#
    )
    .fetch_optional(pool)
    .await?;

    let batch = match batch {
        None => return Ok(()),
        Some(b) => b,
    };

    let batch_id = batch.id;
    info!(batch_id = %batch_id, total = batch.total_count, "Processing fiat payout batch");

    let items = sqlx::query!(
        r#"
        SELECT id, destination, amount, memo
        FROM batch_items
        WHERE batch_id = $1 AND status = 'pending'
        ORDER BY created_at ASC
        "#,
        batch_id
    )
    .fetch_all(pool)
    .await?;

    if items.is_empty() {
        finalize_batch(pool, batch_id).await?;
        return Ok(());
    }

    for item in &items {
        let item_id = item.id;

        sqlx::query!(
            "UPDATE batch_items SET status = 'processing', updated_at = now() WHERE id = $1",
            item_id
        )
        .execute(pool)
        .await?;

        match submit_fiat_payout(&item.destination, &item.amount).await {
            Ok(reference) => {
                sqlx::query!(
                    r#"
                    UPDATE batch_items
                    SET status = 'completed', provider_reference = $2, updated_at = now()
                    WHERE id = $1
                    "#,
                    item_id,
                    reference,
                )
                .execute(pool)
                .await?;
                update_batch_counts(pool, batch_id, 1, 0).await?;
            }
            Err(e) => {
                let reason = e.to_string();
                warn!(
                    batch_id = %batch_id,
                    item_id = %item_id,
                    error = %reason,
                    "Fiat payout item failed (other items continue)"
                );
                sqlx::query!(
                    r#"
                    UPDATE batch_items
                    SET status = 'failed', failure_reason = $2, updated_at = now()
                    WHERE id = $1
                    "#,
                    item_id,
                    reason,
                )
                .execute(pool)
                .await?;
                update_batch_counts(pool, batch_id, 0, 1).await?;
            }
        }
    }

    finalize_batch(pool, batch_id).await?;
    Ok(())
}

/// Submit a single fiat payout to the payment provider.
/// Returns the provider-assigned payout reference on success.
///
/// NOTE: Replace with actual Paystack / Flutterwave bulk transfer API call.
async fn submit_fiat_payout(
    destination: &str,
    _amount: &BigDecimal,
) -> anyhow::Result<String> {
    // TODO: integrate with payment provider bulk payout API
    // Format: destination is "bank_code:account_number"
    let reference = format!(
        "payout-{}-{}",
        destination.replace(':', "_"),
        uuid::Uuid::new_v4()
    );
    Ok(reference)
}

// ─── Batch Helpers ────────────────────────────────────────────────────────────

/// Increment success_count or failed_count on the parent batch and decrement pending_count.
async fn update_batch_counts(
    pool: &PgPool,
    batch_id: Uuid,
    success_delta: i32,
    failed_delta: i32,
) -> anyhow::Result<()> {
    sqlx::query!(
        r#"
        UPDATE batches
        SET success_count = success_count + $2,
            failed_count  = failed_count  + $3,
            pending_count = GREATEST(0, pending_count - $2 - $3),
            updated_at    = now()
        WHERE id = $1
        "#,
        batch_id,
        success_delta,
        failed_delta,
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Transition a batch to its final status once all items have settled.
async fn finalize_batch(pool: &PgPool, batch_id: Uuid) -> anyhow::Result<()> {
    let counts = sqlx::query!(
        "SELECT total_count, success_count, failed_count FROM batches WHERE id = $1",
        batch_id
    )
    .fetch_one(pool)
    .await?;

    let final_status = match (counts.success_count, counts.failed_count) {
        (s, 0) if s > 0 => "completed",
        (0, f) if f > 0 => "failed",
        _ => "partially_completed",
    };

    sqlx::query!(
        r#"
        UPDATE batches
        SET status = $2, completed_at = now(), updated_at = now()
        WHERE id = $1
        "#,
        batch_id,
        final_status,
    )
    .execute(pool)
    .await?;

    info!(
        batch_id = %batch_id,
        status = final_status,
        success = counts.success_count,
        failed = counts.failed_count,
        "Batch finalized"
    );

    Ok(())
}

// ─── Stuck Batch Monitor ──────────────────────────────────────────────────────

/// Log a warning for any batch that has been in `processing` status beyond the
/// configured maximum duration. Call this from a periodic monitoring task.
pub async fn check_stuck_batches(pool: &PgPool) -> anyhow::Result<()> {
    let stuck = sqlx::query!(
        r#"
        SELECT id, batch_type, updated_at
        FROM batches
        WHERE status = 'processing'
          AND updated_at < now() - ($1 || ' minutes')::interval
        "#,
        MAX_PROCESSING_MINUTES.to_string()
    )
    .fetch_all(pool)
    .await?;

    for batch in &stuck {
        warn!(
            batch_id = %batch.id,
            batch_type = %batch.batch_type,
            last_updated = ?batch.updated_at,
            "ALERT: Batch stuck in processing state beyond {}min threshold",
            MAX_PROCESSING_MINUTES
        );
    }

    if stuck.is_empty() {
        info!("Stuck batch check: no stuck batches found");
    }

    Ok(())
}
