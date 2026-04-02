//! Mint & Burn Event Monitoring Worker.
//!
//! Subscribes to the Stellar Horizon SSE stream for the cNGN issuer account,
//! classifies incoming operations as Mint, Burn, or Clawback, persists them
//! atomically to the database, and exposes Prometheus metrics and structured
//! logs for production observability.
//!
//! Requirements: 1.1–1.5, 2.5, 3.2, 4.4, 4.5, 5.4, 6.1–6.6, 8.4, 8.5,
//!               9.1–9.4

use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use chrono::Utc;
use futures::StreamExt;
use sqlx::PgPool;
use tokio::sync::watch;
use uuid::Uuid;

use crate::mint_burn::{
    classifier::{self, OperationType},
    memo_parser::{self, ParsedMemo},
    metrics::MintBurnMetrics,
    models::{MintBurnConfig, MintBurnError, ProcessedEvent, UnmatchedEvent},
    repository::MintBurnRepository,
};

// ---------------------------------------------------------------------------
// MintBurnWorker
// ---------------------------------------------------------------------------

/// Background worker that subscribes to the Stellar Horizon SSE stream and
/// processes Mint, Burn, and Clawback events.
pub struct MintBurnWorker {
    config: MintBurnConfig,
    pool: PgPool,
    metrics: Arc<MintBurnMetrics>,
    /// Shutdown signal receiver. The worker exits its run loop when the sender
    /// is dropped or sends `true`.
    shutdown_rx: watch::Receiver<bool>,
}

impl MintBurnWorker {
    /// Create a new worker. The returned `shutdown_tx` should be held by the
    /// application; dropping it (or sending `true`) triggers graceful shutdown.
    pub fn new(
        config: MintBurnConfig,
        pool: PgPool,
        metrics: Arc<MintBurnMetrics>,
    ) -> (Self, watch::Sender<bool>) {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        (
            Self {
                config,
                pool,
                metrics,
                shutdown_rx,
            },
            shutdown_tx,
        )
    }

    /// Spawn the worker as a `tokio` task.
    ///
    /// Returns the `JoinHandle` for lifecycle management (Requirement 9.1).
    pub fn spawn(self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            self.run().await;
        })
    }

    // -----------------------------------------------------------------------
    // stream_url
    // -----------------------------------------------------------------------

    /// Build the Horizon SSE URL for the given cursor (Requirement 1.2, 1.3).
    ///
    /// Format: `{horizon_base_url}/accounts/{issuer_id}/operations?cursor={cursor}`
    fn stream_url(&self, cursor: &str) -> String {
        format!(
            "{}/accounts/{}/operations?cursor={}",
            self.config.horizon_base_url.trim_end_matches('/'),
            self.config.issuer_id,
            cursor,
        )
    }

    // -----------------------------------------------------------------------
    // connect
    // -----------------------------------------------------------------------

    /// Open an SSE byte stream to the Horizon endpoint (Requirement 1.1).
    async fn connect(
        &self,
        cursor: &str,
    ) -> Result<impl futures::Stream<Item = reqwest::Result<Bytes>>, MintBurnError> {
        let url = self.stream_url(cursor);
        let client = reqwest::Client::new();
        let response = client
            .get(&url)
            .header("Accept", "text/event-stream")
            .send()
            .await
            .map_err(|e| MintBurnError::StreamError(e.to_string()))?;

        if !response.status().is_success() {
            return Err(MintBurnError::StreamError(format!(
                "Horizon returned HTTP {}",
                response.status()
            )));
        }

        Ok(response.bytes_stream())
    }

    // -----------------------------------------------------------------------
    // process_event
    // -----------------------------------------------------------------------

    /// Process a single SSE `data:` payload (Requirement 1.4, 2.x, 3.x, 4.x,
    /// 5.1, 7.x, 8.x).
    ///
    /// Returns `Ok(())` on success or on gracefully-handled non-fatal errors
    /// (duplicate, unmatched, missing field). Returns `Err` only for errors
    /// that should be logged by the caller but do not terminate the worker.
    pub async fn process_event(&self, raw: &str) -> Result<(), MintBurnError> {
        let repo = MintBurnRepository::new(self.pool.clone());

        // 1. Deserialise HorizonOperation
        let op: crate::mint_burn::models::HorizonOperation =
            serde_json::from_str(raw).map_err(|e| MintBurnError::ParseError(e.to_string()))?;

        // Increment operations_received counter
        self.metrics.operations_received_total.inc();

        // Update seconds_since_last_message gauge (reset to 0 on each event)
        self.metrics.seconds_since_last_message.set(0.0);

        // 2. Validate created_at presence (Requirement 7.3)
        // created_at is non-optional in HorizonOperation, so if deserialization
        // succeeded it is present. However we still record the chain timestamp.
        let created_at_chain = op.created_at;

        // 3. Classify operation (Requirement 2.x, 1.4)
        let op_type = classifier::classify(&op, &self.config.issuer_id);

        // 4. Filter: skip Other and SelfTransfer (Requirement 1.4, 2.4)
        match &op_type {
            OperationType::Other => {
                tracing::debug!(
                    transaction_hash = %op.transaction_hash,
                    op_type = %op.op_type,
                    "Skipping non-payment/clawback operation"
                );
                return Ok(());
            }
            OperationType::SelfTransfer => {
                tracing::debug!(
                    transaction_hash = %op.transaction_hash,
                    reason = "self-transfer",
                    "Discarding self-transfer operation (Requirement 2.4)"
                );
                return Ok(());
            }
            _ => {}
        }

        // Emit structured log for classified operation (Requirement 2.5)
        tracing::info!(
            op_type = ?op_type,
            transaction_hash = %op.transaction_hash,
            ledger_id = op.ledger,
            created_at = %created_at_chain,
            "Classified operation"
        );

        // 5. Idempotency check (fast pre-filter — definitive guard is ON CONFLICT in commit_event)
        if repo.is_duplicate(&op.transaction_hash).await? {
            tracing::info!(
                transaction_hash = %op.transaction_hash,
                "Duplicate operation skipped (pre-check)"
            );
            self.metrics.duplicates_skipped_total.inc();
            return Ok(());
        }

        // Start latency timer (Requirement 8.3)
        let latency_start = Instant::now();

        // 6. Parse memo (Requirement 4.1, 4.2)
        let parsed_memo = memo_parser::parse_memo(op.transaction_memo.as_deref());

        // Determine operation_type string and destination_account
        let (op_type_str, destination_account) = match &op_type {
            OperationType::Mint => ("mint", op.to.clone()),
            OperationType::Burn => ("burn", op.to.clone()),
            OperationType::Clawback => ("clawback", op.account.clone()),
            _ => unreachable!("Other/SelfTransfer already filtered above"),
        };

        // 7. Handle Missing or Unparseable memo → insert_unmatched (Req 4.4)
        match &parsed_memo {
            ParsedMemo::Missing | ParsedMemo::Unparseable(_) => {
                let raw_op = serde_json::to_value(&op)
                    .unwrap_or(serde_json::Value::String(raw.to_owned()));

                let unmatched = UnmatchedEvent {
                    id: Uuid::new_v4(),
                    transaction_hash: op.transaction_hash.clone(),
                    raw_memo: op.transaction_memo.clone(),
                    raw_operation: raw_op,
                    recorded_at: Utc::now(),
                };

                if let Err(e) = repo.insert_unmatched(&unmatched).await {
                    tracing::warn!(
                        error = %e,
                        transaction_hash = %op.transaction_hash,
                        "Failed to insert unmatched event; continuing"
                    );
                } else {
                    tracing::warn!(
                        transaction_hash = %op.transaction_hash,
                        raw_memo = ?op.transaction_memo,
                        "Unmatched event: memo missing or unparseable (Requirement 4.4)"
                    );
                    self.metrics.unmatched_events_total.inc();
                }
                return Ok(());
            }
            _ => {}
        }

        // 8. Build ProcessedEvent and commit (Requirement 3.3, 4.3, 5.1)
        let parsed_id = match &parsed_memo {
            ParsedMemo::MintId(id) | ParsedMemo::RedemptionId(id) => Some(id.clone()),
            _ => None,
        };

        let event = ProcessedEvent {
            id: Uuid::new_v4(),
            transaction_hash: op.transaction_hash.clone(),
            operation_type: op_type_str.to_owned(),
            ledger_id: op.ledger,
            created_at_chain,
            processed_at: Utc::now(),
            asset_code: op.asset_code.clone(),
            asset_issuer: op.asset_issuer.clone(),
            amount: op.amount.clone(),
            source_account: op.source_account.clone(),
            destination_account,
            raw_memo: op.transaction_memo.clone(),
            parsed_id,
        };

        let db_start = Instant::now();
        let commit_result = repo.commit_event(&event, &op.paging_token).await;
        let db_duration_ms = db_start.elapsed().as_millis();

        match commit_result {
            Ok(()) => {
                // Update type-specific counter (Requirement 8.1)
                match op_type {
                    OperationType::Mint => self.metrics.mint_events_total.inc(),
                    OperationType::Burn => self.metrics.burn_events_total.inc(),
                    OperationType::Clawback => self.metrics.clawback_events_total.inc(),
                    _ => {}
                }

                // Emit DB commit log (Requirement 8.5)
                tracing::info!(
                    transaction_hash = %op.transaction_hash,
                    operation_type = op_type_str,
                    db_duration_ms = db_duration_ms,
                    "Database transaction committed (Requirement 8.5)"
                );
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    transaction_hash = %op.transaction_hash,
                    "commit_event failed; event will be retried on reconnect"
                );
                return Err(e);
            }
        }

        // 9. Update processing_latency_seconds histogram (Requirement 8.3)
        let latency_secs = latency_start.elapsed().as_secs_f64();
        self.metrics.processing_latency_seconds.observe(latency_secs);

        Ok(())
    }

    // -----------------------------------------------------------------------
    // run
    // -----------------------------------------------------------------------

    /// Inner run loop — connects, reads SSE, reconnects on timeout/error.
    ///
    /// Never returns due to transient errors (Requirement 9.4).
    async fn run(mut self) {
        let repo = MintBurnRepository::new(self.pool.clone());
        let mut attempt: u32 = 0;
        let mut replayed_ops: u64 = 0;
        let mut catch_up_logged = false;

        loop {
            // Check shutdown signal
            if *self.shutdown_rx.borrow() {
                tracing::info!("MintBurnWorker received shutdown signal; exiting");
                break;
            }

            // Load cursor from DB (default to "now" if None) — Requirement 1.2, 1.3
            let cursor = match repo.load_cursor().await {
                Ok(Some(c)) => c,
                Ok(None) => "now".to_owned(),
                Err(e) => {
                    tracing::warn!(error = %e, "Failed to load cursor; defaulting to 'now'");
                    "now".to_owned()
                }
            };

            let url = self.stream_url(&cursor);

            // Emit stream connect log (Requirement 1.5)
            tracing::info!(
                issuer_id = %self.config.issuer_id,
                cursor = %cursor,
                url = %url,
                "Connecting to Horizon SSE stream (Requirement 1.5)"
            );

            // Connect to SSE stream
            let stream = match self.connect(&cursor).await {
                Ok(s) => {
                    // Update stream_connected gauge (Requirement 8.4)
                    self.metrics.stream_connected.set(1.0);
                    tracing::info!(
                        cursor = %cursor,
                        timestamp = %Utc::now(),
                        "Stream connection established (Requirement 8.4)"
                    );
                    attempt = 0; // reset backoff on successful connect
                    s
                }
                Err(e) => {
                    self.metrics.stream_connected.set(0.0);
                    tracing::warn!(
                        error = %e,
                        cursor = %cursor,
                        attempt = attempt,
                        reason = "connection_error",
                        "Reconnection attempt failed (Requirement 6.5)"
                    );
                    self.metrics.reconnect_attempts_total.inc();
                    let backoff = self.backoff_duration(attempt);
                    attempt = attempt.saturating_add(1);

                    tokio::select! {
                        _ = tokio::time::sleep(backoff) => {}
                        _ = self.shutdown_rx.changed() => {
                            tracing::info!("Shutdown during backoff; exiting");
                            break;
                        }
                    }
                    continue;
                }
            };

            // Pin the stream for use in the read loop
            tokio::pin!(stream);

            // SSE line buffer — accumulates bytes until we have complete lines
            let mut line_buf = String::new();
            let mut last_message_at = Instant::now();

            // SSE read loop
            loop {
                // Check shutdown
                if *self.shutdown_rx.borrow() {
                    tracing::info!("MintBurnWorker shutting down during SSE read");
                    self.metrics.stream_connected.set(0.0);
                    return;
                }

                // Update seconds_since_last_message gauge
                self.metrics
                    .seconds_since_last_message
                    .set(last_message_at.elapsed().as_secs_f64());

                // Read next chunk with heartbeat timeout (Requirement 6.2)
                let timeout_dur =
                    tokio::time::Duration::from_secs(self.config.heartbeat_timeout_secs);

                let chunk_result = tokio::select! {
                    result = tokio::time::timeout(timeout_dur, stream.next()) => result,
                    _ = self.shutdown_rx.changed() => {
                        tracing::info!("Shutdown signal during SSE read; exiting");
                        self.metrics.stream_connected.set(0.0);
                        return;
                    }
                };

                match chunk_result {
                    Err(_timeout) => {
                        // Heartbeat timeout — trigger reconnect (Requirement 6.2, 6.5)
                        self.metrics.stream_connected.set(0.0);
                        self.metrics.reconnect_attempts_total.inc();
                        tracing::warn!(
                            cursor = %cursor,
                            attempt = attempt,
                            reason = "heartbeat_timeout",
                            "Heartbeat timeout; reconnecting (Requirement 6.5)"
                        );
                        let backoff = self.backoff_duration(attempt);
                        attempt = attempt.saturating_add(1);
                        tokio::time::sleep(backoff).await;
                        break; // break inner loop → reconnect
                    }
                    Ok(None) => {
                        // Stream ended
                        self.metrics.stream_connected.set(0.0);
                        self.metrics.reconnect_attempts_total.inc();
                        tracing::warn!(
                            cursor = %cursor,
                            attempt = attempt,
                            reason = "stream_ended",
                            "SSE stream ended; reconnecting (Requirement 6.5)"
                        );
                        let backoff = self.backoff_duration(attempt);
                        attempt = attempt.saturating_add(1);
                        tokio::time::sleep(backoff).await;
                        break;
                    }
                    Ok(Some(Err(e))) => {
                        // Stream error — reconnect (Requirement 6.4, 6.5)
                        self.metrics.stream_connected.set(0.0);
                        self.metrics.reconnect_attempts_total.inc();
                        tracing::warn!(
                            error = %e,
                            cursor = %cursor,
                            attempt = attempt,
                            reason = "stream_error",
                            "SSE stream error; reconnecting (Requirement 6.5)"
                        );
                        let backoff = self.backoff_duration(attempt);
                        attempt = attempt.saturating_add(1);
                        tokio::time::sleep(backoff).await;
                        break;
                    }
                    Ok(Some(Ok(chunk))) => {
                        // Received data — update last_message timestamp
                        last_message_at = Instant::now();
                        self.metrics.seconds_since_last_message.set(0.0);

                        // Append chunk to line buffer and parse SSE lines
                        if let Ok(text) = std::str::from_utf8(&chunk) {
                            line_buf.push_str(text);
                        } else {
                            continue;
                        }

                        // Process all complete lines in the buffer
                        while let Some(newline_pos) = line_buf.find('\n') {
                            let line = line_buf[..newline_pos].trim_end_matches('\r').to_owned();
                            line_buf.drain(..=newline_pos);

                            // SSE line parser: extract data: payloads
                            if line.starts_with("event: hello") || line == "event:hello" {
                                // Horizon sends "event: hello" when the stream
                                // reaches the live ledger position — this is the
                                // correct catch-up completion signal.
                                if !catch_up_logged {
                                    tracing::info!(
                                        replayed_ops = replayed_ops,
                                        "Catch-up complete; stream is now live"
                                    );
                                    catch_up_logged = true;
                                }
                                continue;
                            }

                            if let Some(payload) = line.strip_prefix("data: ") {
                                let payload = payload.trim();
                                if payload.is_empty() {
                                    continue;
                                }

                                // Process the event (Requirement 9.4 — never terminate on error)
                                match self.process_event(payload).await {
                                    Ok(()) => {
                                        replayed_ops += 1;
                                    }
                                    Err(e) => {
                                        tracing::warn!(
                                            error = %e,
                                            "process_event error; continuing (Requirement 9.4)"
                                        );
                                    }
                                }
                            }
                            // Skip: "event:", "retry:", empty lines (heartbeat pings)
                        }
                    }
                }
            }

            // Reconnect success log (Requirement 6.6) — emitted at top of loop
            // after successful connect (already handled above with attempt = 0 reset).
            tracing::info!(
                cursor = %cursor,
                timestamp = %Utc::now(),
                "Reconnecting to Horizon SSE stream (Requirement 6.6)"
            );
        }

        // Worker termination log (Requirement 9.3)
        tracing::info!("MintBurnWorker terminated cleanly");
    }

    // -----------------------------------------------------------------------
    // backoff_duration
    // -----------------------------------------------------------------------

    /// Compute exponential backoff: `min(initial * 2^attempt, max)`.
    fn backoff_duration(&self, attempt: u32) -> tokio::time::Duration {
        let initial = self.config.reconnect_backoff_initial_secs;
        let max = self.config.reconnect_backoff_max_secs;
        let secs = initial.saturating_mul(1u64.saturating_shl(attempt.min(63)));
        tokio::time::Duration::from_secs(secs.min(max))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use prometheus::Registry;

    fn make_worker() -> MintBurnWorker {
        let config = MintBurnConfig {
            issuer_id: "GCEZWKCA5VLDNRLN3RPRJMRZOX3Z6G5CHCGZWM9CQJUQE3QLQNZJQE".to_owned(),
            horizon_base_url: "https://horizon-testnet.stellar.org".to_owned(),
            heartbeat_timeout_secs: 30,
            reconnect_backoff_max_secs: 60,
            reconnect_backoff_initial_secs: 1,
        };
        let registry = Registry::new();
        let metrics = Arc::new(MintBurnMetrics::new(&registry).unwrap());
        // We need a PgPool — use a dummy URL; pool won't be used in unit tests
        // that don't call DB methods.
        let pool = sqlx::PgPool::connect_lazy("postgres://localhost/test").unwrap();
        let (worker, _tx) = MintBurnWorker::new(config, pool, metrics);
        worker
    }

    // -----------------------------------------------------------------------
    // stream_url unit tests
    // -----------------------------------------------------------------------

    #[test]
    fn stream_url_contains_issuer_and_cursor() {
        let worker = make_worker();
        let url = worker.stream_url("12345");
        assert!(url.contains("/accounts/GCEZWKCA5VLDNRLN3RPRJMRZOX3Z6G5CHCGZWM9CQJUQE3QLQNZJQE/operations"));
        assert!(url.contains("cursor=12345"));
    }

    #[test]
    fn stream_url_with_now_cursor() {
        let worker = make_worker();
        let url = worker.stream_url("now");
        assert!(url.contains("cursor=now"));
    }

    #[test]
    fn stream_url_trims_trailing_slash_from_base() {
        let mut config = MintBurnConfig::default();
        config.issuer_id = "ISSUER".to_owned();
        config.horizon_base_url = "https://horizon.example.com/".to_owned();
        let registry = Registry::new();
        let metrics = Arc::new(MintBurnMetrics::new(&registry).unwrap());
        let pool = sqlx::PgPool::connect_lazy("postgres://localhost/test").unwrap();
        let (worker, _tx) = MintBurnWorker::new(config, pool, metrics);
        let url = worker.stream_url("abc");
        assert!(!url.contains("//accounts"), "double slash should not appear");
    }

    // -----------------------------------------------------------------------
    // backoff_duration unit tests
    // -----------------------------------------------------------------------

    #[test]
    fn backoff_attempt_0_returns_initial() {
        let worker = make_worker();
        assert_eq!(
            worker.backoff_duration(0),
            tokio::time::Duration::from_secs(1)
        );
    }

    #[test]
    fn backoff_attempt_1_returns_2_secs() {
        let worker = make_worker();
        assert_eq!(
            worker.backoff_duration(1),
            tokio::time::Duration::from_secs(2)
        );
    }

    #[test]
    fn backoff_caps_at_max() {
        let worker = make_worker();
        // attempt 10 → 1 * 2^10 = 1024, capped at 60
        assert_eq!(
            worker.backoff_duration(10),
            tokio::time::Duration::from_secs(60)
        );
    }

    // -----------------------------------------------------------------------
    // Property 9: Cursor URL Construction
    // Feature: mint-burn-event-monitoring, Property 9: Cursor URL Construction
    // Validates: Requirements 1.2, 1.3
    // -----------------------------------------------------------------------

    #[cfg(test)]
    mod prop_tests {
        use super::*;
        use proptest::prelude::*;

        fn make_worker_for_prop() -> MintBurnWorker {
            let config = MintBurnConfig {
                issuer_id: "ISSUER123".to_owned(),
                horizon_base_url: "https://horizon.example.com".to_owned(),
                heartbeat_timeout_secs: 30,
                reconnect_backoff_max_secs: 60,
                reconnect_backoff_initial_secs: 1,
            };
            let registry = Registry::new();
            let metrics = Arc::new(MintBurnMetrics::new(&registry).unwrap());
            let pool = sqlx::PgPool::connect_lazy("postgres://localhost/test").unwrap();
            let (worker, _tx) = MintBurnWorker::new(config, pool, metrics);
            worker
        }

        // Property 9: Cursor URL Construction
        // Feature: mint-burn-event-monitoring, Property 9: Cursor URL Construction
        proptest! {
            #![proptest_config(proptest::test_runner::Config::with_cases(256))]

            #[test]
            fn prop_cursor_url(cursor in "[a-zA-Z0-9_\\-]{1,64}") {
                // Feature: mint-burn-event-monitoring, Property 9: Cursor URL Construction
                // Validates: Requirements 1.2, 1.3
                let worker = make_worker_for_prop();
                let url = worker.stream_url(&cursor);
                // URL must contain cursor=<value>
                let expected_param = format!("cursor={}", cursor);
                prop_assert!(
                    url.contains(&expected_param),
                    "URL '{}' does not contain '{}'",
                    url,
                    expected_param
                );
                // URL must contain the issuer ID
                prop_assert!(url.contains("ISSUER123"));
                // URL must contain /operations
                prop_assert!(url.contains("/operations"));
            }

            #[test]
            fn prop_cursor_url_now_when_no_cursor(_dummy in 0u8..1u8) {
                // Feature: mint-burn-event-monitoring, Property 9: Cursor URL Construction
                // Validates: Requirement 1.3 — when no cursor persisted, use "now"
                let worker = make_worker_for_prop();
                let url = worker.stream_url("now");
                prop_assert!(url.contains("cursor=now"));
            }
        }

        // Property 8: Resilience to Malformed Operations
        // Feature: mint-burn-event-monitoring, Property 8: Resilience
        // Validates: Requirements 9.4
        proptest! {
            #![proptest_config(proptest::test_runner::Config::with_cases(256))]

            #[test]
            fn prop_malformed_op_resilience(raw in ".*") {
                // Feature: mint-burn-event-monitoring, Property 8: Resilience
                // Validates: Requirements 9.4
                // process_event on arbitrary strings must not panic.
                // We run this synchronously by creating a runtime.
                let rt = tokio::runtime::Runtime::new().unwrap();
                let worker = make_worker_for_prop();
                // The result can be Ok or Err — what matters is no panic.
                let _result = rt.block_on(worker.process_event(&raw));
                // If we reach here, no panic occurred.
            }
        }
    }
}
