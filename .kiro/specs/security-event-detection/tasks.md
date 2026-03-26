# Implementation Plan: Security Event Detection

## Overview

Implement the `src/security/` module as a real-time threat detection, alert management, and automated response subsystem. The pipeline flows: ingest → Redis Streams buffer → rule engine → alert manager → responder/notifier. All background tasks follow the existing `run(shutdown: watch::Receiver<bool>)` pattern.

## Tasks

- [ ] 1. Scaffold module structure and shared types
  - Create `src/security/mod.rs` exporting all sub-modules
  - Create `src/security/types.rs` with `SecurityEvent`, `Severity`, `DetectionRule`, `RuleCategory`, `ResponseAction`, `Alert`, `AlertStatus`, `ResponseActionRecord`, `SecurityIncident`, `IncidentStatus`, `TimelineEntry` structs and enums
  - Derive `serde::{Serialize, Deserialize}`, `sqlx::FromRow` where applicable; implement `Display` for `Severity` and `AlertStatus`
  - Add `proptest` to `[dev-dependencies]` in `Cargo.toml`
  - Wire `mod security;` into `src/main.rs` / `src/lib.rs`
  - _Requirements: 4.1, 6.1, 18.1, 27.1_

- [ ] 2. Database migrations
  - [ ] 2.1 Write migration: `security_events` partitioned table + initial monthly partition
    - SQL per design schema; include `CREATE INDEX` on `timestamp`
    - _Requirements: 4.2, 5.1_
  - [ ] 2.2 Write migration: `security_alerts` table + three indexes
    - `idx_security_alerts_status_severity`, `idx_security_alerts_created_at`, `idx_security_alerts_rule_actor`
    - _Requirements: 18.1, 18.2_
  - [ ] 2.3 Write migration: `security_incidents` table
    - _Requirements: 27.1_

- [ ] 3. Event ingestion layer
  - [ ] 3.1 Implement `EventNormaliser` in `src/security/ingestion/normaliser.rs`
    - Convert `RawAuditLogEvent`, `PrometheusAlertFiring`, `SecuritySignalPush` → `SecurityEvent`
    - Apply sentinel values (`"unknown"`, `Severity::Info`) for missing fields; log `tracing::warn!` per field
    - Write normalised event to `security:events` stream via `XADD ... MAXLEN ~ <max>`
    - Increment `aframp_security_events_ingested_total{event_type}` counter
    - _Requirements: 4.1, 4.2, 4.3, 4.4, 32.1_
  - [ ]* 3.2 Write property test for `EventNormaliser` — Property 1: Event Normalisation Completeness
    - **Property 1: For any valid inbound event, all required fields are non-empty and `event_detail` round-trips**
    - **Validates: Requirements 1.2, 2.3, 3.2, 4.1, 4.4**
  - [ ]* 3.3 Write property test for `EventNormaliser` — Property 2: Sentinel Value on Missing Field
    - **Property 2: Events with missing fields get sentinel values and are still written to the stream**
    - **Validates: Requirements 4.3**
  - [ ] 3.4 Implement `AuditLogSubscriber` in `src/security/ingestion/audit_subscriber.rs`
    - Subscribe to Redis pub/sub channel from issue #98 using `bb8-redis` pool
    - Track last acknowledged offset in `sec:audit_offset` Redis key
    - On disconnect, reconnect with exponential backoff (1s initial, 2× factor, 30s max) using `tokio::time::sleep`
    - Forward received messages to `EventNormaliser`
    - _Requirements: 1.1, 1.2, 1.3, 1.4_
  - [ ]* 3.5 Write property test for reconnection backoff — Property 3: Exponential Backoff Bounds
    - **Property 3: Each successive backoff interval ≥ 2× previous, never exceeds 30s**
    - **Validates: Requirements 1.3, 25.5**
  - [ ] 3.6 Implement `PrometheusAlertSubscriber` in `src/security/ingestion/prometheus_subscriber.rs`
    - Subscribe to internal `tokio::sync::broadcast` channel carrying `PrometheusAlertFiring`
    - Filter by configurable rule name allowlist; set `source_system = "prometheus"`, `actor_identity = "system"` when absent
    - Forward to `EventNormaliser`
    - _Requirements: 2.1, 2.2, 2.3, 2.4_
  - [ ] 3.7 Implement `DirectSignalEndpoint` in `src/security/ingestion/direct_signal.rs`
    - Axum handler accepting `SecuritySignalPush` JSON; validate schema, return `400` with structured error on failure
    - Increment `aframp_security_events_ingestion_errors_total{source_system}` on validation failure
    - Forward valid payloads to `EventNormaliser`
    - Mount route in router (internal only)
    - _Requirements: 3.1, 3.2, 3.3, 3.4_

- [ ] 4. Redis stream buffer observability
  - Implement buffer utilisation gauge: after each `XADD`, read stream length and compute `len / max_len`; set `aframp_security_event_stream_buffer_utilisation` gauge
  - Fire `SecurityEventStreamBufferHigh` Prometheus alert rule when gauge > configured threshold
  - _Requirements: 5.2, 5.3_

- [ ] 5. Rule engine — loader and hot-reload
  - [ ] 5.1 Implement `RuleLoader` in `src/security/rules/loader.rs`
    - Load `DetectionRule` definitions from TOML/YAML file at `config.security.rules_path`
    - Validate each rule (required fields present, `aggregation_window` and `threshold` > 0); log structured error and skip invalid rules
    - Store active rules in `Arc<RwLock<Vec<DetectionRule>>>`
    - _Requirements: 6.1, 6.2, 6.3, 6.4_
  - [ ] 5.2 Implement hot-reload polling in `RuleLoader`
    - Poll file mtime every `config.security.rules_poll_interval` (≤ 60s)
    - On change, atomically swap rule set; log structured event with added/updated/removed counts
    - _Requirements: 10.1, 10.2, 10.3, 10.4, 10.5_
  - [ ]* 5.3 Write property test for hot-reload — Property 8: Hot-Reload Rule Application
    - **Property 8: Post-reload events evaluated against new rule set; pre-reload events not re-evaluated**
    - **Validates: Requirements 10.2, 10.3, 10.4**

- [ ] 6. Rule engine — stream consumer
  - Implement `StreamConsumer` in `src/security/rules/consumer.rs`
  - Use `XREADGROUP GROUP security-rule-engine <consumer> COUNT <n> BLOCK <ms>` on `security:events`
  - Acknowledge with `XACK` after successful evaluation; reclaim pending entries via `XAUTOCLAIM` after `PEL_TIMEOUT`
  - Update `aframp_security_rule_engine_processing_lag_seconds` gauge after each batch; fire `SecurityRuleEngineLagHigh` alert when lag exceeds threshold
  - Increment `aframp_security_rules_evaluated_total{rule_id}` per rule evaluated
  - Run as Tokio task following `run(shutdown)` pattern
  - _Requirements: 5.4, 5.5, 7.1, 7.2, 7.4, 7.5_

- [ ] 7. Rule engine — evaluators
  - [ ] 7.1 Implement `SimpleRuleEvaluator` in `src/security/rules/simple_evaluator.rs`
    - Match `event_type_filters` (empty = match-all) and `field_match_conditions` against `SecurityEvent`
    - Fire immediately when all conditions match; return `Option<Alert>`
    - _Requirements: 7.1, 7.3_
  - [ ]* 7.2 Write property test — Property 4: Rule Evaluation Filter Correctness
    - **Property 4: Only rules whose `event_type_filters` contain the event type are evaluated**
    - **Validates: Requirements 7.1**
  - [ ] 7.3 Implement `StatefulRuleEvaluator` in `src/security/rules/stateful_evaluator.rs`
    - Per `(rule_id, actor_identity)`: `INCR sec:state:{rule_id}:{actor}` with `EXPIRE = aggregation_window`
    - For distinct-field rules: `SADD sec:distinct:{rule_id}:{actor}:{field_value}` + `SCARD` check
    - Fire when counter/cardinality reaches threshold; reset counter to 0 after firing
    - _Requirements: 8.1, 8.2, 8.3, 8.4, 8.5_
  - [ ]* 7.4 Write property test — Property 5: Threshold Firing
    - **Property 5: Exactly one Alert produced when T matching events arrive within window; counter resets to 0**
    - **Validates: Requirements 7.3, 8.2, 8.3, 8.4**
  - [ ]* 7.5 Write property test — Property 6: Distinct-Value Stateful Rule
    - **Property 6: Counter increments only on new distinct field values, not repeated values**
    - **Validates: Requirements 8.5**
  - [ ] 7.6 Implement `CorrelationRuleEvaluator` in `src/security/rules/correlation_evaluator.rs`
    - `SADD sec:corr:{rule_id}:{actor}:sources {source_system}` with `EXPIRE = aggregation_window`
    - Collect contributing event IDs in `sec:corr:{rule_id}:{actor}:events` list
    - Fire when `SCARD sources == len(required_sources)`; include all event IDs in `related_event_ids`
    - Discard partial state on TTL expiry (no action needed — Redis handles TTL)
    - _Requirements: 9.1, 9.2, 9.3, 9.4, 9.5_
  - [ ]* 7.7 Write property test — Property 7: Correlation Rule Firing
    - **Property 7: Exactly one Alert with all contributing event IDs when all required sources contribute within window**
    - **Validates: Requirements 9.2, 9.3, 9.4**

- [ ] 8. Checkpoint — rule engine unit tests
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 9. Alert manager — creation and deduplication
  - [ ] 9.1 Implement `AlertManager::create_alert` in `src/security/alerts/manager.rs`
    - Persist `Alert` to `security_alerts` within 500ms of rule firing
    - Increment `aframp_security_alerts_fired_total{rule_id, severity}`; update `aframp_security_open_alerts{severity}` gauge
    - Emit `tracing::info!` with `alert_id`, `rule_id`, `severity`, `actor_identity`, `created_at`
    - _Requirements: 18.1, 18.2, 18.3, 18.4, 33.1_
  - [ ]* 9.2 Write property test — Property 9: Alert Record Completeness
    - **Property 9: Every Alert has non-null `alert_id`, `rule_id`, `severity`, `status=Open`, `created_at`, non-empty `related_event_ids`**
    - **Validates: Requirements 18.1, 18.2**
  - [ ] 9.3 Implement deduplication in `AlertManager`
    - Check `dedup:{rule_id}:{actor}` Redis key; if present, append new event IDs to existing alert's `related_event_ids` and increment `aframp_security_alerts_deduplicated_total{rule_id}`
    - On Redis failure, fail-open (create new alert) and log `tracing::warn!`
    - Set dedup key with TTL = `rule.deduplication_window` (default 300s) on new alert creation
    - _Requirements: 19.1, 19.2, 19.3, 19.4_
  - [ ]* 9.4 Write property test — Property 10: Alert Deduplication Suppression
    - **Property 10: Second firing within dedup window appends event IDs to existing alert; no new alert created**
    - **Validates: Requirements 19.1, 19.4**

- [ ] 10. Alert manager — lifecycle endpoints
  - [ ] 10.1 Implement `POST /api/admin/security/alerts/:alert_id/acknowledge`
    - Validate alert exists (404) and status is `Open` (409); set status → `Acknowledged`, `assigned_admin_id`
    - Emit `tracing::info!` with `alert_id`, `acknowledged_by`, `acknowledged_at`
    - _Requirements: 20.1, 20.2, 20.3, 20.4, 33.3_
  - [ ] 10.2 Implement `POST /api/admin/security/alerts/:alert_id/escalate`
    - Validate escalation_reason present; reject `Critical` with 422; increment severity one level; set status → `Escalated`
    - Route notification to on-call channel via `NotificationRouter`
    - Emit `tracing::warn!` with `alert_id`, `previous_severity`, `new_severity`, `escalation_reason`, `admin_id`
    - _Requirements: 21.1, 21.2, 21.3, 21.4, 33.2_
  - [ ] 10.3 Implement `POST /api/admin/security/alerts/:alert_id/resolve`
    - Reject if status is `Resolved` or `FalsePositive` with 409; set status → `Resolved`, `resolution_timestamp`
    - Decrement `aframp_security_open_alerts{severity}`; emit `tracing::info!` with resolution fields
    - _Requirements: 22.1, 22.2, 22.3, 22.4, 33.4_
  - [ ] 10.4 Implement `POST /api/admin/security/alerts/:alert_id/false-positive`
    - Set status → `FalsePositive`, `resolution_timestamp`; increment `aframp_security_false_positives_total{rule_id}`
    - If `threshold_adjustment` provided, update rule via hot-reload mechanism; suppress dedup window
    - _Requirements: 23.1, 23.2, 23.3, 23.4_
  - [ ]* 10.5 Write property test — Property 11: Alert Lifecycle State Machine
    - **Property 11: Only valid state transitions succeed; `Resolved`/`FalsePositive` → any transition returns HTTP 409**
    - **Validates: Requirements 20.1, 20.3, 21.1, 22.1, 22.2, 23.1**
  - [ ]* 10.6 Write property test — Property 12: Escalation Severity Increment
    - **Property 12: Escalation increments severity by one level; `Critical` returns HTTP 422**
    - **Validates: Requirements 21.1, 21.2**
  - [ ] 10.7 Implement `GET /api/admin/security/alerts` and `GET /api/admin/security/alerts/:alert_id`
    - Paginated list with filters: `severity`, `status`, `rule_category`, `date_range_start`, `date_range_end`; ordered by `created_at DESC`
    - Detail endpoint returns full alert with related events, actor context, response history
    - Require `security.monitoring` permission on both endpoints
    - _Requirements: 24.1, 24.2, 24.3, 24.4_

- [ ] 11. Escalation worker
  - Implement `EscalationWorker` in `src/security/alerts/escalation_worker.rs`
  - Poll every `config.security.escalation_poll_interval` (default 60s) for `high`-severity `Open` alerts where `now() - created_at > acknowledgement_timeout`
  - Auto-escalate: set severity → `Critical`, status → `Escalated`; route on-call notification; emit `tracing::warn!` with `alert_id`, `escalation_reason = "acknowledgement_timeout"`
  - Run as Tokio task following `run(shutdown)` pattern
  - _Requirements: 26.1, 26.2, 26.3, 26.4_

- [ ] 12. Notification router
  - [ ] 12.1 Define `NotificationBackend` trait and `Notification` type in `src/security/notifications/mod.rs`
    - `async fn deliver(&self, notification: &Notification) -> Result<(), NotificationError>`
    - _Requirements: 25.4_
  - [ ] 12.2 Implement `PagerDutyBackend`, `SlackBackend`, `EmailBackend` in `src/security/notifications/backends/`
    - Each implements `NotificationBackend`; use `reqwest` for HTTP-based backends
    - _Requirements: 25.4_
  - [ ] 12.3 Implement `NotificationRouter` routing logic
    - `critical`/`high` → on-call channel; `medium` → security team channel; `low`/`info` → daily digest queue
    - Retry failed deliveries: 3 attempts, 5s initial, 2× factor; on exhaustion log `tracing::error!` and increment `aframp_worker_errors_total{worker="notification_router", error_type="delivery_failed"}`
    - _Requirements: 25.1, 25.2, 25.3, 25.5_
  - [ ]* 12.4 Write property test — Property 16: Notification Severity Routing
    - **Property 16: Notification channel matches severity routing table for all five severity levels**
    - **Validates: Requirements 25.1, 25.2, 25.3**

- [ ] 13. Automated responder
  - [ ] 13.1 Implement `AutomatedResponder` in `src/security/response/responder.rs`
    - Listen on `tokio::sync::mpsc` channel for `AutomatedResponseRequest`
    - Dispatch to action handlers; record each action in alert's `response_actions` JSONB with `executed_by = "system"`
    - Increment `aframp_security_automated_responses_total{action_type}`; emit `tracing::warn!` with `alert_id`, `action_type`, `target`, `executed_at`
    - On action failure: log `tracing::error!`, record `status = "failed"` in `response_actions`
    - Run as Tokio task following `run(shutdown)` pattern
    - _Requirements: 28.2, 28.4, 31.2, 33.5_
  - [ ] 13.2 Implement `TightenRateLimit` action handler
    - Call rate limiting system to tighten limits for `actor_identity` in alert
    - _Requirements: 28.1, 28.2_
  - [ ] 13.3 Implement `RevokeOAuthTokenFamily` action handler
    - Revoke token family identified in `related_event_ids`; record `action_type = "oauth_token_family_revocation"`
    - _Requirements: 29.1, 29.2_
  - [ ] 13.4 Implement `TerminateAdminSessions` action handler
    - Terminate all active sessions for involved admin account; set account to require re-authentication; record `action_type = "admin_session_termination"`
    - _Requirements: 30.1, 30.2_
  - [ ] 13.5 Implement `ActivateElevatedRateLimiting` action handler
    - Activate platform-wide elevated adaptive rate limiting; record `action_type = "elevated_rate_limiting_activation"`
    - _Requirements: 31.1, 31.2_
  - [ ] 13.6 Implement `POST /api/admin/security/alerts/:alert_id/override-response`
    - Cancel pending automated response; record override with `override_admin_id`; return 409 if action already executed
    - _Requirements: 28.3, 29.3, 30.3, 31.3_
  - [ ]* 13.7 Write property test — Property 14: Automated Response Cause-Effect
    - **Property 14: Correct action executed and recorded with `executed_by = "system"` for each `ResponseAction` variant**
    - **Validates: Requirements 28.1, 28.2, 29.1, 29.2, 30.1, 30.2, 31.1, 31.2**

- [ ] 14. Checkpoint — alert manager and responder tests
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 15. Incident manager
  - [ ] 15.1 Implement `IncidentManager` CRUD in `src/security/incidents/manager.rs`
    - `POST /api/admin/security/incidents`: create `SecurityIncident` with empty timeline
    - `GET /api/admin/security/incidents`: paginated list with severity, status, linked alert count
    - `GET /api/admin/security/incidents/:incident_id`: full detail with linked alerts, timeline, response actions
    - `PATCH /api/admin/security/incidents/:incident_id`: update severity/status/notes; append `TimelineEntry` atomically via PostgreSQL JSONB array append
    - _Requirements: 27.1, 27.2, 27.3, 27.4, 27.5_
  - [ ]* 15.2 Write property test — Property 15: Incident Timeline Append-Only
    - **Property 15: Every update appends a new `TimelineEntry`; no existing entries modified or removed**
    - **Validates: Requirements 27.5**

- [ ] 16. Observability — metrics and structured logging completeness
  - Register all Prometheus metrics in `src/security/metrics.rs`: counters (`events_ingested_total`, `rules_evaluated_total`, `alerts_fired_total`, `automated_responses_total`, `false_positives_total`, `alerts_deduplicated_total`) and gauges (`open_alerts`, `event_stream_buffer_utilisation`, `rule_engine_processing_lag_seconds`)
  - Register metrics with the existing Prometheus registry from `src/metrics/`
  - _Requirements: 32.1–32.8_
  - [ ]* 16.1 Write property test — Property 13: Metrics Monotonicity
    - **Property 13: All counters are non-decreasing and increment by exactly 1 per corresponding operation**
    - **Validates: Requirements 7.2, 18.3, 19.3, 28.4, 32.1–32.5**
  - [ ]* 16.2 Write property test — Property 17: Structured Log Field Completeness
    - **Property 17: Every significant security action emits a log event with all required fields at the correct level**
    - **Validates: Requirements 33.1–33.5**

- [ ] 17. Initial detection rule library (seed TOML/YAML file)
  - Create `config/security_rules.toml` (or `.yaml`) with seeded rules for all 7 categories:
    - Authentication Anomalies: impossible travel, new device login, credential stuffing, brute force, MFA bypass (Req 11.1–11.5)
    - Credential Abuse: API key reuse after revocation, OAuth token replay, refresh token family reuse, service impersonation (Req 12.1–12.4)
    - Transaction Fraud: structuring pattern, round-trip transaction, velocity anomaly, new consumer high-value, cNGN flagged wallet (Req 13.1–13.5)
    - Access Control Violations: repeated permission denial, admin privilege escalation without approval, sensitive action confirmation bypass, scope over-claim (Req 14.1–14.4)
    - Data Access Anomalies: bulk data export, sequential resource enumeration, anomalous read volume spike (Req 15.1–15.3)
    - Infrastructure Anomalies: certificate expiry, backup replication failure, worker cycle failure, rate limit system degradation (Req 16.1–16.4)
    - Coordinated Attack Patterns: multi-consumer auth failures, distributed IP attack, coordinated transaction fraud (Req 17.1–17.3)
  - _Requirements: 11.1–17.3_

- [ ] 18. Wire all components into application startup
  - In `src/security/mod.rs`, expose a `start(app_state: AppState, shutdown: watch::Receiver<bool>)` function that spawns all Tokio tasks: `AuditLogSubscriber`, `PrometheusAlertSubscriber`, `StreamConsumer`, `EscalationWorker`, `AutomatedResponder`
  - Mount all HTTP routes under `/api/admin/security/` in the main Axum router
  - Add `[security]` config section to `config/*.toml` with all configurable parameters
  - _Requirements: 1.1, 5.4, 7.1, 26.1_

- [ ] 19. Unit tests
  - [ ] 19.1 Write unit tests for `EventNormaliser` — sentinel values, field mapping, `event_detail` round-trip
    - _Requirements: 34.1, 4.3_
  - [ ] 19.2 Write unit tests for `SimpleRuleEvaluator` — fires on match, does not fire on non-match, threshold boundary (T-1 → no fire, T → fire)
    - _Requirements: 34.1_
  - [ ] 19.3 Write unit tests for `StatefulRuleEvaluator` — counter reset after firing, distinct-value deduplication, window expiry resets counter
    - _Requirements: 34.2_
  - [ ] 19.4 Write unit tests for `CorrelationRuleEvaluator` — partial state does not fire, all-sources-present fires, contributing event IDs collected
    - _Requirements: 34.3_
  - [ ] 19.5 Write unit tests for `AlertManager` deduplication — suppression within window, new alert allowed after window expiry
    - _Requirements: 34.4_
  - [ ] 19.6 Write unit tests for alert lifecycle state machine — all valid transitions succeed, all invalid transitions return correct HTTP error
    - _Requirements: 34.5, 20.3, 22.2_
  - [ ] 19.7 Write unit tests for escalation severity increment — each level increments correctly, `Critical` returns 422
    - _Requirements: 21.1, 21.2_
  - [ ] 19.8 Write unit tests for `AutomatedResponder` — each `ResponseAction` variant triggers correct handler and records action in alert
    - _Requirements: 34.5_
  - [ ] 19.9 Write unit tests for `NotificationRouter` — severity-to-channel mapping for all five severity levels
    - _Requirements: 25.1, 25.2, 25.3_
  - [ ] 19.10 Write unit tests for backoff algorithm — intervals bounded by 30s and grow exponentially
    - _Requirements: 1.3_

- [ ] 20. Integration tests
  - [ ] 20.1 Write integration test: end-to-end detection for one rule from each of the 7 rule categories
    - Use real PostgreSQL + Redis; follow pattern from `tests/cache_integration_test.rs`
    - _Requirements: 35.1_
  - [ ] 20.2 Write integration test: full Alert lifecycle — creation → acknowledge → escalate → resolve → false positive
    - _Requirements: 35.2_
  - [ ] 20.3 Write integration test: notification routing delivers to correct channel for each severity level
    - _Requirements: 35.3_
  - [ ] 20.4 Write integration test: each automated response action executed end-to-end and recorded in alert
    - _Requirements: 35.4_
  - [ ] 20.5 Write integration test: `SecurityIncident` create, update, timeline append
    - _Requirements: 35.5_
  - [ ] 20.6 Write integration test: rule hot-reload — update rule file, wait one poll interval, verify new rule applies without event loss
    - _Requirements: 35.6_

- [ ] 21. Final checkpoint — all tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for a faster MVP
- Each task references specific requirements for traceability
- Property tests use the `proptest` crate; each test is annotated with `// Feature: security-event-detection, Property N: <text>`
- All background workers follow the `run(shutdown: watch::Receiver<bool>)` pattern from `src/workers/`
- Integration tests follow the pattern from `tests/cache_integration_test.rs`
