# Requirements Document

## Introduction

The Security Event Detection system provides real-time threat detection, alert management, and automated response capabilities for the Aframp platform. It ingests events from the audit log pub/sub stream (issue #98), Prometheus alert firings, and direct security signal pushes from the abuse detection, IP reputation, and rate limiting systems. A configurable rule engine evaluates normalised events against a library of detection rules covering authentication anomalies, credential abuse, transaction fraud, access control violations, data access anomalies, infrastructure anomalies, and coordinated attack patterns. Fired rules produce security alerts that flow through a full lifecycle — creation, acknowledgement, escalation, and resolution — with automated response actions for high-confidence detections and a correlation engine that groups related signals into coherent security incidents.

## Glossary

- **Security_Event_Detector**: The top-level service component that owns the ingestion pipeline, rule engine, alert manager, correlation engine, and incident manager.
- **Event_Ingestion_Layer**: The subsystem that subscribes to all event sources and normalises inbound data into the common Security_Event schema.
- **Security_Event**: A normalised record with fields: event_type, severity, source_system, actor_identity, target_resource, event_detail (JSON), and timestamp.
- **Redis_Event_Stream**: A Redis Streams data structure used as the buffer between the Event_Ingestion_Layer and the Rule_Engine.
- **Rule_Engine**: The component that reads events from the Redis_Event_Stream and evaluates all matching Detection_Rules.
- **Detection_Rule**: A configurable rule definition specifying event_type_filters, field_match_conditions, aggregation_window, threshold, severity_level, and response_action.
- **Stateful_Rule**: A Detection_Rule that tracks event counts or field value patterns across a time window before firing.
- **Correlation_Rule**: A Detection_Rule that requires matching events from two or more distinct source systems within a time window before firing.
- **Alert**: A record produced when a Detection_Rule fires, containing alert_id, rule_id, severity, status, assigned_admin_id, related_event_ids, created_at, and resolution_timestamp.
- **Alert_Manager**: The component responsible for the full Alert lifecycle including creation, deduplication, assignment, escalation, and resolution.
- **Correlation_Engine**: The component that groups related Alerts from multiple sources into a single Security_Incident.
- **Security_Incident**: A record grouping one or more related Alerts with a shared timeline of all response actions.
- **Notification_Router**: The component that routes Alerts to the appropriate notification channel based on severity.
- **Automated_Responder**: The component that executes predefined response actions when specific high-confidence Alerts fire.
- **Deduplication_Window**: A configurable time interval during which duplicate Alerts for the same rule and actor are suppressed.
- **Acknowledgement_Timeout**: A configurable duration after which an unacknowledged high-severity Alert is automatically escalated to critical.
- **Admin**: An authenticated administrator account as defined in the existing admin access control system.

## Requirements

### Requirement 1: Event Ingestion — Audit Log Pub/Sub Subscription

**User Story:** As a security engineer, I want the system to consume the real-time audit log pub/sub stream, so that every platform action is available for security rule evaluation without manual polling.

#### Acceptance Criteria

1. WHEN the Security_Event_Detector starts, THE Event_Ingestion_Layer SHALL subscribe to the audit log pub/sub channel established in issue #98.
2. WHEN an audit log message is received from the pub/sub channel, THE Event_Ingestion_Layer SHALL normalise it into a Security_Event within 100 ms of receipt.
3. IF the audit log pub/sub channel is temporarily unavailable, THEN THE Event_Ingestion_Layer SHALL attempt reconnection with exponential backoff up to a maximum interval of 30 seconds.
4. WHEN the pub/sub connection is re-established after a failure, THE Event_Ingestion_Layer SHALL resume consumption from the last acknowledged offset to prevent event loss.

### Requirement 2: Event Ingestion — Prometheus Alert Firing Subscription

**User Story:** As a security engineer, I want the system to consume Prometheus alert rule firing events, so that infrastructure and service-level anomalies detected by existing alert rules are automatically fed into the security detection pipeline.

#### Acceptance Criteria

1. WHEN a Prometheus alert rule transitions to the firing state, THE Event_Ingestion_Layer SHALL receive the alert firing event via the internal event bus within 5 seconds of the state transition.
2. THE Event_Ingestion_Layer SHALL subscribe to all Prometheus alert rules whose names match the security-relevant rule set defined across previous issues.
3. WHEN a Prometheus alert firing event is received, THE Event_Ingestion_Layer SHALL normalise it into a Security_Event with source_system set to "prometheus".
4. IF a Prometheus alert firing event contains no actor_identity field, THEN THE Event_Ingestion_Layer SHALL set actor_identity to "system" in the resulting Security_Event.

### Requirement 3: Event Ingestion — Direct Security Signal Push

**User Story:** As a security engineer, I want the abuse detection, IP reputation, and rate limiting systems to push signals directly into the detection pipeline, so that high-fidelity signals from specialised subsystems are processed without latency.

#### Acceptance Criteria

1. THE Event_Ingestion_Layer SHALL expose an internal event bus endpoint that accepts direct security signal pushes from the abuse detection system, IP reputation system, and rate limiting system.
2. WHEN a direct security signal is received, THE Event_Ingestion_Layer SHALL normalise it into a Security_Event within 50 ms of receipt.
3. IF a direct security signal push fails schema validation, THEN THE Event_Ingestion_Layer SHALL reject the signal with a structured error response and increment the aframp_security_events_ingestion_errors_total counter labelled by source_system.
4. THE Event_Ingestion_Layer SHALL accept concurrent signal pushes from all three source systems without serialisation bottlenecks.

### Requirement 4: Event Normalisation Schema

**User Story:** As a security engineer, I want all inbound events normalised into a common schema, so that the rule engine can evaluate events from all sources using a single consistent data model.

#### Acceptance Criteria

1. THE Event_Ingestion_Layer SHALL normalise every inbound event into a Security_Event containing: event_type (string), severity (info | low | medium | high | critical), source_system (string), actor_identity (string), target_resource (string), event_detail (JSON object), and timestamp (RFC 3339 UTC).
2. WHEN a normalised Security_Event is produced, THE Event_Ingestion_Layer SHALL append it to the Redis_Event_Stream within 100 ms.
3. IF any required Security_Event field cannot be derived from the inbound event, THEN THE Event_Ingestion_Layer SHALL set that field to a defined sentinel value and log a structured warning event.
4. THE Event_Ingestion_Layer SHALL preserve the original inbound event payload in the event_detail field of the Security_Event without modification.

### Requirement 5: Redis Event Stream Buffering

**User Story:** As a platform engineer, I want incoming events buffered in a Redis stream, so that temporary Rule_Engine processing lag does not cause event loss.

#### Acceptance Criteria

1. THE Event_Ingestion_Layer SHALL write all normalised Security_Events to a Redis Streams key with a configurable maximum stream length (MAXLEN).
2. WHILE the Redis_Event_Stream length exceeds 80% of the configured maximum, THE Security_Event_Detector SHALL set the aframp_security_event_stream_buffer_utilisation gauge to a value greater than 0.8.
3. WHEN the Redis_Event_Stream buffer utilisation exceeds the configured alert threshold, THE Security_Event_Detector SHALL fire a Prometheus alert named SecurityEventStreamBufferHigh.
4. THE Rule_Engine SHALL consume events from the Redis_Event_Stream using consumer group semantics so that each event is processed exactly once across all Rule_Engine instances.
5. IF the Rule_Engine fails to acknowledge a consumed event within a configurable timeout, THEN THE Redis_Event_Stream SHALL redeliver that event to another consumer group member.

### Requirement 6: Detection Rule Definition Format

**User Story:** As a security engineer, I want a structured rule definition format, so that detection rules can be authored, reviewed, and updated without modifying application code.

#### Acceptance Criteria

1. THE Rule_Engine SHALL load Detection_Rules from a configurable rule definition store where each rule specifies: rule_id, rule_name, event_type_filters (list of strings), field_match_conditions (key-value map), aggregation_window (duration in seconds), threshold (integer), severity_level, and response_action (optional).
2. WHEN a Detection_Rule definition is loaded, THE Rule_Engine SHALL validate that all required fields are present and that aggregation_window and threshold are positive values.
3. IF a Detection_Rule definition fails validation, THEN THE Rule_Engine SHALL log a structured error event containing the rule_id and validation failure reason, and SHALL skip that rule without halting the engine.
4. THE Rule_Engine SHALL support rule definitions that specify no response_action, in which case the Alert is created without triggering automated remediation.

### Requirement 7: Rule Evaluation Loop

**User Story:** As a security engineer, I want the rule engine to continuously evaluate incoming events against all matching rules, so that threats are detected in real time.

#### Acceptance Criteria

1. WHEN a Security_Event is consumed from the Redis_Event_Stream, THE Rule_Engine SHALL evaluate all Detection_Rules whose event_type_filters match the event's event_type field.
2. THE Rule_Engine SHALL increment the aframp_security_rules_evaluated_total counter for each rule evaluated.
3. WHEN a Detection_Rule's threshold is met or exceeded within its aggregation_window, THE Rule_Engine SHALL produce an Alert via the Alert_Manager.
4. THE Rule_Engine SHALL update the aframp_security_rule_engine_processing_lag_seconds gauge after each event batch to reflect the age of the oldest unprocessed event in the Redis_Event_Stream.
5. WHEN the rule engine processing lag exceeds the configured lag alert threshold, THE Security_Event_Detector SHALL fire a Prometheus alert named SecurityRuleEngineLagHigh.

### Requirement 8: Stateful Rule Evaluation

**User Story:** As a security engineer, I want rules that track event patterns across a time window, so that multi-step attack sequences are detected even when individual events appear benign.

#### Acceptance Criteria

1. THE Rule_Engine SHALL maintain per-actor, per-rule state counters in Redis with a TTL equal to the Detection_Rule's aggregation_window.
2. WHEN a Security_Event matches a Stateful_Rule's event_type_filters and field_match_conditions, THE Rule_Engine SHALL increment the state counter for the (rule_id, actor_identity) key pair.
3. WHEN the state counter for a (rule_id, actor_identity) key pair reaches the Detection_Rule's threshold within the aggregation_window, THE Rule_Engine SHALL fire the rule and produce an Alert.
4. WHEN a Stateful_Rule fires, THE Rule_Engine SHALL reset the state counter for the (rule_id, actor_identity) key pair to prevent duplicate firings for the same event window.
5. THE Rule_Engine SHALL support Stateful_Rules that track distinct field values (e.g. distinct source IP addresses) rather than raw event counts.

### Requirement 9: Correlation Rule Evaluation

**User Story:** As a security engineer, I want rules that require signals from multiple source systems before firing, so that coordinated attacks are detected with higher confidence and lower false positive rates.

#### Acceptance Criteria

1. THE Rule_Engine SHALL support Correlation_Rules that specify a required_sources list containing two or more distinct source_system values.
2. WHEN a Security_Event matches a Correlation_Rule's event_type_filters, THE Rule_Engine SHALL record the source_system of the matching event in a per-rule, per-actor correlation state set in Redis with a TTL equal to the aggregation_window.
3. WHEN the correlation state set for a (rule_id, actor_identity) key pair contains all source_system values listed in the Correlation_Rule's required_sources, THE Rule_Engine SHALL fire the rule and produce an Alert.
4. WHEN a Correlation_Rule fires, THE Rule_Engine SHALL include the IDs of all contributing Security_Events in the Alert's related_event_ids field.
5. IF the correlation state set TTL expires before all required sources have contributed, THEN THE Rule_Engine SHALL discard the partial state without firing the rule.

### Requirement 10: Rule Hot-Reload

**User Story:** As a security engineer, I want rule updates to take effect without a service restart, so that new detection logic can be deployed immediately in response to emerging threats.

#### Acceptance Criteria

1. THE Rule_Engine SHALL poll the rule definition store for changes at a configurable interval not exceeding 60 seconds.
2. WHEN the Rule_Engine detects a change to the rule definition store, THE Rule_Engine SHALL reload all Detection_Rules within one polling interval without dropping events from the Redis_Event_Stream.
3. WHEN a Detection_Rule is updated via hot-reload, THE Rule_Engine SHALL apply the updated rule definition to all events processed after the reload completes.
4. WHEN a Detection_Rule is removed via hot-reload, THE Rule_Engine SHALL stop evaluating that rule and discard any in-progress stateful state for that rule_id.
5. WHEN a hot-reload completes successfully, THE Rule_Engine SHALL log a structured event containing the number of rules added, updated, and removed.

### Requirement 11: Initial Detection Rule Library — Authentication Anomalies

**User Story:** As a security engineer, I want pre-seeded authentication anomaly rules, so that common credential-based attacks are detected from day one without manual rule authoring.

#### Acceptance Criteria

1. THE Rule_Engine SHALL include a seeded Stateful_Rule that fires when the same actor_identity authenticates successfully from two geographic locations that are physically impossible to travel between within the elapsed time (impossible travel login).
2. THE Rule_Engine SHALL include a seeded Stateful_Rule that fires when an actor_identity authenticates successfully from a device fingerprint not previously associated with that actor within a configurable lookback window (new device login).
3. THE Rule_Engine SHALL include a seeded Stateful_Rule that fires when the count of distinct actor_identity values failing authentication from the same source IP address exceeds the configured threshold within the aggregation_window (credential stuffing pattern).
4. THE Rule_Engine SHALL include a seeded Stateful_Rule that fires when the count of failed authentication attempts for the same actor_identity exceeds the configured threshold within the aggregation_window (brute force pattern).
5. THE Rule_Engine SHALL include a seeded Stateful_Rule that fires when an MFA challenge is bypassed or skipped for an actor_identity that has MFA configured (MFA bypass attempt).

### Requirement 12: Initial Detection Rule Library — Credential Abuse

**User Story:** As a security engineer, I want pre-seeded credential abuse rules, so that token and API key misuse is detected automatically.

#### Acceptance Criteria

1. THE Rule_Engine SHALL include a seeded event-driven rule that fires when an API key that has been marked as revoked is used in an authentication attempt (API key reuse after revocation).
2. THE Rule_Engine SHALL include a seeded event-driven rule that fires when an OAuth access token is presented after its associated refresh token family has been invalidated (OAuth token replay attempt).
3. THE Rule_Engine SHALL include a seeded event-driven rule that fires when a refresh token from an already-used token family is presented (refresh token family reuse).
4. THE Rule_Engine SHALL include a seeded Correlation_Rule that fires when authentication events from a service account are correlated with access patterns inconsistent with that service account's declared scope (service impersonation attempt).

### Requirement 13: Initial Detection Rule Library — Transaction Fraud

**User Story:** As a security engineer, I want pre-seeded transaction fraud rules, so that financial crime patterns are detected in real time.

#### Acceptance Criteria

1. THE Rule_Engine SHALL include a seeded Stateful_Rule that fires when a series of transactions from the same actor_identity are structured to remain below reporting thresholds within the aggregation_window (structuring pattern).
2. THE Rule_Engine SHALL include a seeded Correlation_Rule that fires when funds are transferred out and an equivalent amount is transferred back within the aggregation_window from the same actor_identity (round-trip transaction pattern).
3. THE Rule_Engine SHALL include a seeded Stateful_Rule that fires when the transaction velocity for an actor_identity exceeds the configured threshold within the aggregation_window (velocity anomaly).
4. THE Rule_Engine SHALL include a seeded event-driven rule that fires when a consumer account with no prior transaction history initiates a transaction above the configured high-value threshold (new consumer high-value transaction).
5. THE Rule_Engine SHALL include a seeded event-driven rule that fires when a cNGN transfer targets a wallet address present in the flagged wallet list (cNGN transfer to flagged wallet).

### Requirement 14: Initial Detection Rule Library — Access Control Violations

**User Story:** As a security engineer, I want pre-seeded access control violation rules, so that privilege abuse and bypass attempts are detected automatically.

#### Acceptance Criteria

1. THE Rule_Engine SHALL include a seeded Stateful_Rule that fires when the count of permission-denied responses for the same actor_identity exceeds the configured threshold within the aggregation_window (repeated permission denial pattern).
2. THE Rule_Engine SHALL include a seeded event-driven rule that fires when an admin account is granted elevated privileges without a corresponding approved escalation request (admin privilege escalation without approval).
3. THE Rule_Engine SHALL include a seeded event-driven rule that fires when a sensitive action is executed without a valid sensitive action confirmation token (sensitive action confirmation bypass attempt).
4. THE Rule_Engine SHALL include a seeded event-driven rule that fires when an OAuth token is used to access a resource outside the scopes granted to that token (scope over-claim attempt).

### Requirement 15: Initial Detection Rule Library — Data Access Anomalies

**User Story:** As a security engineer, I want pre-seeded data access anomaly rules, so that bulk data exfiltration and enumeration attacks are detected.

#### Acceptance Criteria

1. THE Rule_Engine SHALL include a seeded Stateful_Rule that fires when the count of data export requests from the same actor_identity exceeds the configured threshold within the aggregation_window (bulk data export pattern).
2. THE Rule_Engine SHALL include a seeded Stateful_Rule that fires when an actor_identity accesses sequentially incrementing resource identifiers at a rate exceeding the configured threshold within the aggregation_window (sequential resource enumeration pattern).
3. THE Rule_Engine SHALL include a seeded Stateful_Rule that fires when the read request volume for an actor_identity exceeds a configurable multiple of that actor's rolling baseline within the aggregation_window (anomalous read volume spike).

### Requirement 16: Initial Detection Rule Library — Infrastructure Anomalies

**User Story:** As a security engineer, I want pre-seeded infrastructure anomaly rules, so that platform health degradation that could indicate an attack or enable one is surfaced as a security alert.

#### Acceptance Criteria

1. THE Rule_Engine SHALL include a seeded event-driven rule that fires when a TLS certificate is within the configured number of days of expiry (certificate expiry approaching).
2. THE Rule_Engine SHALL include a seeded event-driven rule that fires when a backup replication job fails (backup replication failure).
3. THE Rule_Engine SHALL include a seeded event-driven rule that fires when a background worker cycle fails to complete within the configured timeout (worker cycle failure).
4. THE Rule_Engine SHALL include a seeded event-driven rule that fires when the rate limiting system reports degraded operation (rate limit system degradation).

### Requirement 17: Initial Detection Rule Library — Coordinated Attack Patterns

**User Story:** As a security engineer, I want pre-seeded coordinated attack rules, so that distributed multi-actor attacks are detected even when individual actor signals fall below single-actor thresholds.

#### Acceptance Criteria

1. THE Rule_Engine SHALL include a seeded Correlation_Rule that fires when authentication failures are observed across a configurable minimum number of distinct consumer accounts within the aggregation_window from correlated source signals (multi-consumer correlated authentication failures).
2. THE Rule_Engine SHALL include a seeded Correlation_Rule that fires when attack signals are observed from a configurable minimum number of distinct IP addresses targeting the same resource within the aggregation_window (distributed IP attack pattern).
3. THE Rule_Engine SHALL include a seeded Correlation_Rule that fires when transaction fraud signals are observed across a configurable minimum number of distinct consumer accounts within the aggregation_window (coordinated transaction fraud).

### Requirement 18: Alert Record and Creation

**User Story:** As a security engineer, I want every rule firing to produce a structured alert record, so that all detected threats are tracked with full context.

#### Acceptance Criteria

1. WHEN a Detection_Rule fires, THE Alert_Manager SHALL create an Alert record containing: alert_id (UUID), rule_id, severity (info | low | medium | high | critical), status (open), assigned_admin_id (null), related_event_ids (list of Security_Event IDs), created_at (RFC 3339 UTC), and resolution_timestamp (null).
2. THE Alert_Manager SHALL persist the Alert record to the database within 500 ms of the rule firing.
3. WHEN an Alert is created, THE Alert_Manager SHALL increment the aframp_security_alerts_fired_total counter labelled by rule_id and severity.
4. THE Alert_Manager SHALL set the aframp_security_open_alerts gauge labelled by severity to reflect the current count of open Alerts after each creation or status change.

### Requirement 19: Alert Deduplication

**User Story:** As a security engineer, I want duplicate alerts suppressed within a configurable window, so that notification flooding does not obscure genuine new threats.

#### Acceptance Criteria

1. WHEN a Detection_Rule fires for the same rule_id and actor_identity combination within the Deduplication_Window of an existing open Alert for that combination, THE Alert_Manager SHALL suppress the duplicate Alert creation and instead append the new Security_Event IDs to the existing Alert's related_event_ids.
2. THE Deduplication_Window SHALL be configurable per Detection_Rule with a default value of 300 seconds.
3. WHEN an Alert is suppressed by deduplication, THE Alert_Manager SHALL increment the aframp_security_alerts_deduplicated_total counter labelled by rule_id.
4. WHEN the Deduplication_Window for an existing Alert expires, THE Alert_Manager SHALL allow a new Alert to be created for the same rule_id and actor_identity combination on the next rule firing.

### Requirement 20: Alert Lifecycle — Acknowledge

**User Story:** As a security admin, I want to acknowledge an alert and assign it for investigation, so that the team has clear ownership of each open threat.

#### Acceptance Criteria

1. WHEN a POST request is received at /api/admin/security/alerts/:alert_id/acknowledge, THE Alert_Manager SHALL update the Alert status to "acknowledged" and set assigned_admin_id to the requesting Admin's ID.
2. IF the Alert does not exist, THEN THE Alert_Manager SHALL return HTTP 404.
3. IF the Alert status is not "open", THEN THE Alert_Manager SHALL return HTTP 409 with a message indicating the current status.
4. WHEN an Alert is acknowledged, THE Alert_Manager SHALL append a structured log event containing alert_id, admin_id, and timestamp.

### Requirement 21: Alert Lifecycle — Escalate

**User Story:** As a security admin, I want to escalate an alert to a higher severity, so that critical threats receive appropriate urgency and routing.

#### Acceptance Criteria

1. WHEN a POST request is received at /api/admin/security/alerts/:alert_id/escalate with an escalation_reason field, THE Alert_Manager SHALL update the Alert status to "escalated" and increase the Alert severity by one level.
2. IF the Alert severity is already "critical", THEN THE Alert_Manager SHALL return HTTP 422 indicating the Alert is already at maximum severity.
3. WHEN an Alert is escalated, THE Alert_Manager SHALL route a notification to the on-call security channel via the Notification_Router.
4. WHEN an Alert is escalated, THE Alert_Manager SHALL append a structured log event containing alert_id, previous_severity, new_severity, escalation_reason, and admin_id.

### Requirement 22: Alert Lifecycle — Resolve

**User Story:** As a security admin, I want to resolve an alert with resolution notes and root cause classification, so that the incident record is complete for audit and retrospective purposes.

#### Acceptance Criteria

1. WHEN a POST request is received at /api/admin/security/alerts/:alert_id/resolve with resolution_notes and root_cause_classification fields, THE Alert_Manager SHALL update the Alert status to "resolved" and set resolution_timestamp to the current UTC time.
2. IF the Alert status is "resolved" or "false_positive", THEN THE Alert_Manager SHALL return HTTP 409.
3. WHEN an Alert is resolved, THE Alert_Manager SHALL decrement the aframp_security_open_alerts gauge for the Alert's severity.
4. WHEN an Alert is resolved, THE Alert_Manager SHALL append a structured log event containing alert_id, resolution_notes, root_cause_classification, and admin_id.

### Requirement 23: Alert Lifecycle — False Positive

**User Story:** As a security admin, I want to mark an alert as a false positive and optionally adjust the triggering rule threshold, so that noisy rules are tuned without manual code changes.

#### Acceptance Criteria

1. WHEN a POST request is received at /api/admin/security/alerts/:alert_id/false-positive with an optional threshold_adjustment field, THE Alert_Manager SHALL update the Alert status to "false_positive" and set resolution_timestamp to the current UTC time.
2. WHERE a threshold_adjustment value is provided, THE Rule_Engine SHALL update the triggering Detection_Rule's threshold to the new value via the hot-reload mechanism within one polling interval.
3. WHEN an Alert is marked as false positive, THE Alert_Manager SHALL increment the aframp_security_false_positives_total counter labelled by rule_id.
4. WHEN an Alert is marked as false positive, THE Alert_Manager SHALL suppress future Alerts for the same rule_id and actor_identity combination for the duration of the Deduplication_Window.

### Requirement 24: Alert Query API

**User Story:** As a security admin, I want to list and retrieve alerts with filtering, so that I can efficiently triage the current threat landscape.

#### Acceptance Criteria

1. WHEN a GET request is received at /api/admin/security/alerts, THE Alert_Manager SHALL return a paginated list of Alerts ordered by created_at descending, supporting filter parameters: severity, status, rule_category, date_range_start, and date_range_end.
2. WHEN a GET request is received at /api/admin/security/alerts/:alert_id, THE Alert_Manager SHALL return the full Alert detail including all related Security_Event records, actor context, and a chronological response history.
3. IF the alert_id does not correspond to an existing Alert, THEN THE Alert_Manager SHALL return HTTP 404.
4. THE Alert query endpoints SHALL require the requesting Admin to hold the "security.monitoring" permission.

### Requirement 25: Notification Routing

**User Story:** As a security engineer, I want alerts routed to the appropriate channel based on severity, so that critical threats receive immediate attention while low-noise alerts are batched.

#### Acceptance Criteria

1. WHEN an Alert with severity "critical" or "high" is created or escalated, THE Notification_Router SHALL deliver a notification to the configured on-call security channel within 60 seconds.
2. WHEN an Alert with severity "medium" is created, THE Notification_Router SHALL deliver a notification to the configured security team channel for next-business-hour review.
3. WHEN an Alert with severity "low" or "info" is created, THE Notification_Router SHALL include the Alert in the next scheduled daily digest report rather than sending an immediate notification.
4. THE Notification_Router SHALL support configurable notification channel backends including PagerDuty, Slack, and email.
5. IF a notification delivery attempt fails, THEN THE Notification_Router SHALL retry with exponential backoff up to 3 attempts before logging a structured error event.

### Requirement 26: Automatic Escalation on Acknowledgement Timeout

**User Story:** As a security engineer, I want unacknowledged high-severity alerts automatically escalated, so that critical threats are never silently ignored.

#### Acceptance Criteria

1. WHILE an Alert with severity "high" has status "open" and the elapsed time since created_at exceeds the configured Acknowledgement_Timeout, THE Alert_Manager SHALL automatically update the Alert severity to "critical" and status to "escalated".
2. THE Acknowledgement_Timeout SHALL be configurable with a default value of 3600 seconds.
3. WHEN an Alert is automatically escalated due to timeout, THE Alert_Manager SHALL route a notification to the on-call security channel via the Notification_Router.
4. WHEN an Alert is automatically escalated due to timeout, THE Alert_Manager SHALL append a structured log event containing alert_id and escalation_reason set to "acknowledgement_timeout".

### Requirement 27: Security Incident Management

**User Story:** As a security engineer, I want to group related alerts into a single incident record, so that coordinated attacks are managed as a unified response effort.

#### Acceptance Criteria

1. WHEN a POST request is received at /api/admin/security/incidents with a list of alert_ids and an incident description, THE Correlation_Engine SHALL create a Security_Incident record containing: incident_id (UUID), severity, status (open), linked alert_ids, description, created_at, and an empty timeline.
2. WHEN a GET request is received at /api/admin/security/incidents, THE Correlation_Engine SHALL return a paginated list of Security_Incidents with severity, status, and linked alert count.
3. WHEN a GET request is received at /api/admin/security/incidents/:incident_id, THE Correlation_Engine SHALL return the full Security_Incident detail including all linked Alerts, the complete timeline, and all response actions taken.
4. WHEN a PATCH request is received at /api/admin/security/incidents/:incident_id with updated severity, status, or response_notes, THE Correlation_Engine SHALL update the Security_Incident and append the change to the incident timeline.
5. WHEN any response action, escalation, or resolution note is recorded against a Security_Incident, THE Correlation_Engine SHALL automatically append a timeline entry containing the action type, actor admin_id, and timestamp.

### Requirement 28: Automated Response — Credential Stuffing

**User Story:** As a security engineer, I want the system to automatically tighten rate limits on confirmed credential stuffing, so that the attack is disrupted without waiting for manual intervention.

#### Acceptance Criteria

1. WHEN the credential stuffing Detection_Rule fires and produces an Alert, THE Automated_Responder SHALL trigger hard rate limit tightening for all consumer accounts identified in the Alert's actor_identity field.
2. WHEN the automated rate limit tightening action is executed, THE Automated_Responder SHALL record the action in the Alert record with action_type, target_actor_identity, executed_at, and executed_by set to "system".
3. WHEN a POST request is received at /api/admin/security/alerts/:alert_id/override-response with an override_action field, THE Alert_Manager SHALL cancel the automated response and record the override in the Alert record with the overriding admin_id.
4. THE Automated_Responder SHALL increment the aframp_security_automated_responses_total counter labelled by action_type.

### Requirement 29: Automated Response — OAuth Token Replay

**User Story:** As a security engineer, I want the system to automatically revoke the involved token family on confirmed OAuth token replay, so that the compromised credential is invalidated immediately.

#### Acceptance Criteria

1. WHEN the OAuth token replay Detection_Rule fires and produces an Alert, THE Automated_Responder SHALL revoke the entire token family identified in the Alert's related_event_ids.
2. WHEN the token family revocation action is executed, THE Automated_Responder SHALL record the action in the Alert record with action_type set to "oauth_token_family_revocation", target_token_family_id, executed_at, and executed_by set to "system".
3. WHEN a POST request is received at /api/admin/security/alerts/:alert_id/override-response, THE Alert_Manager SHALL cancel the automated revocation and record the override with the overriding admin_id.

### Requirement 30: Automated Response — Impossible Travel Admin Login

**User Story:** As a security engineer, I want the system to automatically terminate all active sessions for an admin account on confirmed impossible travel, so that a potentially compromised admin session is invalidated immediately.

#### Acceptance Criteria

1. WHEN the impossible travel admin login Detection_Rule fires and produces an Alert, THE Automated_Responder SHALL terminate all active sessions for the involved admin account and set the account status to require re-authentication.
2. WHEN the session termination action is executed, THE Automated_Responder SHALL record the action in the Alert record with action_type set to "admin_session_termination", target_admin_id, executed_at, and executed_by set to "system".
3. WHEN a POST request is received at /api/admin/security/alerts/:alert_id/override-response, THE Alert_Manager SHALL cancel the automated session termination and record the override with the overriding admin_id.

### Requirement 31: Automated Response — Coordinated Attack

**User Story:** As a security engineer, I want the system to automatically activate elevated adaptive rate limiting on confirmed multi-consumer coordinated attacks, so that the attack surface is reduced platform-wide without manual intervention.

#### Acceptance Criteria

1. WHEN the multi-consumer coordinated attack Detection_Rule fires and produces an Alert, THE Automated_Responder SHALL activate elevated adaptive rate limiting mode across the platform.
2. WHEN the elevated adaptive rate limiting activation is executed, THE Automated_Responder SHALL record the action in the Alert record with action_type set to "elevated_rate_limiting_activation", executed_at, and executed_by set to "system".
3. WHEN a POST request is received at /api/admin/security/alerts/:alert_id/override-response, THE Alert_Manager SHALL deactivate the elevated rate limiting mode and record the override with the overriding admin_id.

### Requirement 32: Observability — Prometheus Metrics

**User Story:** As a platform engineer, I want comprehensive Prometheus metrics for the detection pipeline, so that the health and performance of the security system can be monitored in real time.

#### Acceptance Criteria

1. THE Security_Event_Detector SHALL expose a counter aframp_security_events_ingested_total labelled by event_type that increments for every Security_Event written to the Redis_Event_Stream.
2. THE Security_Event_Detector SHALL expose a counter aframp_security_rules_evaluated_total labelled by rule_id that increments for every rule evaluation performed by the Rule_Engine.
3. THE Security_Event_Detector SHALL expose a counter aframp_security_alerts_fired_total labelled by rule_id and severity that increments for every Alert created.
4. THE Security_Event_Detector SHALL expose a counter aframp_security_automated_responses_total labelled by action_type that increments for every automated response action executed.
5. THE Security_Event_Detector SHALL expose a counter aframp_security_false_positives_total labelled by rule_id that increments for every Alert marked as false positive.
6. THE Security_Event_Detector SHALL expose a gauge aframp_security_open_alerts labelled by severity reflecting the current count of open Alerts.
7. THE Security_Event_Detector SHALL expose a gauge aframp_security_event_stream_buffer_utilisation reflecting the current Redis_Event_Stream length as a fraction of the configured maximum.
8. THE Security_Event_Detector SHALL expose a gauge aframp_security_rule_engine_processing_lag_seconds reflecting the age of the oldest unprocessed event in the Redis_Event_Stream.

### Requirement 33: Observability — Structured Logging

**User Story:** As a security engineer, I want structured log events for every significant security system action, so that all detection and response activity is auditable.

#### Acceptance Criteria

1. WHEN an Alert is created, THE Alert_Manager SHALL emit a structured log event at INFO level containing alert_id, rule_id, severity, actor_identity, and created_at.
2. WHEN an Alert is escalated, THE Alert_Manager SHALL emit a structured log event at WARN level containing alert_id, previous_severity, new_severity, escalation_reason, and escalated_by.
3. WHEN an Alert is acknowledged, THE Alert_Manager SHALL emit a structured log event at INFO level containing alert_id, acknowledged_by, and acknowledged_at.
4. WHEN an Alert is resolved, THE Alert_Manager SHALL emit a structured log event at INFO level containing alert_id, resolution_notes, root_cause_classification, and resolved_by.
5. WHEN an automated response action is executed, THE Automated_Responder SHALL emit a structured log event at WARN level containing alert_id, action_type, target, and executed_at.

### Requirement 34: Unit Tests

**User Story:** As a developer, I want unit tests for core detection logic, so that rule evaluation correctness is verified in isolation without requiring a running infrastructure.

#### Acceptance Criteria

1. THE test suite SHALL include unit tests that verify Detection_Rule evaluation produces an Alert when the threshold is met and does not produce an Alert when the threshold is not met.
2. THE test suite SHALL include unit tests that verify Stateful_Rule window tracking correctly resets the counter after the aggregation_window expires.
3. THE test suite SHALL include unit tests that verify Correlation_Rule multi-source matching fires only when all required_sources have contributed within the aggregation_window.
4. THE test suite SHALL include unit tests that verify Alert deduplication suppresses a second Alert for the same rule_id and actor_identity within the Deduplication_Window.
5. THE test suite SHALL include unit tests that verify each automated response action is triggered for its corresponding Alert type and that the action is recorded in the Alert record.

### Requirement 35: Integration Tests

**User Story:** As a developer, I want integration tests covering the full detection pipeline, so that end-to-end correctness is verified across all components.

#### Acceptance Criteria

1. THE test suite SHALL include integration tests that verify end-to-end detection for at least one rule from each of the seven rule categories: authentication anomalies, credential abuse, transaction fraud, access control violations, data access anomalies, infrastructure anomalies, and coordinated attack patterns.
2. THE test suite SHALL include integration tests that verify the full Alert lifecycle: creation, acknowledgement, escalation, resolution, and false positive marking.
3. THE test suite SHALL include integration tests that verify notification routing delivers to the correct channel for each severity level.
4. THE test suite SHALL include integration tests that verify each automated response action is executed end-to-end and recorded in the Alert record.
5. THE test suite SHALL include integration tests that verify Security_Incident creation, update, and timeline append operations.
6. THE test suite SHALL include integration tests that verify rule hot-reload applies updated rule definitions to events processed after the reload without dropping events.
