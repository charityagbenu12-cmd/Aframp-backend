use crate::admin::models::*;
use prometheus::{
    Counter, Histogram, Gauge, IntCounter, IntGauge, Registry, TextEncoder, Encoder,
    opts, register_counter_vec, register_histogram_vec, register_gauge_vec, register_int_counter_vec, register_int_gauge_vec
};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn, error};

#[derive(Clone)]
pub struct AdminMetrics {
    // Authentication metrics
    pub login_attempts_total: IntCounterVec,
    pub login_success_total: IntCounterVec,
    pub login_failure_total: IntCounterVec,
    pub mfa_verification_total: IntCounterVec,
    pub mfa_verification_failure_total: IntCounterVec,
    pub account_lockouts_total: IntCounterVec,

    // Session metrics
    pub active_sessions: IntGaugeVec,
    pub sessions_created_total: IntCounterVec,
    pub sessions_terminated_total: IntCounterVec,
    pub session_duration_seconds: HistogramVec,

    // Permission metrics
    pub permission_denials_total: IntCounterVec,
    pub permission_checks_total: IntCounterVec,

    // Sensitive action metrics
    pub sensitive_action_confirmations_total: IntCounterVec,
    pub sensitive_action_executions_total: IntCounterVec,

    // Audit trail metrics
    pub audit_entries_total: IntCounterVec,
    pub audit_trail_verification_duration_seconds: Histogram,
    pub audit_replication_success_total: IntCounter,
    pub audit_replication_failure_total: IntCounter,

    // Security monitoring metrics
    pub security_events_total: IntCounterVec,
    pub suspicious_login_attempts_total: IntCounterVec,
    pub impossible_travel_events_total: IntCounter,

    // System metrics
    pub admin_accounts_total: IntGaugeVec,
    pub admin_accounts_by_status: IntGaugeVec,
    pub failed_login_attempts_total: IntGauge,
}

impl AdminMetrics {
    pub fn new() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        // Authentication metrics
        let login_attempts_total = register_int_counter_vec!(
            opts!("admin_login_attempts_total", "Total number of admin login attempts"),
            &["role", "outcome"]
        )?;

        let login_success_total = register_int_counter_vec!(
            opts!("admin_login_success_total", "Total number of successful admin logins"),
            &["role", "mfa_method"]
        )?;

        let login_failure_total = register_int_counter_vec!(
            opts!("admin_login_failure_total", "Total number of failed admin logins"),
            &["role", "reason"]
        )?;

        let mfa_verification_total = register_int_counter_vec!(
            opts!("admin_mfa_verification_total", "Total number of MFA verification attempts"),
            &["role", "method"]
        )?;

        let mfa_verification_failure_total = register_int_counter_vec!(
            opts!("admin_mfa_verification_failure_total", "Total number of failed MFA verification attempts"),
            &["role", "method", "reason"]
        )?;

        let account_lockouts_total = register_int_counter_vec!(
            opts!("admin_account_lockouts_total", "Total number of admin account lockouts"),
            &["role"]
        )?;

        // Session metrics
        let active_sessions = register_int_gauge_vec!(
            opts!("admin_active_sessions", "Number of active admin sessions"),
            &["role"]
        )?;

        let sessions_created_total = register_int_counter_vec!(
            opts!("admin_sessions_created_total", "Total number of admin sessions created"),
            &["role"]
        )?;

        let sessions_terminated_total = register_int_counter_vec!(
            opts!("admin_sessions_terminated_total", "Total number of admin sessions terminated"),
            &["role", "reason"]
        )?;

        let session_duration_seconds = register_histogram_vec!(
            opts!("admin_session_duration_seconds", "Duration of admin sessions"),
            &["role"],
            vec![60.0, 300.0, 900.0, 1800.0, 3600.0, 7200.0, 14400.0, 28800.0]
        )?;

        // Permission metrics
        let permission_denials_total = register_int_counter_vec!(
            opts!("admin_permission_denials_total", "Total number of admin permission denials"),
            &["role", "endpoint", "required_permission"]
        )?;

        let permission_checks_total = register_int_counter_vec!(
            opts!("admin_permission_checks_total", "Total number of admin permission checks"),
            &["role", "outcome"]
        )?;

        // Sensitive action metrics
        let sensitive_action_confirmations_total = register_int_counter_vec!(
            opts!("admin_sensitive_action_confirmations_total", "Total number of sensitive action confirmations"),
            &["role", "action_type", "method"]
        )?;

        let sensitive_action_executions_total = register_int_counter_vec!(
            opts!("admin_sensitive_action_executions_total", "Total number of sensitive action executions"),
            &["role", "action_type"]
        )?;

        // Audit trail metrics
        let audit_entries_total = register_int_counter_vec!(
            opts!("admin_audit_entries_total", "Total number of audit trail entries"),
            &["action_type", "role"]
        )?;

        let audit_trail_verification_duration_seconds = register_histogram!(
            opts!("admin_audit_trail_verification_duration_seconds", "Duration of audit trail verification"),
            vec![0.1, 0.5, 1.0, 2.5, 5.0, 10.0]
        )?;

        let audit_replication_success_total = register_int_counter!(
            opts!("admin_audit_replication_success_total", "Total number of successful audit replications")
        )?;

        let audit_replication_failure_total = register_int_counter!(
            opts!("admin_audit_replication_failure_total", "Total number of failed audit replications")
        )?;

        // Security monitoring metrics
        let security_events_total = register_int_counter_vec!(
            opts!("admin_security_events_total", "Total number of security events"),
            &["event_type", "severity"]
        )?;

        let suspicious_login_attempts_total = register_int_counter_vec!(
            opts!("admin_suspicious_login_attempts_total", "Total number of suspicious login attempts"),
            &["type", "role"]
        )?;

        let impossible_travel_events_total = register_int_counter!(
            opts!("admin_impossible_travel_events_total", "Total number of impossible travel events")
        )?;

        // System metrics
        let admin_accounts_total = register_int_gauge_vec!(
            opts!("admin_accounts_total", "Total number of admin accounts"),
            &["role"]
        )?;

        let admin_accounts_by_status = register_int_gauge_vec!(
            opts!("admin_accounts_by_status", "Number of admin accounts by status"),
            &["status"]
        )?;

        let failed_login_attempts_total = register_int_gauge!(
            opts!("admin_failed_login_attempts_total", "Total number of failed login attempts")
        )?;

        Ok(Self {
            login_attempts_total,
            login_success_total,
            login_failure_total,
            mfa_verification_total,
            mfa_verification_failure_total,
            account_lockouts_total,
            active_sessions,
            sessions_created_total,
            sessions_terminated_total,
            session_duration_seconds,
            permission_denials_total,
            permission_checks_total,
            sensitive_action_confirmations_total,
            sensitive_action_executions_total,
            audit_entries_total,
            audit_trail_verification_duration_seconds,
            audit_replication_success_total,
            audit_replication_failure_total,
            security_events_total,
            suspicious_login_attempts_total,
            impossible_travel_events_total,
            admin_accounts_total,
            admin_accounts_by_status,
            failed_login_attempts_total,
        })
    }

    pub fn record_login_attempt(&self, role: &str, outcome: &str) {
        self.login_attempts_total.with_label_values(&[role, outcome]).inc();
    }

    pub fn record_login_success(&self, role: &str, mfa_method: &str) {
        self.login_success_total.with_label_values(&[role, mfa_method]).inc();
    }

    pub fn record_login_failure(&self, role: &str, reason: &str) {
        self.login_failure_total.with_label_values(&[role, reason]).inc();
    }

    pub fn record_mfa_verification(&self, role: &str, method: &str) {
        self.mfa_verification_total.with_label_values(&[role, method]).inc();
    }

    pub fn record_mfa_verification_failure(&self, role: &str, method: &str, reason: &str) {
        self.mfa_verification_failure_total.with_label_values(&[role, method, reason]).inc();
    }

    pub fn record_account_lockout(&self, role: &str) {
        self.account_lockouts_total.with_label_values(&[role]).inc();
    }

    pub fn update_active_sessions(&self, role: &str, count: i64) {
        self.active_sessions.with_label_values(&[role]).set(count);
    }

    pub fn record_session_created(&self, role: &str) {
        self.sessions_created_total.with_label_values(&[role]).inc();
    }

    pub fn record_session_terminated(&self, role: &str, reason: &str) {
        self.sessions_terminated_total.with_label_values(&[role, reason]).inc();
    }

    pub fn record_session_duration(&self, role: &str, duration_seconds: f64) {
        self.session_duration_seconds.with_label_values(&[role]).observe(duration_seconds);
    }

    pub fn record_permission_denial(&self, role: &str, endpoint: &str, required_permission: &str) {
        self.permission_denials_total.with_label_values(&[role, endpoint, required_permission]).inc();
    }

    pub fn record_permission_check(&self, role: &str, outcome: &str) {
        self.permission_checks_total.with_label_values(&[role, outcome]).inc();
    }

    pub fn record_sensitive_action_confirmation(&self, role: &str, action_type: &str, method: &str) {
        self.sensitive_action_confirmations_total.with_label_values(&[role, action_type, method]).inc();
    }

    pub fn record_sensitive_action_execution(&self, role: &str, action_type: &str) {
        self.sensitive_action_executions_total.with_label_values(&[role, action_type]).inc();
    }

    pub fn record_audit_entry(&self, action_type: &str, role: &str) {
        self.audit_entries_total.with_label_values(&[action_type, role]).inc();
    }

    pub fn record_audit_trail_verification_duration(&self, duration_seconds: f64) {
        self.audit_trail_verification_duration_seconds.observe(duration_seconds);
    }

    pub fn record_audit_replication_success(&self) {
        self.audit_replication_success_total.inc();
    }

    pub fn record_audit_replication_failure(&self) {
        self.audit_replication_failure_total.inc();
    }

    pub fn record_security_event(&self, event_type: &str, severity: &str) {
        self.security_events_total.with_label_values(&[event_type, severity]).inc();
    }

    pub fn record_suspicious_login_attempt(&self, login_type: &str, role: &str) {
        self.suspicious_login_attempts_total.with_label_values(&[login_type, role]).inc();
    }

    pub fn record_impossible_travel_event(&self) {
        self.impossible_travel_events_total.inc();
    }

    pub fn update_admin_accounts_total(&self, role: &str, count: i64) {
        self.admin_accounts_total.with_label_values(&[role]).set(count);
    }

    pub fn update_admin_accounts_by_status(&self, status: &str, count: i64) {
        self.admin_accounts_by_status.with_label_values(&[status]).set(count);
    }

    pub fn update_failed_login_attempts_total(&self, count: i64) {
        self.failed_login_attempts_total.set(count);
    }
}

pub struct AdminObservability {
    metrics: AdminMetrics,
    registry: Registry,
}

impl AdminObservability {
    pub fn new() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let metrics = AdminMetrics::new()?;
        let registry = Registry::new();

        // Register all metrics
        registry.register(Box::new(metrics.login_attempts_total.clone()))?;
        registry.register(Box::new(metrics.login_success_total.clone()))?;
        registry.register(Box::new(metrics.login_failure_total.clone()))?;
        registry.register(Box::new(metrics.mfa_verification_total.clone()))?;
        registry.register(Box::new(metrics.mfa_verification_failure_total.clone()))?;
        registry.register(Box::new(metrics.account_lockouts_total.clone()))?;
        registry.register(Box::new(metrics.active_sessions.clone()))?;
        registry.register(Box::new(metrics.sessions_created_total.clone()))?;
        registry.register(Box::new(metrics.sessions_terminated_total.clone()))?;
        registry.register(Box::new(metrics.session_duration_seconds.clone()))?;
        registry.register(Box::new(metrics.permission_denials_total.clone()))?;
        registry.register(Box::new(metrics.permission_checks_total.clone()))?;
        registry.register(Box::new(metrics.sensitive_action_confirmations_total.clone()))?;
        registry.register(Box::new(metrics.sensitive_action_executions_total.clone()))?;
        registry.register(Box::new(metrics.audit_entries_total.clone()))?;
        registry.register(Box::new(metrics.audit_trail_verification_duration_seconds.clone()))?;
        registry.register(Box::new(metrics.audit_replication_success_total.clone()))?;
        registry.register(Box::new(metrics.audit_replication_failure_total.clone()))?;
        registry.register(Box::new(metrics.security_events_total.clone()))?;
        registry.register(Box::new(metrics.suspicious_login_attempts_total.clone()))?;
        registry.register(Box::new(metrics.impossible_travel_events_total.clone()))?;
        registry.register(Box::new(metrics.admin_accounts_total.clone()))?;
        registry.register(Box::new(metrics.admin_accounts_by_status.clone()))?;
        registry.register(Box::new(metrics.failed_login_attempts_total.clone()))?;

        Ok(Self { metrics, registry })
    }

    pub fn metrics(&self) -> &AdminMetrics {
        &self.metrics
    }

    pub fn export_metrics(&self) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let encoder = TextEncoder::new();
        let metric_families = self.registry.gather();
        let mut buffer = Vec::new();
        encoder.encode(&metric_families, &mut buffer)?;
        Ok(String::from_utf8(buffer)?)
    }
}

pub struct AdminAlerting {
    alert_thresholds: AlertThresholds,
}

#[derive(Clone)]
pub struct AlertThresholds {
    pub failed_login_rate_threshold: f64, // failures per minute
    pub impossible_travel_threshold: i32, // events per hour
    pub concurrent_sessions_threshold: i32,
    pub audit_trail_tampering_threshold: i32, // tampered entries
    pub permission_denial_rate_threshold: f64, // denials per minute
}

impl Default for AlertThresholds {
    fn default() -> Self {
        Self {
            failed_login_rate_threshold: 10.0,
            impossible_travel_threshold: 1,
            concurrent_sessions_threshold: 10,
            audit_trail_tampering_threshold: 1,
            permission_denial_rate_threshold: 5.0,
        }
    }
}

impl AdminAlerting {
    pub fn new(thresholds: AlertThresholds) -> Self {
        Self { alert_thresholds: thresholds }
    }

    pub async fn check_and_alert(&self, metrics: &AdminMetrics, stats: &AdminStatistics, security_stats: &SecurityMonitoringStats) {
        // Check for high failed login rate
        if stats.failed_login_attempts > self.alert_thresholds.failed_login_rate_threshold as i64 {
            self.send_alert(
                "HIGH_FAILED_LOGIN_RATE",
                &format!("Failed login rate exceeded threshold: {}/minute", stats.failed_login_attempts),
                "high",
            ).await;
        }

        // Check for impossible travel events
        if security_stats.impossible_travel_events >= self.alert_thresholds.impossible_travel_threshold {
            self.send_alert(
                "IMPOSSIBLE_TRAVEL_DETECTED",
                &format!("Impossible travel events detected: {}", security_stats.impossible_travel_events),
                "critical",
            ).await;
        }

        // Check for high concurrent sessions
        if stats.active_sessions >= self.alert_thresholds.concurrent_sessions_threshold {
            self.send_alert(
                "HIGH_CONCURRENT_SESSIONS",
                &format!("High number of concurrent sessions: {}", stats.active_sessions),
                "medium",
            ).await;
        }

        // Check for unresolved high-severity security events
        if security_stats.high_severity_events > 0 {
            self.send_alert(
                "UNRESOLVED_HIGH_SEVERITY_EVENTS",
                &format!("Unresolved high-severity security events: {}", security_stats.high_severity_events),
                "high",
            ).await;
        }
    }

    async fn send_alert(&self, alert_type: &str, message: &str, severity: &str) {
        // Log the alert
        match severity {
            "critical" => error!("[ALERT-{}] {}: {}", alert_type, severity, message),
            "high" => error!("[ALERT-{}] {}: {}", alert_type, severity, message),
            "medium" => warn!("[ALERT-{}] {}: {}", alert_type, severity, message),
            _ => info!("[ALERT-{}] {}: {}", alert_type, severity, message),
        }

        // In a real implementation, this would send alerts to:
        // - Slack channels
        // - Email notifications
        // - PagerDuty
        // - Security team incident response system
        // - SIEM systems
    }

    pub async fn alert_account_lockout(&self, admin_id: uuid::Uuid, role: &str, ip_address: &str) {
        self.send_alert(
            "ADMIN_ACCOUNT_LOCKED",
            &format!("Admin account {} ({}) locked due to repeated failed attempts from {}", admin_id, role, ip_address),
            "high",
        ).await;
    }

    pub async fn alert_suspicious_login(&self, admin_id: uuid::Uuid, event_type: &str, details: &str) {
        self.send_alert(
            "SUSPICIOUS_LOGIN_DETECTED",
            &format!("Suspicious login detected for admin {}: {} - {}", admin_id, event_type, details),
            "medium",
        ).await;
    }

    pub async fn alert_audit_trail_tampering(&self, tampered_entries: &[crate::admin::models::TamperedEntry]) {
        self.send_alert(
            "AUDIT_TRAIL_TAMPERING",
            &format!("Audit trail tampering detected! {} entries affected", tampered_entries.len()),
            "critical",
        ).await;
    }

    pub async fn alert_permission_denial_spike(&self, denials_per_minute: f64, role: &str) {
        self.send_alert(
            "PERMISSION_DENIAL_SPIKE",
            &format!("Permission denial spike detected for {}: {}/minute", role, denials_per_minute),
            "medium",
        ).await;
    }
}

// Structured logging helpers
pub fn log_admin_authentication(
    admin_id: uuid::Uuid,
    role: &str,
    outcome: &str,
    ip_address: &str,
    user_agent: &str,
    mfa_method: Option<&str>,
) {
    tracing::info!(
        target: "admin_authentication",
        admin_id = %admin_id,
        role = role,
        outcome = outcome,
        ip_address = ip_address,
        user_agent = user_agent,
        mfa_method = mfa_method,
        "Admin authentication event"
    );
}

pub fn log_admin_session_lifecycle(
    session_id: uuid::Uuid,
    admin_id: uuid::Uuid,
    role: &str,
    event: &str,
    reason: Option<&str>,
    ip_address: &str,
) {
    tracing::info!(
        target: "admin_session_lifecycle",
        session_id = %session_id,
        admin_id = %admin_id,
        role = role,
        event = event,
        reason = reason,
        ip_address = ip_address,
        "Admin session lifecycle event"
    );
}

pub fn log_permission_denial(
    admin_id: uuid::Uuid,
    role: &str,
    endpoint: &str,
    required_permission: &str,
    ip_address: &str,
) {
    tracing::warn!(
        target: "admin_permission_denial",
        admin_id = %admin_id,
        role = role,
        endpoint = endpoint,
        required_permission = required_permission,
        ip_address = ip_address,
        "Admin permission denied"
    );
}

pub fn log_sensitive_action(
    admin_id: uuid::Uuid,
    role: &str,
    action_type: &str,
    target_resource_type: Option<&str>,
    target_resource_id: Option<uuid::Uuid>,
    confirmation_method: &str,
    outcome: &str,
) {
    tracing::info!(
        target: "admin_sensitive_action",
        admin_id = %admin_id,
        role = role,
        action_type = action_type,
        target_resource_type = target_resource_type,
        target_resource_id = %target_resource_id,
        confirmation_method = confirmation_method,
        outcome = outcome,
        "Admin sensitive action"
    );
}

pub fn log_audit_trail_event(
    admin_id: Option<uuid::Uuid>,
    action_type: &str,
    target_resource_type: Option<&str>,
    target_resource_id: Option<uuid::Uuid>,
    sequence_number: i64,
    ip_address: Option<&str>,
) {
    tracing::info!(
        target: "admin_audit_trail",
        admin_id = %admin_id.unwrap_or_default(),
        action_type = action_type,
        target_resource_type = target_resource_type,
        target_resource_id = %target_resource_id,
        sequence_number = sequence_number,
        ip_address = ip_address,
        "Admin audit trail entry"
    );
}

pub fn log_security_event(
    admin_id: Option<uuid::Uuid>,
    event_type: &str,
    severity: &str,
    details: &str,
) {
    tracing::warn!(
        target: "admin_security_event",
        admin_id = %admin_id.unwrap_or_default(),
        event_type = event_type,
        severity = severity,
        details = details,
        "Admin security event"
    );
}
