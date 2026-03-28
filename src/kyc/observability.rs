use prometheus::{Counter, Histogram, Gauge, IntGauge, Registry, TextEncoder, Encoder};
use std::sync::Arc;
use chrono::{DateTime, Utc};
use uuid::Uuid;
use tracing::{info, warn, error};

use crate::database::kyc_repository::{KycTier, KycStatus, KycEventType};

#[derive(Clone)]
pub struct KycMetrics {
    registry: Arc<Registry>,
    
    // Session metrics
    sessions_initiated_total: Counter,
    sessions_completed_total: Counter,
    sessions_expired_total: Counter,
    session_duration_seconds: Histogram,
    
    // Verification metrics by tier
    verifications_total: Counter,
    verifications_approved_total: Counter,
    verifications_rejected_total: Counter,
    verifications_manual_review_total: Counter,
    verification_processing_time_seconds: Histogram,
    
    // Document metrics
    documents_submitted_total: Counter,
    documents_approved_total: Counter,
    documents_rejected_total: Counter,
    document_processing_time_seconds: Histogram,
    
    // Provider metrics
    provider_api_requests_total: Counter,
    provider_api_errors_total: Counter,
    provider_webhook_received_total: Counter,
    provider_webhook_errors_total: Counter,
    provider_response_time_seconds: Histogram,
    
    // Manual review metrics
    manual_review_queue_depth: IntGauge,
    manual_review_cases_completed_total: Counter,
    manual_review_avg_processing_time_seconds: Histogram,
    
    // EDD metrics
    edd_cases_created_total: Counter,
    edd_cases_resolved_total: Counter,
    edd_active_cases: IntGauge,
    edd_triggers_total: Counter,
    
    // Transaction limit metrics
    limit_checks_total: Counter,
    limit_violations_total: Counter,
    volume_trackers_updated_total: Counter,
    
    // Compliance metrics
    compliance_alerts_total: Counter,
    compliance_reports_generated_total: Counter,
    audit_exports_total: Counter,
    
    // System health metrics
    kyc_service_health: Gauge,
    provider_health: Gauge,
    database_health: Gauge,
}

impl KycMetrics {
    pub fn new() -> Self {
        let registry = Arc::new(Registry::new());
        
        // Session metrics
        let sessions_initiated_total = Counter::new(
            "kyc_sessions_initiated_total",
            "Total number of KYC sessions initiated"
        ).unwrap();
        
        let sessions_completed_total = Counter::new(
            "kyc_sessions_completed_total",
            "Total number of KYC sessions completed"
        ).unwrap();
        
        let sessions_expired_total = Counter::new(
            "kyc_sessions_expired_total",
            "Total number of KYC sessions expired"
        ).unwrap();
        
        let session_duration_seconds = Histogram::with_opts(
            prometheus::HistogramOpts::new(
                "kyc_session_duration_seconds",
                "Duration of KYC sessions in seconds"
            ).buckets(vec![60.0, 300.0, 900.0, 1800.0, 3600.0, 7200.0])
        ).unwrap();
        
        // Verification metrics
        let verifications_total = Counter::new(
            "kyc_verifications_total",
            "Total number of KYC verifications"
        ).unwrap();
        
        let verifications_approved_total = Counter::new(
            "kyc_verifications_approved_total",
            "Total number of KYC verifications approved"
        ).unwrap();
        
        let verifications_rejected_total = Counter::new(
            "kyc_verifications_rejected_total",
            "Total number of KYC verifications rejected"
        ).unwrap();
        
        let verifications_manual_review_total = Counter::new(
            "kyc_verifications_manual_review_total",
            "Total number of KYC verifications sent to manual review"
        ).unwrap();
        
        let verification_processing_time_seconds = Histogram::with_opts(
            prometheus::HistogramOpts::new(
                "kyc_verification_processing_time_seconds",
                "Time taken to process KYC verifications"
            ).buckets(vec![60.0, 300.0, 900.0, 1800.0, 3600.0, 7200.0, 14400.0])
        ).unwrap();
        
        // Document metrics
        let documents_submitted_total = Counter::new(
            "kyc_documents_submitted_total",
            "Total number of documents submitted"
        ).unwrap();
        
        let documents_approved_total = Counter::new(
            "kyc_documents_approved_total",
            "Total number of documents approved"
        ).unwrap();
        
        let documents_rejected_total = Counter::new(
            "kyc_documents_rejected_total",
            "Total number of documents rejected"
        ).unwrap();
        
        let document_processing_time_seconds = Histogram::with_opts(
            prometheus::HistogramOpts::new(
                "kyc_document_processing_time_seconds",
                "Time taken to process documents"
            ).buckets(vec![10.0, 30.0, 60.0, 120.0, 300.0, 600.0])
        ).unwrap();
        
        // Provider metrics
        let provider_api_requests_total = Counter::new(
            "kyc_provider_api_requests_total",
            "Total number of provider API requests"
        ).unwrap();
        
        let provider_api_errors_total = Counter::new(
            "kyc_provider_api_errors_total",
            "Total number of provider API errors"
        ).unwrap();
        
        let provider_webhook_received_total = Counter::new(
            "kyc_provider_webhook_received_total",
            "Total number of provider webhooks received"
        ).unwrap();
        
        let provider_webhook_errors_total = Counter::new(
            "kyc_provider_webhook_errors_total",
            "Total number of provider webhook errors"
        ).unwrap();
        
        let provider_response_time_seconds = Histogram::with_opts(
            prometheus::HistogramOpts::new(
                "kyc_provider_response_time_seconds",
                "Provider API response time in seconds"
            ).buckets(vec![0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0])
        ).unwrap();
        
        // Manual review metrics
        let manual_review_queue_depth = IntGauge::new(
            "kyc_manual_review_queue_depth",
            "Current depth of manual review queue"
        ).unwrap();
        
        let manual_review_cases_completed_total = Counter::new(
            "kyc_manual_review_cases_completed_total",
            "Total number of manual review cases completed"
        ).unwrap();
        
        let manual_review_avg_processing_time_seconds = Histogram::with_opts(
            prometheus::HistogramOpts::new(
                "kyc_manual_review_processing_time_seconds",
                "Time taken to process manual review cases"
            ).buckets(vec![300.0, 900.0, 1800.0, 3600.0, 7200.0, 14400.0, 28800.0])
        ).unwrap();
        
        // EDD metrics
        let edd_cases_created_total = Counter::new(
            "kyc_edd_cases_created_total",
            "Total number of EDD cases created"
        ).unwrap();
        
        let edd_cases_resolved_total = Counter::new(
            "kyc_edd_cases_resolved_total",
            "Total number of EDD cases resolved"
        ).unwrap();
        
        let edd_active_cases = IntGauge::new(
            "kyc_edd_active_cases",
            "Current number of active EDD cases"
        ).unwrap();
        
        let edd_triggers_total = Counter::new(
            "kyc_edd_triggers_total",
            "Total number of EDD triggers"
        ).unwrap();
        
        // Transaction limit metrics
        let limit_checks_total = Counter::new(
            "kyc_limit_checks_total",
            "Total number of transaction limit checks"
        ).unwrap();
        
        let limit_violations_total = Counter::new(
            "kyc_limit_violations_total",
            "Total number of transaction limit violations"
        ).unwrap();
        
        let volume_trackers_updated_total = Counter::new(
            "kyc_volume_trackers_updated_total",
            "Total number of volume tracker updates"
        ).unwrap();
        
        // Compliance metrics
        let compliance_alerts_total = Counter::new(
            "kyc_compliance_alerts_total",
            "Total number of compliance alerts"
        ).unwrap();
        
        let compliance_reports_generated_total = Counter::new(
            "kyc_compliance_reports_generated_total",
            "Total number of compliance reports generated"
        ).unwrap();
        
        let audit_exports_total = Counter::new(
            "kyc_audit_exports_total",
            "Total number of audit trail exports"
        ).unwrap();
        
        // System health metrics
        let kyc_service_health = Gauge::new(
            "kyc_service_health",
            "KYC service health (1 = healthy, 0 = unhealthy)"
        ).unwrap();
        
        let provider_health = Gauge::new(
            "kyc_provider_health",
            "Provider health (1 = healthy, 0 = unhealthy)"
        ).unwrap();
        
        let database_health = Gauge::new(
            "kyc_database_health",
            "Database health (1 = healthy, 0 = unhealthy)"
        ).unwrap();
        
        // Register all metrics
        registry.register(Box::new(sessions_initiated_total.clone())).unwrap();
        registry.register(Box::new(sessions_completed_total.clone())).unwrap();
        registry.register(Box::new(sessions_expired_total.clone())).unwrap();
        registry.register(Box::new(session_duration_seconds.clone())).unwrap();
        
        registry.register(Box::new(verifications_total.clone())).unwrap();
        registry.register(Box::new(verifications_approved_total.clone())).unwrap();
        registry.register(Box::new(verifications_rejected_total.clone())).unwrap();
        registry.register(Box::new(verifications_manual_review_total.clone())).unwrap();
        registry.register(Box::new(verification_processing_time_seconds.clone())).unwrap();
        
        registry.register(Box::new(documents_submitted_total.clone())).unwrap();
        registry.register(Box::new(documents_approved_total.clone())).unwrap();
        registry.register(Box::new(documents_rejected_total.clone())).unwrap();
        registry.register(Box::new(document_processing_time_seconds.clone())).unwrap();
        
        registry.register(Box::new(provider_api_requests_total.clone())).unwrap();
        registry.register(Box::new(provider_api_errors_total.clone())).unwrap();
        registry.register(Box::new(provider_webhook_received_total.clone())).unwrap();
        registry.register(Box::new(provider_webhook_errors_total.clone())).unwrap();
        registry.register(Box::new(provider_response_time_seconds.clone())).unwrap();
        
        registry.register(Box::new(manual_review_queue_depth.clone())).unwrap();
        registry.register(Box::new(manual_review_cases_completed_total.clone())).unwrap();
        registry.register(Box::new(manual_review_avg_processing_time_seconds.clone())).unwrap();
        
        registry.register(Box::new(edd_cases_created_total.clone())).unwrap();
        registry.register(Box::new(edd_cases_resolved_total.clone())).unwrap();
        registry.register(Box::new(edd_active_cases.clone())).unwrap();
        registry.register(Box::new(edd_triggers_total.clone())).unwrap();
        
        registry.register(Box::new(limit_checks_total.clone())).unwrap();
        registry.register(Box::new(limit_violations_total.clone())).unwrap();
        registry.register(Box::new(volume_trackers_updated_total.clone())).unwrap();
        
        registry.register(Box::new(compliance_alerts_total.clone())).unwrap();
        registry.register(Box::new(compliance_reports_generated_total.clone())).unwrap();
        registry.register(Box::new(audit_exports_total.clone())).unwrap();
        
        registry.register(Box::new(kyc_service_health.clone())).unwrap();
        registry.register(Box::new(provider_health.clone())).unwrap();
        registry.register(Box::new(database_health.clone())).unwrap();
        
        Self {
            registry,
            sessions_initiated_total,
            sessions_completed_total,
            sessions_expired_total,
            session_duration_seconds,
            verifications_total,
            verifications_approved_total,
            verifications_rejected_total,
            verifications_manual_review_total,
            verification_processing_time_seconds,
            documents_submitted_total,
            documents_approved_total,
            documents_rejected_total,
            document_processing_time_seconds,
            provider_api_requests_total,
            provider_api_errors_total,
            provider_webhook_received_total,
            provider_webhook_errors_total,
            provider_response_time_seconds,
            manual_review_queue_depth,
            manual_review_cases_completed_total,
            manual_review_avg_processing_time_seconds,
            edd_cases_created_total,
            edd_cases_resolved_total,
            edd_active_cases,
            edd_triggers_total,
            limit_checks_total,
            limit_violations_total,
            volume_trackers_updated_total,
            compliance_alerts_total,
            compliance_reports_generated_total,
            audit_exports_total,
            kyc_service_health,
            provider_health,
            database_health,
        }
    }
    
    pub fn registry(&self) -> &Registry {
        &self.registry
    }
    
    // Session metrics
    pub fn record_session_initiated(&self, tier: KycTier) {
        self.sessions_initiated_total
            .with_label_values(&[&format!("{:?}", tier)])
            .inc();
        info!("KYC session initiated for tier {:?}", tier);
    }
    
    pub fn record_session_completed(&self, tier: KycTier, duration_seconds: f64) {
        self.sessions_completed_total
            .with_label_values(&[&format!("{:?}", tier)])
            .inc();
        self.session_duration_seconds
            .with_label_values(&[&format!("{:?}", tier)])
            .observe(duration_seconds);
        info!("KYC session completed for tier {:?} in {} seconds", tier, duration_seconds);
    }
    
    pub fn record_session_expired(&self, tier: KycTier) {
        self.sessions_expired_total
            .with_label_values(&[&format!("{:?}", tier)])
            .inc();
        warn!("KYC session expired for tier {:?}", tier);
    }
    
    // Verification metrics
    pub fn record_verification_started(&self, tier: KycTier) {
        self.verifications_total
            .with_label_values(&[&format!("{:?}", tier)])
            .inc();
    }
    
    pub fn record_verification_approved(&self, tier: KycTier, processing_time_seconds: f64) {
        self.verifications_approved_total
            .with_label_values(&[&format!("{:?}", tier)])
            .inc();
        self.verification_processing_time_seconds
            .with_label_values(&[&format!("{:?}", tier)])
            .observe(processing_time_seconds);
        info!("KYC verification approved for tier {:?} in {} seconds", tier, processing_time_seconds);
    }
    
    pub fn record_verification_rejected(&self, tier: KycTier, processing_time_seconds: f64) {
        self.verifications_rejected_total
            .with_label_values(&[&format!("{:?}", tier)])
            .inc();
        self.verification_processing_time_seconds
            .with_label_values(&[&format!("{:?}", tier)])
            .observe(processing_time_seconds);
        warn!("KYC verification rejected for tier {:?} in {} seconds", tier, processing_time_seconds);
    }
    
    pub fn record_verification_manual_review(&self, tier: KycTier, processing_time_seconds: f64) {
        self.verifications_manual_review_total
            .with_label_values(&[&format!("{:?}", tier)])
            .inc();
        self.verification_processing_time_seconds
            .with_label_values(&[&format!("{:?}", tier)])
            .observe(processing_time_seconds);
        info!("KYC verification sent to manual review for tier {:?}", tier);
    }
    
    // Document metrics
    pub fn record_document_submitted(&self, document_type: &str) {
        self.documents_submitted_total
            .with_label_values(&[document_type])
            .inc();
    }
    
    pub fn record_document_approved(&self, document_type: &str, processing_time_seconds: f64) {
        self.documents_approved_total
            .with_label_values(&[document_type])
            .inc();
        self.document_processing_time_seconds
            .with_label_values(&[document_type])
            .observe(processing_time_seconds);
    }
    
    pub fn record_document_rejected(&self, document_type: &str, processing_time_seconds: f64) {
        self.documents_rejected_total
            .with_label_values(&[document_type])
            .inc();
        self.document_processing_time_seconds
            .with_label_values(&[document_type])
            .observe(processing_time_seconds);
    }
    
    // Provider metrics
    pub fn record_provider_api_request(&self, provider: &str, endpoint: &str, response_time_seconds: f64) {
        self.provider_api_requests_total
            .with_label_values(&[provider, endpoint])
            .inc();
        self.provider_response_time_seconds
            .with_label_values(&[provider, endpoint])
            .observe(response_time_seconds);
    }
    
    pub fn record_provider_api_error(&self, provider: &str, endpoint: &str, error_type: &str) {
        self.provider_api_errors_total
            .with_label_values(&[provider, endpoint, error_type])
            .inc();
        error!("Provider API error: {} {} {}", provider, endpoint, error_type);
    }
    
    pub fn record_webhook_received(&self, provider: &str, event_type: &str) {
        self.provider_webhook_received_total
            .with_label_values(&[provider, event_type])
            .inc();
    }
    
    pub fn record_webhook_error(&self, provider: &str, error_type: &str) {
        self.provider_webhook_errors_total
            .with_label_values(&[provider, error_type])
            .inc();
        error!("Webhook error: {} {}", provider, error_type);
    }
    
    // Manual review metrics
    pub fn update_manual_review_queue_depth(&self, depth: i64) {
        self.manual_review_queue_depth.set(depth);
    }
    
    pub fn record_manual_review_completed(&self, processing_time_seconds: f64) {
        self.manual_review_cases_completed_total.inc();
        self.manual_review_avg_processing_time_seconds.observe(processing_time_seconds);
    }
    
    // EDD metrics
    pub fn record_edd_case_created(&self, severity: &str, tier: KycTier) {
        self.edd_cases_created_total
            .with_label_values(&[severity, &format!("{:?}", tier)])
            .inc();
        self.edd_active_cases.inc();
        warn!("EDD case created: {} {:?}", severity, tier);
    }
    
    pub fn record_edd_case_resolved(&self) {
        self.edd_cases_resolved_total.inc();
        self.edd_active_cases.dec();
        info!("EDD case resolved");
    }
    
    pub fn record_edd_trigger(&self, trigger_type: &str, severity: &str, tier: KycTier) {
        self.edd_triggers_total
            .with_label_values(&[trigger_type, severity, &format!("{:?}", tier)])
            .inc();
        warn!("EDD trigger: {} {} {:?}", trigger_type, severity, tier);
    }
    
    // Transaction limit metrics
    pub fn record_limit_check(&self, tier: KycTier) {
        self.limit_checks_total
            .with_label_values(&[&format!("{:?}", tier)])
            .inc();
    }
    
    pub fn record_limit_violation(&self, tier: KycTier, violation_type: &str) {
        self.limit_violations_total
            .with_label_values(&[&format!("{:?}", tier), violation_type])
            .inc();
        warn!("Transaction limit violation: {:?} {}", tier, violation_type);
    }
    
    pub fn record_volume_tracker_update(&self, tier: KycTier) {
        self.volume_trackers_updated_total
            .with_label_values(&[&format!("{:?}", tier)])
            .inc();
    }
    
    // Compliance metrics
    pub fn record_compliance_alert(&self, alert_type: &str, severity: &str) {
        self.compliance_alerts_total
            .with_label_values(&[alert_type, severity])
            .inc();
        warn!("Compliance alert: {} {}", alert_type, severity);
    }
    
    pub fn record_compliance_report_generated(&self, report_type: &str) {
        self.compliance_reports_generated_total
            .with_label_values(&[report_type])
            .inc();
        info!("Compliance report generated: {}", report_type);
    }
    
    pub fn record_audit_export(&self, format: &str, consumer_id: Uuid) {
        self.audit_exports_total
            .with_label_values(&[format])
            .inc();
        info!("Audit trail exported: {} for consumer {}", format, consumer_id);
    }
    
    // System health metrics
    pub fn update_service_health(&self, healthy: bool) {
        let value = if healthy { 1.0 } else { 0.0 };
        self.kyc_service_health.set(value);
    }
    
    pub fn update_provider_health(&self, provider: &str, healthy: bool) {
        let value = if healthy { 1.0 } else { 0.0 };
        self.provider_health
            .with_label_values(&[provider])
            .set(value);
    }
    
    pub fn update_database_health(&self, healthy: bool) {
        let value = if healthy { 1.0 } else { 0.0 };
        self.database_health.set(value);
    }
    
    /// Export metrics in Prometheus format
    pub fn export(&self) -> Result<String, prometheus::Error> {
        let encoder = TextEncoder::new();
        let metric_families = self.registry.gather();
        encoder.encode_to_string(&metric_families)
    }
}

// Structured logging helpers
pub struct KycLogger;

impl KycLogger {
    pub fn log_kyc_event(
        consumer_id: Uuid,
        event_type: KycEventType,
        tier: Option<KycTier>,
        provider: Option<&str>,
        details: &str,
        metadata: Option<&serde_json::Value>,
    ) {
        let mut log_data = serde_json::json!({
            "consumer_id": consumer_id,
            "event_type": format!("{:?}", event_type),
            "details": details,
            "timestamp": Utc::now().to_rfc3339()
        });
        
        if let Some(t) = tier {
            log_data["tier"] = serde_json::Value::String(format!("{:?}", t));
        }
        
        if let Some(p) = provider {
            log_data["provider"] = serde_json::Value::String(p.to_string());
        }
        
        if let Some(m) = metadata {
            log_data["metadata"] = m.clone();
        }
        
        match event_type {
            KycEventType::SessionInitiated => {
                info!("KYC event: {}", serde_json::to_string(&log_data).unwrap_or_default());
            },
            KycEventType::DecisionMade => {
                info!("KYC decision: {}", serde_json::to_string(&log_data).unwrap_or_default());
            },
            KycEventType::ManualReviewAssigned => {
                warn!("KYC manual review: {}", serde_json::to_string(&log_data).unwrap_or_default());
            },
            KycEventType::EnhancedDueDiligenceTriggered => {
                warn!("KYC EDD triggered: {}", serde_json::to_string(&log_data).unwrap_or_default());
            },
            _ => {
                info!("KYC event: {}", serde_json::to_string(&log_data).unwrap_or_default());
            }
        }
    }
    
    pub fn log_decision(
        consumer_id: Uuid,
        decision: KycStatus,
        tier: KycTier,
        reason: &str,
        reviewer: Option<Uuid>,
        provider_response: Option<&str>,
    ) {
        let log_data = serde_json::json!({
            "consumer_id": consumer_id,
            "decision": format!("{:?}", decision),
            "tier": format!("{:?}", tier),
            "reason": reason,
            "reviewer": reviewer,
            "provider_response": provider_response,
            "timestamp": Utc::now().to_rfc3339()
        });
        
        match decision {
            KycStatus::Approved => {
                info!("KYC approved: {}", serde_json::to_string(&log_data).unwrap_or_default());
            },
            KycStatus::Rejected => {
                warn!("KYC rejected: {}", serde_json::to_string(&log_data).unwrap_or_default());
            },
            KycStatus::ManualReview => {
                warn!("KYC manual review: {}", serde_json::to_string(&log_data).unwrap_or_default());
            },
            _ => {
                info!("KYC decision: {}", serde_json::to_string(&log_data).unwrap_or_default());
            }
        }
    }
    
    pub fn log_provider_error(
        provider: &str,
        operation: &str,
        error: &str,
        consumer_id: Option<Uuid>,
    ) {
        let log_data = serde_json::json!({
            "provider": provider,
            "operation": operation,
            "error": error,
            "consumer_id": consumer_id,
            "timestamp": Utc::now().to_rfc3339()
        });
        
        error!("KYC provider error: {}", serde_json::to_string(&log_data).unwrap_or_default());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_metrics_creation() {
        let metrics = KycMetrics::new();
        assert!(metrics.export().is_ok());
    }
    
    #[test]
    fn test_session_metrics() {
        let metrics = KycMetrics::new();
        metrics.record_session_initiated(KycTier::Basic);
        metrics.record_session_completed(KycTier::Basic, 300.0);
        
        let export = metrics.export().unwrap();
        assert!(export.contains("kyc_sessions_initiated_total"));
        assert!(export.contains("kyc_sessions_completed_total"));
    }
}
