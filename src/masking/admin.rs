//! Admin endpoints for masking rule management and effectiveness status.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json, Router,
    routing::{delete, get, patch, post},
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;

use crate::masking::{
    engine::MaskingStrategy,
    patterns::scan_and_redact,
    rules::{MaskingRule, RuleStore},
};

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct MaskingAdminState {
    pub rules: Arc<RuleStore>,
}

impl MaskingAdminState {
    pub fn new() -> Self {
        Self {
            rules: Arc::new(RuleStore::new()),
        }
    }
}

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct CreateRuleRequest {
    pub field_name: String,
    pub category: String,
    pub strategy: MaskingStrategy,
    pub channels: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateRuleRequest {
    pub field_name: Option<String>,
    pub category: Option<String>,
    pub strategy: Option<MaskingStrategy>,
    pub channels: Option<Vec<String>>,
    pub enabled: Option<bool>,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// GET /api/admin/security/masking/rules
pub async fn list_rules(State(state): State<Arc<MaskingAdminState>>) -> impl IntoResponse {
    let rules = state.rules.list();
    Json(json!({ "rules": rules }))
}

/// POST /api/admin/security/masking/rules
pub async fn create_rule(
    State(state): State<Arc<MaskingAdminState>>,
    Json(req): Json<CreateRuleRequest>,
) -> impl IntoResponse {
    let rule = MaskingRule::new(req.field_name, req.category, req.strategy, req.channels);
    let id = state.rules.add(rule);
    (StatusCode::CREATED, Json(json!({ "id": id })))
}

/// PATCH /api/admin/security/masking/rules/:rule_id
pub async fn update_rule(
    State(state): State<Arc<MaskingAdminState>>,
    Path(rule_id): Path<String>,
    Json(req): Json<UpdateRuleRequest>,
) -> impl IntoResponse {
    match state.rules.get(&rule_id) {
        None => (StatusCode::NOT_FOUND, Json(json!({"error": "rule not found"}))),
        Some(mut existing) => {
            if let Some(f) = req.field_name { existing.field_name = f; }
            if let Some(c) = req.category { existing.category = c; }
            if let Some(s) = req.strategy { existing.strategy = s; }
            if let Some(ch) = req.channels { existing.channels = ch; }
            if let Some(e) = req.enabled { existing.enabled = e; }
            state.rules.update(&rule_id, existing);
            (StatusCode::OK, Json(json!({ "updated": true })))
        }
    }
}

/// DELETE /api/admin/security/masking/rules/:rule_id
pub async fn delete_rule(
    State(state): State<Arc<MaskingAdminState>>,
    Path(rule_id): Path<String>,
) -> impl IntoResponse {
    if state.rules.remove(&rule_id) {
        (StatusCode::OK, Json(json!({ "deleted": true })))
    } else {
        (StatusCode::NOT_FOUND, Json(json!({ "error": "rule not found" })))
    }
}

/// GET /api/admin/security/masking/status
/// Runs a synthetic effectiveness test and returns per-channel status.
pub async fn masking_status(State(_state): State<Arc<MaskingAdminState>>) -> impl IntoResponse {
    let channels = run_effectiveness_test();
    Json(json!({
        "last_tested": Utc::now().to_rfc3339(),
        "channels": channels
    }))
}

// ---------------------------------------------------------------------------
// Effectiveness test
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct ChannelStatus {
    channel: &'static str,
    passed: bool,
    detail: &'static str,
}

fn run_effectiveness_test() -> Vec<ChannelStatus> {
    let mut results = Vec::new();

    // Test log message pattern scanner
    let test_msg = "token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c email=test@example.com";
    let (sanitised, detected) = scan_and_redact(test_msg);
    let log_passed = !sanitised.contains("eyJ") && !sanitised.contains("test@example.com");
    if !log_passed {
        crate::masking::metrics::record_masking_alert("log_message");
        tracing::error!("MASKING EFFECTIVENESS TEST FAILED: log_message channel");
    }
    results.push(ChannelStatus {
        channel: "log_message",
        passed: log_passed,
        detail: if log_passed { "all patterns redacted" } else { "UNMASKED DATA DETECTED" },
    });

    // Test structured field masking
    let mut test_event = serde_json::Map::new();
    test_event.insert("password".into(), serde_json::Value::String("secret123".into()));
    test_event.insert("amount".into(), serde_json::Value::Number(100.into()));
    crate::masking::engine::mask_log_event(&mut test_event);
    let field_passed = test_event["password"] != "secret123" && test_event["amount"] == 100;
    if !field_passed {
        crate::masking::metrics::record_masking_alert("log_field");
        tracing::error!("MASKING EFFECTIVENESS TEST FAILED: log_field channel");
    }
    results.push(ChannelStatus {
        channel: "log_field",
        passed: field_passed,
        detail: if field_passed { "sensitive fields masked" } else { "UNMASKED DATA DETECTED" },
    });

    // Test response masking
    let test_resp = serde_json::json!({"account_number": "0123456789", "nin": "12345678901"});
    let masked_resp = crate::masking::response::mask_consumer_response(test_resp);
    let resp_passed = masked_resp["account_number"] != "0123456789"
        && masked_resp.get("nin").is_none();
    if !resp_passed {
        crate::masking::metrics::record_masking_alert("response");
        tracing::error!("MASKING EFFECTIVENESS TEST FAILED: response channel");
    }
    results.push(ChannelStatus {
        channel: "response",
        passed: resp_passed,
        detail: if resp_passed { "response fields masked" } else { "UNMASKED DATA DETECTED" },
    });

    results
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn masking_admin_routes() -> Router<Arc<MaskingAdminState>> {
    Router::new()
        .route("/security/masking/rules", get(list_rules).post(create_rule))
        .route("/security/masking/rules/:rule_id", patch(update_rule).delete(delete_rule))
        .route("/security/masking/status", get(masking_status))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_effectiveness_test_passes() {
        let results = run_effectiveness_test();
        for r in &results {
            assert!(r.passed, "Channel {} failed effectiveness test", r.channel);
        }
    }
}
