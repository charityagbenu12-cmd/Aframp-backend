//! Admin endpoints for DDoS protection management.
//!
//! GET    /api/admin/ddos/status        — current mode, active attacks, metrics
//! GET    /api/admin/ddos/traffic       — traffic breakdown by tier/endpoint/geo
//! POST   /api/admin/ddos/block         — block an IP/CIDR/ASN
//! GET    /api/admin/ddos/attack-history — paginated attack history
//! POST   /api/admin/ddos/lockdown      — activate emergency lockdown
//! DELETE /api/admin/ddos/lockdown      — deactivate lockdown

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::ddos::{
    detector::ProtectionMode,
    queue::QueueStats,
    state::{BlockedEntry, DdosState},
};

pub fn ddos_admin_router(state: Arc<DdosState>) -> Router {
    Router::new()
        .route("/api/admin/ddos/status", get(get_status))
        .route("/api/admin/ddos/traffic", get(get_traffic))
        .route("/api/admin/ddos/block", post(block_target))
        .route("/api/admin/ddos/attack-history", get(get_attack_history))
        .route("/api/admin/ddos/lockdown", post(activate_lockdown))
        .route("/api/admin/ddos/lockdown", delete(deactivate_lockdown))
        .with_state(state)
}

// ── Status ────────────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct StatusResponse {
    mode: ProtectionMode,
    lockdown: crate::ddos::lockdown::LockdownStatus,
    active_attacks: Vec<crate::ddos::detector::AttackEvent>,
    queue: QueueStats,
    current_rps: f64,
}

async fn get_status(State(state): State<Arc<DdosState>>) -> impl IntoResponse {
    let mode = state.detector.current_mode().await;
    let lockdown = state.lockdown.status().await;
    let active_attacks = state.detector.active_attacks().await;
    let queue = state.queue.queue_stats();
    let current_rps = state.detector.current_rps().await;

    Json(StatusResponse {
        mode,
        lockdown,
        active_attacks,
        queue,
        current_rps,
    })
}

// ── Traffic breakdown ─────────────────────────────────────────────────────────

#[derive(Serialize)]
struct TrafficResponse {
    endpoint_rps: std::collections::HashMap<String, f64>,
    queue: QueueStats,
    global_rps: f64,
}

async fn get_traffic(State(state): State<Arc<DdosState>>) -> impl IntoResponse {
    let endpoint_rps = state.detector.endpoint_rps().await;
    let queue = state.queue.queue_stats();
    let global_rps = state.detector.current_rps().await;

    Json(TrafficResponse {
        endpoint_rps,
        queue,
        global_rps,
    })
}

// ── Block target ──────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct BlockRequest {
    target: String, // IP, CIDR, or ASN
    reason: String,
    blocked_by: String,
}

async fn block_target(
    State(state): State<Arc<DdosState>>,
    Json(req): Json<BlockRequest>,
) -> impl IntoResponse {
    if req.target.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "target is required" })),
        )
            .into_response();
    }

    state.block_target(&req.target, &req.reason, &req.blocked_by).await;

    (
        StatusCode::OK,
        Json(serde_json::json!({ "blocked": req.target })),
    )
        .into_response()
}

// ── Attack history ────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct HistoryQuery {
    page: Option<usize>,
    per_page: Option<usize>,
}

async fn get_attack_history(
    State(state): State<Arc<DdosState>>,
    Query(q): Query<HistoryQuery>,
) -> impl IntoResponse {
    let page = q.page.unwrap_or(0);
    let per_page = q.per_page.unwrap_or(20).min(100);
    let history = state.detector.attack_history(page, per_page).await;
    Json(history)
}

// ── Lockdown ──────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct LockdownRequest {
    trigger: Option<String>,
}

async fn activate_lockdown(
    State(state): State<Arc<DdosState>>,
    Json(req): Json<LockdownRequest>,
) -> impl IntoResponse {
    let trigger = req.trigger.as_deref().unwrap_or("manual_admin");
    state.lockdown.activate(trigger).await;

    // Also activate CDN under-attack mode
    state.cdn.activate_under_attack_mode().await;

    // Escalate detector mode
    *state.detector.mode.write().await = ProtectionMode::EmergencyLockdown;

    tracing::warn!(trigger = trigger, "Emergency lockdown activated via admin API");

    (
        StatusCode::OK,
        Json(state.lockdown.status().await),
    )
        .into_response()
}

async fn deactivate_lockdown(State(state): State<Arc<DdosState>>) -> impl IntoResponse {
    state.lockdown.deactivate().await;
    state.cdn.deactivate_under_attack_mode().await;

    // Downgrade mode if no active attacks
    if state.detector.active_attacks().await.is_empty() {
        *state.detector.mode.write().await = ProtectionMode::Passive;
    }

    tracing::info!("Emergency lockdown deactivated via admin API");

    (StatusCode::OK, Json(state.lockdown.status().await)).into_response()
}
