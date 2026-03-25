use std::collections::HashMap;
use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::Response;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::PgPool;
use tracing::{debug, warn};

use crate::cache::RedisCache;
use crate::middleware::api_key::AuthenticatedKey;

pub mod anomaly;
pub mod consistency;
pub mod errors;
pub mod field_validation;
pub mod structural;

use anomaly::{evaluate_anomaly, AnomalyAssessment, ConsumerProfile};
use consistency::validate_consistency;
use errors::IntegrityError;
use field_validation::{validate_fields, ValidationContext};
use structural::{endpoint_max_body_size, validate_structure};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IntegrityEndpoint {
    OnrampInitiate,
    OfframpInitiate,
    BatchCngnTransfer,
    BatchFiatPayout,
}

impl IntegrityEndpoint {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OnrampInitiate => "onramp_initiate",
            Self::OfframpInitiate => "offramp_initiate",
            Self::BatchCngnTransfer => "batch_cngn_transfer",
            Self::BatchFiatPayout => "batch_fiat_payout",
        }
    }
}

#[derive(Debug, Clone)]
pub struct RequestIntegrityState {
    pub endpoint: IntegrityEndpoint,
    pub db: Option<Arc<PgPool>>,
    pub cache: Option<Arc<RedisCache>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SecurityAuditEvent {
    pub consumer_id: String,
    pub endpoint: String,
    pub method: String,
    pub layer: &'static str,
    pub error_code: String,
    pub error_message: String,
    pub field: Option<String>,
    pub request_body: Value,
    pub request_headers: HashMap<String, String>,
    pub context: Option<Value>,
}

pub async fn request_integrity_middleware(
    State(state): State<RequestIntegrityState>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let consumer_id = resolve_consumer_id(&req);
    let endpoint = state.endpoint;
    let method = req.method().clone();
    let headers = flatten_headers(req.headers());

    let (parts, body) = req.into_parts();
    let max_body_size = endpoint_max_body_size(endpoint);
    let body_bytes = match to_bytes(body, max_body_size + 1).await {
        Ok(bytes) => bytes,
        Err(error) => {
            let integrity_error = IntegrityError::payload_too_large(
                endpoint,
                max_body_size,
                format!("Request body could not be buffered safely: {error}"),
            );
            persist_failure(
                &state,
                SecurityAuditEvent {
                    consumer_id,
                    endpoint: parts.uri.path().to_string(),
                    method: method.to_string(),
                    layer: integrity_error.layer.as_str(),
                    error_code: integrity_error.code.clone(),
                    error_message: integrity_error.message.clone(),
                    field: integrity_error.field.clone(),
                    request_body: Value::Null,
                    request_headers: headers,
                    context: integrity_error.details.clone(),
                },
            )
            .await;
            return integrity_error.into_response();
        }
    };

    if body_bytes.len() > max_body_size {
        let integrity_error = IntegrityError::payload_too_large(
            endpoint,
            max_body_size,
            format!("Request body exceeds the configured limit of {max_body_size} bytes"),
        );
        persist_failure(
            &state,
            SecurityAuditEvent {
                consumer_id,
                endpoint: parts.uri.path().to_string(),
                method: method.to_string(),
                layer: integrity_error.layer.as_str(),
                error_code: integrity_error.code.clone(),
                error_message: integrity_error.message.clone(),
                field: integrity_error.field.clone(),
                request_body: Value::Null,
                request_headers: headers,
                context: integrity_error.details.clone(),
            },
        )
        .await;
        return integrity_error.into_response();
    }

    let payload = match serde_json::from_slice::<Value>(&body_bytes) {
        Ok(value) => value,
        Err(error) => {
            let integrity_error = IntegrityError::invalid_json(error.to_string());
            persist_failure(
                &state,
                SecurityAuditEvent {
                    consumer_id,
                    endpoint: parts.uri.path().to_string(),
                    method: method.to_string(),
                    layer: integrity_error.layer.as_str(),
                    error_code: integrity_error.code.clone(),
                    error_message: integrity_error.message.clone(),
                    field: integrity_error.field.clone(),
                    request_body: Value::Null,
                    request_headers: headers,
                    context: integrity_error.details.clone(),
                },
            )
            .await;
            return integrity_error.into_response();
        }
    };

    if let Err(error) = validate_structure(endpoint, &payload, body_bytes.len()) {
        persist_failure(
            &state,
            SecurityAuditEvent {
                consumer_id,
                endpoint: parts.uri.path().to_string(),
                method: method.to_string(),
                layer: error.layer.as_str(),
                error_code: error.code.clone(),
                error_message: error.message.clone(),
                field: error.field.clone(),
                request_body: payload.clone(),
                request_headers: headers,
                context: error.details.clone(),
            },
        )
        .await;
        return error.into_response();
    }

    let mut ctx = ValidationContext::default();
    if let Err(error) = validate_fields(endpoint, &payload, &state, &mut ctx).await {
        persist_failure(
            &state,
            SecurityAuditEvent {
                consumer_id,
                endpoint: parts.uri.path().to_string(),
                method: method.to_string(),
                layer: error.layer.as_str(),
                error_code: error.code.clone(),
                error_message: error.message.clone(),
                field: error.field.clone(),
                request_body: payload.clone(),
                request_headers: headers,
                context: error.details.clone(),
            },
        )
        .await;
        return error.into_response();
    }

    if let Err(error) = validate_consistency(endpoint, &payload, &state, &ctx).await {
        persist_failure(
            &state,
            SecurityAuditEvent {
                consumer_id,
                endpoint: parts.uri.path().to_string(),
                method: method.to_string(),
                layer: error.layer.as_str(),
                error_code: error.code.clone(),
                error_message: error.message.clone(),
                field: error.field.clone(),
                request_body: payload.clone(),
                request_headers: headers,
                context: error.details.clone(),
            },
        )
        .await;
        return error.into_response();
    }

    if let Some(assessment) = evaluate_anomaly(endpoint, &payload, &consumer_id, &state, &ctx).await {
        debug!(
            consumer_id = %consumer_id,
            endpoint = endpoint.as_str(),
            flagged = assessment.flagged,
            "Request anomaly assessment complete"
        );
        let mut req = Request::from_parts(parts, Body::from(body_bytes));
        req.extensions_mut().insert(assessment);
        return next.run(req).await;
    }

    let req = Request::from_parts(parts, Body::from(body_bytes));
    next.run(req).await
}

fn resolve_consumer_id(req: &Request<Body>) -> String {
    req.extensions()
        .get::<AuthenticatedKey>()
        .map(|auth| auth.consumer_id.to_string())
        .or_else(|| {
            req.headers()
                .get("x-consumer-id")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
        })
        .unwrap_or_else(|| "anonymous".to_string())
}

fn flatten_headers(headers: &axum::http::HeaderMap) -> HashMap<String, String> {
    headers
        .iter()
        .filter_map(|(name, value)| value.to_str().ok().map(|v| (name.to_string(), v.to_string())))
        .collect()
}

async fn persist_failure(state: &RequestIntegrityState, event: SecurityAuditEvent) {
    warn!(
        consumer_id = %event.consumer_id,
        endpoint = %event.endpoint,
        layer = event.layer,
        error_code = %event.error_code,
        error_message = %event.error_message,
        "Request integrity failure"
    );

    let Some(db) = &state.db else {
        return;
    };

    let headers_json = match serde_json::to_value(&event.request_headers) {
        Ok(value) => value,
        Err(error) => {
            warn!(error = %error, "Failed to serialize integrity audit headers");
            Value::Null
        }
    };

    if let Err(error) = sqlx::query(
        r#"
        INSERT INTO security_audit_log
            (consumer_id, endpoint, method, validation_layer, error_code, error_message, field_name, request_body, request_headers, context)
        VALUES
            ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        "#,
    )
    .bind(event.consumer_id)
    .bind(event.endpoint)
    .bind(event.method)
    .bind(event.layer)
    .bind(event.error_code)
    .bind(event.error_message)
    .bind(event.field)
    .bind(sqlx::types::Json(event.request_body))
    .bind(sqlx::types::Json(headers_json))
    .bind(event.context.map(sqlx::types::Json))
    .execute(db.as_ref())
    .await
    {
        warn!(error = %error, "Failed to persist request integrity audit log");
    }
}

pub(crate) fn parse_profile(value: Option<String>) -> Option<ConsumerProfile> {
    value.and_then(|raw| serde_json::from_str::<ConsumerProfile>(&raw).ok())
}

pub(crate) fn parse_anomaly_assessment(req: &Request<Body>) -> Option<AnomalyAssessment> {
    req.extensions().get::<AnomalyAssessment>().cloned()
}
