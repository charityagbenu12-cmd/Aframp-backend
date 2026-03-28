use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;
use serde_json::{json, Value};

use super::IntegrityEndpoint;

#[derive(Debug, Clone, Copy)]
pub enum IntegrityLayer {
    Structural,
    Field,
    Consistency,
}

impl IntegrityLayer {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Structural => "structural",
            Self::Field => "field_validation",
            Self::Consistency => "consistency",
        }
    }
}

#[derive(Debug, Clone)]
pub struct IntegrityError {
    pub layer: IntegrityLayer,
    pub status: StatusCode,
    pub code: String,
    pub message: String,
    pub field: Option<String>,
    pub details: Option<Value>,
}

#[derive(Debug, Serialize)]
struct IntegrityErrorBody {
    error: IntegrityErrorDetail,
}

#[derive(Debug, Serialize)]
struct IntegrityErrorDetail {
    code: String,
    message: String,
    layer: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    field: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<Value>,
}

impl IntegrityError {
    pub fn structural(code: impl Into<String>, message: impl Into<String>, field: Option<String>) -> Self {
        Self {
            layer: IntegrityLayer::Structural,
            status: StatusCode::BAD_REQUEST,
            code: code.into(),
            message: message.into(),
            field,
            details: None,
        }
    }

    pub fn field(code: impl Into<String>, message: impl Into<String>, field: Option<String>) -> Self {
        Self {
            layer: IntegrityLayer::Field,
            status: StatusCode::BAD_REQUEST,
            code: code.into(),
            message: message.into(),
            field,
            details: None,
        }
    }

    pub fn consistency(code: impl Into<String>, message: impl Into<String>, field: Option<String>) -> Self {
        Self {
            layer: IntegrityLayer::Consistency,
            status: StatusCode::UNPROCESSABLE_ENTITY,
            code: code.into(),
            message: message.into(),
            field,
            details: None,
        }
    }

    pub fn with_details(mut self, details: Value) -> Self {
        self.details = Some(details);
        self
    }

    pub fn invalid_json(reason: String) -> Self {
        Self::structural(
            "INVALID_JSON_BODY",
            "Request body is not valid JSON",
            None,
        )
        .with_details(json!({ "reason": reason }))
    }

    pub fn payload_too_large(endpoint: IntegrityEndpoint, max_body_size: usize, reason: String) -> Self {
        Self {
            layer: IntegrityLayer::Structural,
            status: StatusCode::PAYLOAD_TOO_LARGE,
            code: "REQUEST_BODY_TOO_LARGE".to_string(),
            message: format!(
                "Request body for {} exceeds the maximum allowed size",
                endpoint.as_str()
            ),
            field: None,
            details: Some(json!({
                "max_body_size": max_body_size,
                "reason": reason,
            })),
        }
    }

    pub fn into_response(self) -> Response {
        (
            self.status,
            Json(IntegrityErrorBody {
                error: IntegrityErrorDetail {
                    code: self.code,
                    message: self.message,
                    layer: self.layer.as_str(),
                    field: self.field,
                    details: self.details,
                },
            }),
        )
            .into_response()
    }
}

