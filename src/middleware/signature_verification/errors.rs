//! Error types and response helpers for signature verification (Issue #140).

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;

/// All distinct reasons a signature verification can fail.
/// Used internally for logging and metrics — never sent to the consumer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyFailReason {
    MissingSignature,
    MissingKeyId,
    MalformedHeader,
    ExpiredTimestamp,
    UnsupportedAlgorithm,
    AlgorithmTooWeak,
    KeyNotFound,
    SignatureMismatch,
}

impl VerifyFailReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MissingSignature    => "missing_signature",
            Self::MissingKeyId        => "missing_key_id",
            Self::MalformedHeader     => "malformed_header",
            Self::ExpiredTimestamp    => "expired_timestamp",
            Self::UnsupportedAlgorithm => "unsupported_algorithm",
            Self::AlgorithmTooWeak    => "algorithm_too_weak",
            Self::KeyNotFound         => "key_not_found",
            Self::SignatureMismatch   => "signature_mismatch",
        }
    }
}

#[derive(Serialize)]
struct SigError {
    error: SigErrorDetail,
}

#[derive(Serialize)]
struct SigErrorDetail {
    code: &'static str,
    message: &'static str,
}

/// Generic 401 returned to the consumer for every verification failure.
/// No failure detail is leaked — reason is only in internal logs/metrics.
pub fn sig_401() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(SigError {
            error: SigErrorDetail {
                code: "SIGNATURE_VERIFICATION_FAILED",
                message: "Request signature verification failed.",
            },
        }),
    )
        .into_response()
}

/// 401 for weak-algorithm failures on high-value endpoints.
/// Indicates the required algorithm so the consumer can fix their client.
pub fn sig_401_weak_algorithm(required: &'static str) -> Response {
    #[derive(Serialize)]
    struct WeakAlgError {
        error: WeakAlgDetail,
    }
    #[derive(Serialize)]
    struct WeakAlgDetail {
        code: &'static str,
        message: String,
        required_algorithm: &'static str,
    }
    (
        StatusCode::UNAUTHORIZED,
        Json(WeakAlgError {
            error: WeakAlgDetail {
                code: "ALGORITHM_TOO_WEAK",
                message: format!(
                    "This endpoint requires {}. Upgrade your signing algorithm.",
                    required
                ),
                required_algorithm: required,
            },
        }),
    )
        .into_response()
}
