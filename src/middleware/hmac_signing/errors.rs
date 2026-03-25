//! HMAC signing error response helpers.

use axum::{http::StatusCode, response::{IntoResponse, Response}, Json};
use serde::Serialize;

#[derive(Serialize)]
struct SigningError {
    error: SigningErrorDetail,
}

#[derive(Serialize)]
struct SigningErrorDetail {
    code: String,
    message: String,
}

pub fn signing_401(code: &str, message: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(SigningError {
            error: SigningErrorDetail {
                code: code.to_string(),
                message: message.to_string(),
            },
        }),
    )
        .into_response()
}
