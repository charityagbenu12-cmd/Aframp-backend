//! Service token verification middleware

use axum::{
    body::Body,
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use chrono::Utc;
use serde_json::json;
use std::sync::Arc;
use tracing::{debug, warn};

use super::allowlist::ServiceAllowlist;
use super::types::{
    AuthResult, AuthenticatedService, ServiceAuthAudit, ServiceAuthError, ServiceTokenClaims,
};
use crate::metrics::service_auth;
use crate::oauth::token::validate_access_token;
use crate::oauth::types::OAuthError;
use sqlx::PgPool;

// ── Service auth state ───────────────────────────────────────────────────────

#[derive(Clone)]
pub struct ServiceAuthState {
    pub pool: Arc<PgPool>,
    pub allowlist: Arc<ServiceAllowlist>,
    pub jwt_secret: String,
}

// ── Middleware ───────────────────────────────────────────────────────────────

pub async fn service_token_verification(
    State(state): State<ServiceAuthState>,
    mut request: Request<Body>,
    next: Next,
) -> Result<Response, Response> {
    let path = request.uri().path().to_string();
    let request_id = request
        .headers()
        .get("X-Request-ID")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // Extract Authorization header
    let auth_header = request
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));

    let token = match auth_header {
        Some(t) => t,
        None => {
            return Err(unauthorized_response(
                "MISSING_SERVICE_TOKEN",
                "Service authentication required",
            ));
        }
    };

    // Extract X-Service-Name header
    let service_name_header = request
        .headers()
        .get("X-Service-Name")
        .and_then(|v| v.to_str().ok());

    let service_name = match service_name_header {
        Some(name) => name,
        None => {
            return Err(unauthorized_response(
                "MISSING_SERVICE_NAME",
                "X-Service-Name header required",
            ));
        }
    };

    // Validate JWT token
    let claims = match validate_service_token(token, &state.jwt_secret) {
        Ok(c) => c,
        Err(e) => {
            warn!(
                service_name = %service_name,
                path = %path,
                error = %e,
                "Service token validation failed"
            );

            log_auth_audit(
                &state.pool,
                service_name,
                &path,
                None,
                AuthResult::Unauthorized,
                Some(e.to_string()),
                request_id.as_deref(),
            )
            .await;

            service_auth::service_call_authentications()
                .with_label_values(&[service_name, &path, "unauthorized"])
                .inc();

            return Err(unauthorized_response("INVALID_SERVICE_TOKEN", &e.to_string()));
        }
    };

    // Verify microservice:internal scope
    if !claims.scope.contains("microservice:internal") {
        warn!(
            service_name = %service_name,
            path = %path,
            scope = %claims.scope,
            "Service token missing required scope"
        );

        log_auth_audit(
            &state.pool,
            service_name,
            &path,
            Some(&claims.jti),
            AuthResult::Unauthorized,
            Some("Missing microservice:internal scope".to_string()),
            request_id.as_deref(),
        )
        .await;

        return Err(unauthorized_response(
            "INSUFFICIENT_SCOPE",
            "Token missing microservice:internal scope",
        ));
    }

    // Verify service name matches token subject
    if claims.sub != service_name {
        warn!(
            claimed_service = %service_name,
            token_subject = %claims.sub,
            path = %path,
            "Service impersonation attempt detected"
        );

        log_auth_audit(
            &state.pool,
            service_name,
            &path,
            Some(&claims.jti),
            AuthResult::ImpersonationAttempt,
            Some(format!(
                "Service name mismatch: claimed={}, token={}",
                service_name, claims.sub
            )),
            request_id.as_deref(),
        )
        .await;

        service_auth::service_call_authorization_denials()
            .with_label_values(&[service_name, &path, "impersonation"])
            .inc();

        return Err(forbidden_response(
            "SERVICE_IMPERSONATION",
            "Service name does not match token subject",
        ));
    }

    // Check service call allowlist
    match state.allowlist.is_allowed(service_name, &path).await {
        Ok(true) => {
            // Allowed
        }
        Ok(false) => {
            warn!(
                service_name = %service_name,
                path = %path,
                "Service not authorized to call endpoint"
            );

            log_auth_audit(
                &state.pool,
                service_name,
                &path,
                Some(&claims.jti),
                AuthResult::Forbidden,
                Some("Service not in allowlist for endpoint".to_string()),
                request_id.as_deref(),
            )
            .await;

            service_auth::service_call_authorization_denials()
                .with_label_values(&[service_name, &path, "not_allowed"])
                .inc();

            return Err(forbidden_response(
                "SERVICE_NOT_AUTHORIZED",
                &format!(
                    "Service '{}' is not authorized to call endpoint '{}'",
                    service_name, path
                ),
            ));
        }
        Err(e) => {
            warn!(
                service_name = %service_name,
                path = %path,
                error = %e,
                "Allowlist check failed"
            );

            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": {
                        "code": "ALLOWLIST_CHECK_FAILED",
                        "message": "Failed to verify service authorization"
                    }
                })),
            )
                .into_response());
        }
    }

    // Log successful authentication
    log_auth_audit(
        &state.pool,
        service_name,
        &path,
        Some(&claims.jti),
        AuthResult::Success,
        None,
        request_id.as_deref(),
    )
    .await;

    service_auth::service_call_authentications()
        .with_label_values(&[service_name, &path, "success"])
        .inc();

    debug!(
        service_name = %service_name,
        path = %path,
        jti = %claims.jti,
        "Service authentication successful"
    );

    // Inject authenticated service into request extensions
    let authenticated = AuthenticatedService {
        service_name: service_name.to_string(),
        client_id: claims.client_id.clone(),
        scopes: claims.scope.split_whitespace().map(String::from).collect(),
        token_jti: claims.jti.clone(),
    };

    request.extensions_mut().insert(authenticated);

    Ok(next.run(request).await)
}

// ── Helper functions ─────────────────────────────────────────────────────────

fn validate_service_token(
    token: &str,
    jwt_secret: &str,
) -> Result<ServiceTokenClaims, ServiceAuthError> {
    // Decode and validate JWT
    use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};

    let mut validation = Validation::new(Algorithm::RS256);
    validation.validate_exp = true;
    validation.set_required_spec_claims(&["exp", "iat", "sub", "jti"]);

    let decoding_key = DecodingKey::from_secret(jwt_secret.as_bytes());

    let token_data = decode::<ServiceTokenClaims>(token, &decoding_key, &validation)
        .map_err(|e| ServiceAuthError::InvalidCredentials)?;

    // Check expiry
    let now = Utc::now().timestamp();
    if token_data.claims.exp < now {
        return Err(ServiceAuthError::TokenExpired);
    }

    Ok(token_data.claims)
}

async fn log_auth_audit(
    pool: &PgPool,
    calling_service: &str,
    target_endpoint: &str,
    token_jti: Option<&str>,
    auth_result: AuthResult,
    failure_reason: Option<String>,
    request_id: Option<&str>,
) {
    let result = sqlx::query!(
        r#"
        INSERT INTO service_auth_audit (
            calling_service, target_endpoint, token_jti,
            auth_result, failure_reason, request_id
        )
        VALUES ($1, $2, $3, $4, $5, $6)
        "#,
        calling_service,
        target_endpoint,
        token_jti,
        auth_result.to_string(),
        failure_reason,
        request_id,
    )
    .execute(pool)
    .await;

    if let Err(e) = result {
        warn!(
            calling_service = %calling_service,
            error = %e,
            "Failed to log service auth audit"
        );
    }
}

fn unauthorized_response(code: &str, message: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({
            "error": {
                "code": code,
                "message": message
            }
        })),
    )
        .into_response()
}

fn forbidden_response(code: &str, message: &str) -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(json!({
            "error": {
                "code": code,
                "message": message
            }
        })),
    )
        .into_response()
}
