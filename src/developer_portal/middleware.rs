use axum::{
    body::Body,
    extract::{Request, State},
    http::{header::AUTHORIZATION, StatusCode},
    middleware::Next,
    response::Response,
};
use std::sync::Arc;
use tower::ServiceExt;
use tracing::{error, info};

use super::models::DeveloperPortalError;
use super::services::DeveloperService;
use crate::auth::jwt::Claims;

#[derive(Debug, Clone)]
pub struct AuthenticatedDeveloper {
    pub developer_account_id: uuid::Uuid,
    pub email: String,
}

pub async fn developer_auth_middleware(
    State(service): State<Arc<DeveloperService>>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Extract Authorization header
    let auth_header = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|header| header.to_str().ok())
        .and_then(|header| {
            if header.starts_with("Bearer ") {
                Some(&header[7..])
            } else {
                None
            }
        });

    let token = match auth_header {
        Some(token) => token,
        None => {
            error!("Missing or invalid Authorization header");
            return Err(StatusCode::UNAUTHORIZED);
        }
    };

    // Validate JWT token
    let claims = match crate::auth::jwt::validate_token(token) {
        Ok(claims) => claims,
        Err(e) => {
            error!("Invalid JWT token: {}", e);
            return Err(StatusCode::UNAUTHORIZED);
        }
    };

    // Verify it's a developer token
    if claims.token_type != "developer" {
        error!("Token is not a developer token");
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Get developer account
    let developer_account = match service.get_developer_account(claims.sub).await {
        Ok(account) => account,
        Err(e) => {
            error!("Developer account not found: {}", e);
            return Err(StatusCode::UNAUTHORIZED);
        }
    };

    // Check if account is active
    if developer_account.status_code == "suspended" {
        error!("Developer account is suspended: {}", developer_account.email);
        return Err(StatusCode::FORBIDDEN);
    }

    // Check if email is verified for non-public endpoints
    let path = request.uri().path();
    if !path.ends_with("/register") && !path.contains("/verify-email") {
        if !developer_account.email_verified {
            error!("Developer email not verified: {}", developer_account.email);
            return Err(StatusCode::FORBIDDEN);
        }
    }

    // Add developer info to request extensions
    let auth_info = AuthenticatedDeveloper {
        developer_account_id: developer_account.id,
        email: developer_account.email,
    };
    request.extensions_mut().insert(auth_info);

    info!(
        "Developer authenticated: {} for {}",
        developer_account.email, path
    );

    Ok(next.run(request).await)
}

pub async fn api_key_auth_middleware(
    State(service): State<Arc<DeveloperService>>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Extract API key from Authorization header
    let auth_header = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|header| header.to_str().ok())
        .and_then(|header| {
            if header.starts_with("Bearer ") {
                Some(&header[7..])
            } else {
                None
            }
        });

    let api_key = match auth_header {
        Some(key) => key,
        None => {
            error!("Missing or invalid Authorization header for API key auth");
            return Err(StatusCode::UNAUTHORIZED);
        }
    };

    // Check if it's an API key (starts with "ak_")
    if !api_key.starts_with("ak_") {
        error!("Invalid API key format");
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Validate API key
    let key_info = match service.validate_api_key(api_key).await {
        Ok(Some(key)) => key,
        Ok(None) => {
            error!("API key not found or inactive");
            return Err(StatusCode::UNAUTHORIZED);
        }
        Err(e) => {
            error!("Error validating API key: {}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    // Check if key has expired
    if let Some(expires_at) = key_info.expires_at {
        if expires_at < chrono::Utc::now() {
            error!("API key has expired");
            return Err(StatusCode::UNAUTHORIZED);
        }
    }

    // Get application to verify ownership
    let application = match service.get_application(key_info.application_id).await {
        Ok(app) => app,
        Err(e) => {
            error!("Application not found for API key: {}", e);
            return Err(StatusCode::UNAUTHORIZED);
        }
    };

    // Get developer account
    let developer_account = match service.get_developer_account(application.developer_account_id).await {
        Ok(account) => account,
        Err(e) => {
            error!("Developer account not found: {}", e);
            return Err(StatusCode::UNAUTHORIZED);
        }
    }

    // Check if account is active
    if developer_account.status_code == "suspended" {
        error!("Developer account is suspended: {}", developer_account.email);
        return Err(StatusCode::FORBIDDEN);
    }

    // Update API key usage
    if let Err(e) = service.update_api_key_usage(key_info.id).await {
        error!("Failed to update API key usage: {}", e);
        // Don't fail the request, just log the error
    }

    // Add auth info to request extensions
    let auth_info = AuthenticatedDeveloper {
        developer_account_id: developer_account.id,
        email: developer_account.email,
    };
    request.extensions_mut().insert(auth_info);

    // Add API key info to request extensions for rate limiting
    request.extensions_mut().insert(key_info);

    info!(
        "API key authenticated: {} for {}",
        api_key, request.uri().path()
    );

    Ok(next.run(request).await)
}

// Rate limiting middleware for API keys
pub async fn rate_limit_middleware(
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Get API key info from request extensions
    let api_key = request.extensions().get::<super::models::ApiKey>();
    
    if let Some(key) = api_key {
        // TODO: Implement rate limiting logic using Redis or in-memory counter
        // For now, just pass through
        info!(
            "Rate limit check for API key: {} (limit: {} req/min)",
            key.key_name, key.rate_limit_per_minute
        );
    }

    Ok(next.run(request).await)
}

// Middleware to log API usage for statistics
pub async fn usage_logging_middleware(
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let start_time = std::time::Instant::now();
    let method = request.method().clone();
    let uri = request.uri().clone();
    let path = uri.path().to_string();

    let response = next.run(request).await;

    let duration = start_time.elapsed();
    let status = response.status();

    // Get developer and application info from extensions
    let auth_info = response.extensions().get::<AuthenticatedDeveloper>();
    let api_key = response.extensions().get::<super::models::ApiKey>();

    if let (Some(dev), Some(key)) = (auth_info, api_key) {
        // TODO: Log usage statistics to database
        info!(
            "API usage: {} {} {} - {}ms - Developer: {} - Key: {}",
            method, path, status.as_u16(),
            duration.as_millis(),
            dev.email,
            key.key_name
        );
    }

    Ok(response)
}
