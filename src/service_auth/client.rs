//! HTTP client with automatic service token injection

use reqwest::{Client, Request, Response};
use std::sync::Arc;
use tracing::{debug, warn};
use uuid::Uuid;

use super::token_manager::ServiceTokenManager;
use super::types::{ServiceAuthError, ServiceAuthResult};

// ── Service HTTP client ──────────────────────────────────────────────────────

pub struct ServiceHttpClient {
    service_name: String,
    token_manager: Arc<ServiceTokenManager>,
    http_client: Client,
}

impl ServiceHttpClient {
    pub fn new(service_name: String, token_manager: Arc<ServiceTokenManager>) -> Self {
        Self {
            service_name,
            token_manager,
            http_client: Client::new(),
        }
    }

    /// Execute a request with automatic token injection and retry on 401
    pub async fn execute(&self, mut request: Request) -> ServiceAuthResult<Response> {
        // Generate request ID for tracing
        let request_id = Uuid::new_v4().to_string();

        // Inject service token and headers
        self.inject_auth_headers(&mut request, &request_id).await?;

        debug!(
            service_name = %self.service_name,
            method = %request.method(),
            url = %request.url(),
            request_id = %request_id,
            "Executing service request"
        );

        // Execute request
        let response = self
            .http_client
            .execute(request.try_clone().expect("Request should be cloneable"))
            .await
            .map_err(|e| ServiceAuthError::Internal(format!("HTTP error: {}", e)))?;

        // Handle 401 with token refresh and retry
        if response.status() == 401 {
            warn!(
                service_name = %self.service_name,
                request_id = %request_id,
                "Received 401, refreshing token and retrying"
            );

            // Force token refresh
            self.token_manager.acquire_token().await?;

            // Retry with new token
            self.inject_auth_headers(&mut request, &request_id).await?;

            let retry_response = self
                .http_client
                .execute(request)
                .await
                .map_err(|e| ServiceAuthError::Internal(format!("HTTP error on retry: {}", e)))?;

            return Ok(retry_response);
        }

        Ok(response)
    }

    async fn inject_auth_headers(
        &self,
        request: &mut Request,
        request_id: &str,
    ) -> ServiceAuthResult<()> {
        let token = self.token_manager.get_token().await?;

        let headers = request.headers_mut();

        // Authorization header
        headers.insert(
            "Authorization",
            format!("Bearer {}", token)
                .parse()
                .map_err(|e| ServiceAuthError::Internal(format!("Invalid header value: {}", e)))?,
        );

        // Service identity header
        headers.insert(
            "X-Service-Name",
            self.service_name
                .parse()
                .map_err(|e| ServiceAuthError::Internal(format!("Invalid header value: {}", e)))?,
        );

        // Request ID for distributed tracing
        headers.insert(
            "X-Request-ID",
            request_id
                .parse()
                .map_err(|e| ServiceAuthError::Internal(format!("Invalid header value: {}", e)))?,
        );

        Ok(())
    }

    /// Get the underlying HTTP client for custom requests
    pub fn client(&self) -> &Client {
        &self.http_client
    }
}
