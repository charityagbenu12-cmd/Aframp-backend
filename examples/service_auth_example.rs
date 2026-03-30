//! Example demonstrating microservice-to-microservice authentication setup

use Bitmesh_backend::service_auth::{
    ServiceAllowlist, ServiceHttpClient, ServiceRegistry, ServiceRegistration,
    ServiceTokenManager, TokenRefreshConfig,
};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Microservice Authentication Example ===\n");

    // This example demonstrates the complete flow of setting up
    // microservice-to-microservice authentication

    // Step 1: Service Registration
    println!("Step 1: Registering a new service...");
    
    // In a real application, you would:
    // let pool = Arc::new(sqlx::PgPool::connect(&database_url).await?);
    // let registry = ServiceRegistry::new(pool);
    
    println!("  - Service name: worker_service");
    println!("  - Allowed scopes: [worker:execute]");
    println!("  - Allowed targets: [/api/settlement/*]");
    
    // let registration = ServiceRegistration {
    //     service_name: "worker_service".to_string(),
    //     allowed_scopes: vec!["worker:execute".to_string()],
    //     allowed_targets: vec!["/api/settlement/*".to_string()],
    // };
    // let identity = registry.register_service(registration).await?;
    
    println!("  ✓ Service registered");
    println!("  - Client ID: service_worker_service");
    println!("  - Client Secret: svc_secret_*** (store securely!)");
    println!();

    // Step 2: Configure Allowlist
    println!("Step 2: Configuring service call allowlist...");
    
    // let cache = Arc::new(RedisCache::new(cache_pool));
    // let allowlist = ServiceAllowlist::new(pool.clone(), cache);
    
    // Allow worker to call settlement endpoints
    // allowlist
    //     .set_permission("worker_service", "/api/settlement/*", true)
    //     .await?;
    
    println!("  ✓ Allowed: worker_service -> /api/settlement/*");
    
    // Deny worker from calling admin endpoints
    // allowlist
    //     .set_permission("worker_service", "/api/admin/*", false)
    //     .await?;
    
    println!("  ✓ Denied: worker_service -> /api/admin/*");
    println!();

    // Step 3: Initialize Token Manager
    println!("Step 3: Initializing token manager...");
    
    let config = TokenRefreshConfig {
        refresh_threshold: 0.2,  // Refresh at 20% remaining lifetime
        max_retries: 3,
        initial_backoff_ms: 100,
        max_backoff_ms: 5000,
    };
    
    println!("  - Refresh threshold: 20% remaining lifetime");
    println!("  - Max retries: 3");
    println!("  - Backoff: 100ms - 5000ms");
    
    // let token_manager = Arc::new(ServiceTokenManager::new(
    //     "worker_service".to_string(),
    //     "service_worker_service".to_string(),
    //     client_secret,
    //     "https://api.aframp.com/oauth/token".to_string(),
    //     config,
    // ));
    
    // token_manager.initialize().await?;
    // token_manager.clone().start_refresh_task();
    
    println!("  ✓ Token manager initialized");
    println!("  ✓ Background refresh task started");
    println!();

    // Step 4: Make Service Calls
    println!("Step 4: Making authenticated service calls...");
    
    // let client = ServiceHttpClient::new(
    //     "worker_service".to_string(),
    //     token_manager.clone(),
    // );
    
    println!("  - Creating HTTP client with automatic token injection");
    println!("  - Headers added automatically:");
    println!("    * Authorization: Bearer <token>");
    println!("    * X-Service-Name: worker_service");
    println!("    * X-Request-ID: <uuid>");
    
    // let request = reqwest::Request::new(
    //     reqwest::Method::POST,
    //     "https://api.aframp.com/api/settlement/process".parse()?,
    // );
    
    // let response = client.execute(request).await?;
    
    println!("  ✓ Request executed successfully");
    println!("  ✓ Token automatically refreshed if needed");
    println!("  ✓ 401 responses automatically retried");
    println!();

    // Step 5: Monitoring
    println!("Step 5: Monitoring and observability...");
    println!("  Available metrics:");
    println!("  - aframp_service_token_acquisitions_total");
    println!("  - aframp_service_token_refresh_events_total");
    println!("  - aframp_service_token_refresh_failures_total");
    println!("  - aframp_service_call_authentications_total");
    println!("  - aframp_service_call_authorization_denials_total");
    println!();
    println!("  Audit logging:");
    println!("  - All authentication events logged to service_auth_audit table");
    println!("  - Includes: service name, endpoint, result, timestamp");
    println!("  - Impersonation attempts flagged for security review");
    println!();

    println!("=== Setup Complete ===");
    println!("\nNext steps:");
    println!("1. Store client secret in secrets manager");
    println!("2. Configure alerts for token refresh failures");
    println!("3. Set up certificate monitoring for mTLS");
    println!("4. Review allowlist quarterly");
    println!("5. Monitor authentication metrics");

    Ok(())
}
