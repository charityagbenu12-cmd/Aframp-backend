use crate::developer_portal::{DeveloperService, ProductionAccessService, repositories::{DeveloperAccountRepository, DeveloperApplicationRepository, ApiKeyRepository, ProductionAccessRequestRepository, WebhookConfigurationRepository}};
use crate::database::PgPool;
use std::sync::Arc;
use axum::{Router, middleware};
use tower::ServiceBuilder;

pub struct DeveloperPortalState {
    pub developer_service: Arc<DeveloperService>,
    pub production_access_service: Arc<ProductionAccessService>,
}

impl DeveloperPortalState {
    pub fn new(pool: Arc<PgPool>) -> Self {
        let developer_account_repo = DeveloperAccountRepository::new(pool.clone());
        let application_repo = DeveloperApplicationRepository::new(pool.clone());
        let api_key_repo = ApiKeyRepository::new(pool.clone());
        let production_access_repo = ProductionAccessRequestRepository::new(pool.clone());
        let webhook_repo = WebhookConfigurationRepository::new(pool.clone());
        
        let developer_service = Arc::new(DeveloperService::new(
            developer_account_repo.clone(),
            application_repo.clone(),
            api_key_repo.clone(),
        ));

        let production_access_service = Arc::new(ProductionAccessService::new(
            developer_account_repo,
            application_repo,
            production_access_repo,
            webhook_repo,
        ));

        Self {
            developer_service,
            production_access_service,
        }
    }
}

pub fn create_developer_portal_routes(state: Arc<DeveloperPortalState>) -> Router {
    let services = (state.developer_service.clone(), state.production_access_service.clone());
    
    Router::new()
        .nest("/api/developer", crate::developer_portal::handlers::developer_portal_routes())
        .nest("/api/admin/developer-portal", crate::developer_portal::admin_handlers::admin_developer_portal_routes())
        .layer(
            ServiceBuilder::new()
                .middleware(middleware::from_fn_with_state(
                    state.developer_service.clone(),
                    crate::developer_portal::middleware::usage_logging_middleware
                ))
        )
        .with_state(services)
}

// Add this to your main router setup
pub fn register_developer_portal_routes(router: Router<Arc<crate::config::AppConfig>>, pool: Arc<PgPool>) -> Router<Arc<crate::config::AppConfig>> {
    let developer_portal_state = Arc::new(DeveloperPortalState::new(pool));
    let developer_routes = create_developer_portal_routes(developer_portal_state);
    
    router.merge(developer_routes)
}
