use super::models::*;
use crate::database::error::DatabaseError;
use crate::database::repository::Repository;
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

#[derive(Clone)]
pub struct DeveloperAccountRepository {
    pool: Arc<PgPool>,
}

impl DeveloperAccountRepository {
    pub fn new(pool: Arc<PgPool>) -> Self {
        Self { pool }
    }

    pub async fn create(
        &self,
        request: CreateDeveloperAccountRequest,
        email_verification_token: Option<String>,
        email_verification_expires_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<DeveloperAccount, DeveloperPortalError> {
        let account = sqlx::query_as!(
            DeveloperAccount,
            r#"
            INSERT INTO developer_accounts (
                email, full_name, organisation, country, use_case_description,
                status_code, access_tier_code, email_verified,
                email_verification_token, email_verification_expires_at
            ) VALUES ($1, $2, $3, $4, $5, 'unverified', 'sandbox', false, $6, $7)
            RETURNING *
            "#,
            request.email,
            request.full_name,
            request.organisation,
            request.country,
            request.use_case_description,
            email_verification_token,
            email_verification_expires_at
        )
        .fetch_one(self.pool.as_ref())
        .await?;

        Ok(account)
    }

    pub async fn find_by_email(&self, email: &str) -> Result<Option<DeveloperAccount>, DeveloperPortalError> {
        let account = sqlx::query_as!(
            DeveloperAccount,
            "SELECT * FROM developer_accounts WHERE email = $1",
            email
        )
        .fetch_optional(self.pool.as_ref())
        .await?;

        Ok(account)
    }

    pub async fn find_by_id(&self, id: Uuid) -> Result<Option<DeveloperAccount>, DeveloperPortalError> {
        let account = sqlx::query_as!(
            DeveloperAccount,
            "SELECT * FROM developer_accounts WHERE id = $1",
            id
        )
        .fetch_optional(self.pool.as_ref())
        .await?;

        Ok(account)
    }

    pub async fn find_by_verification_token(
        &self,
        token: &str,
    ) -> Result<Option<DeveloperAccount>, DeveloperPortalError> {
        let account = sqlx::query_as!(
            DeveloperAccount,
            "SELECT * FROM developer_accounts WHERE email_verification_token = $1",
            token
        )
        .fetch_optional(self.pool.as_ref())
        .await?;

        Ok(account)
    }

    pub async fn verify_email(&self, account_id: Uuid) -> Result<DeveloperAccount, DeveloperPortalError> {
        let account = sqlx::query_as!(
            DeveloperAccount,
            r#"
            UPDATE developer_accounts 
            SET email_verified = true,
                email_verification_token = NULL,
                email_verification_expires_at = NULL,
                status_code = 'verified',
                updated_at = now()
            WHERE id = $1
            RETURNING *
            "#,
            account_id
        )
        .fetch_one(self.pool.as_ref())
        .await?;

        Ok(account)
    }

    pub async fn update_identity_verification(
        &self,
        account_id: Uuid,
        verification_data: IdentityVerificationRequest,
    ) -> Result<DeveloperAccount, DeveloperPortalError> {
        let identity_data = serde_json::to_value(verification_data)?;
        
        let account = sqlx::query_as!(
            DeveloperAccount,
            r#"
            UPDATE developer_accounts 
            SET identity_verification_status = 'pending',
                identity_verification_data = $1,
                updated_at = now()
            WHERE id = $2
            RETURNING *
            "#,
            identity_data,
            account_id
        )
        .fetch_one(self.pool.as_ref())
        .await?;

        Ok(account)
    }

    pub async fn approve_identity_verification(
        &self,
        account_id: Uuid,
    ) -> Result<DeveloperAccount, DeveloperPortalError> {
        let account = sqlx::query_as!(
            DeveloperAccount,
            r#"
            UPDATE developer_accounts 
            SET identity_verification_status = 'verified',
                identity_verified_at = now(),
                updated_at = now()
            WHERE id = $1
            RETURNING *
            "#,
            account_id
        )
        .fetch_one(self.pool.as_ref())
        .await?;

        Ok(account)
    }

    pub async fn reject_identity_verification(
        &self,
        account_id: Uuid,
    ) -> Result<DeveloperAccount, DeveloperPortalError> {
        let account = sqlx::query_as!(
            DeveloperAccount,
            r#"
            UPDATE developer_accounts 
            SET identity_verification_status = 'rejected',
                updated_at = now()
            WHERE id = $1
            RETURNING *
            "#,
            account_id
        )
        .fetch_one(self.pool.as_ref())
        .await?;

        Ok(account)
    }

    pub async fn upgrade_to_standard_tier(&self, account_id: Uuid) -> Result<DeveloperAccount, DeveloperPortalError> {
        let account = sqlx::query_as!(
            DeveloperAccount,
            r#"
            UPDATE developer_accounts 
            SET access_tier_code = 'standard',
                status_code = 'active',
                updated_at = now()
            WHERE id = $1
            RETURNING *
            "#,
            account_id
        )
        .fetch_one(self.pool.as_ref())
        .await?;

        Ok(account)
    }

    pub async fn upgrade_to_partner_tier(&self, account_id: Uuid) -> Result<DeveloperAccount, DeveloperPortalError> {
        let account = sqlx::query_as!(
            DeveloperAccount,
            r#"
            UPDATE developer_accounts 
            SET access_tier_code = 'partner',
                status_code = 'active',
                updated_at = now()
            WHERE id = $1
            RETURNING *
            "#,
            account_id
        )
        .fetch_one(self.pool.as_ref())
        .await?;

        Ok(account)
    }

    pub async fn suspend(&self, account_id: Uuid, reason: &str) -> Result<DeveloperAccount, DeveloperPortalError> {
        let account = sqlx::query_as!(
            DeveloperAccount,
            r#"
            UPDATE developer_accounts 
            SET status_code = 'suspended',
                suspended_at = now(),
                suspension_reason = $1,
                updated_at = now()
            WHERE id = $2
            RETURNING *
            "#,
            reason,
            account_id
        )
        .fetch_one(self.pool.as_ref())
        .await?;

        Ok(account)
    }

    pub async fn reinstate(&self, account_id: Uuid) -> Result<DeveloperAccount, DeveloperPortalError> {
        let account = sqlx::query_as!(
            DeveloperAccount,
            r#"
            UPDATE developer_accounts 
            SET status_code = 'active',
                suspended_at = NULL,
                suspension_reason = NULL,
                updated_at = now()
            WHERE id = $1
            RETURNING *
            "#,
            account_id
        )
        .fetch_one(self.pool.as_ref())
        .await?;

        Ok(account)
    }

    pub async fn update(
        &self,
        account_id: Uuid,
        request: UpdateDeveloperAccountRequest,
    ) -> Result<DeveloperAccount, DeveloperPortalError> {
        let account = sqlx::query_as!(
            DeveloperAccount,
            r#"
            UPDATE developer_accounts 
            SET full_name = COALESCE($1, full_name),
                organisation = COALESCE($2, organisation),
                country = COALESCE($3, country),
                use_case_description = COALESCE($4, use_case_description),
                updated_at = now()
            WHERE id = $5
            RETURNING *
            "#,
            request.full_name,
            request.organisation,
            request.country,
            request.use_case_description,
            account_id
        )
        .fetch_one(self.pool.as_ref())
        .await?;

        Ok(account)
    }

    pub async fn get_application_count(&self, account_id: Uuid) -> Result<i64, DeveloperPortalError> {
        let count = sqlx::query_scalar!(
            "SELECT COUNT(*) FROM developer_applications WHERE developer_account_id = $1 AND status != 'deleted'",
            account_id
        )
        .fetch_one(self.pool.as_ref())
        .await?;

        Ok(count.unwrap_or(0))
    }

    pub async fn list_for_admin(
        &self,
        page: i64,
        per_page: i64,
    ) -> Result<AdminDeveloperAccountList, DeveloperPortalError> {
        let offset = (page - 1) * per_page;

        let accounts = sqlx::query_as!(
            AdminDeveloperAccountSummary,
            r#"
            SELECT 
                da.id,
                da.email,
                da.full_name,
                da.organisation,
                da.country,
                da.status_code,
                da.access_tier_code,
                da.email_verified,
                da.identity_verification_status,
                COALESCE(app_count.count, 0) as "application_count!",
                da.created_at,
                da.updated_at as "last_activity?"
            FROM developer_accounts da
            LEFT JOIN (
                SELECT developer_account_id, COUNT(*) as count
                FROM developer_applications
                WHERE status != 'deleted'
                GROUP BY developer_account_id
            ) app_count ON da.id = app_count.developer_account_id
            ORDER BY da.created_at DESC
            LIMIT $1 OFFSET $2
            "#,
            per_page,
            offset
        )
        .fetch_all(self.pool.as_ref())
        .await?;

        let total_count = sqlx::query_scalar!(
            "SELECT COUNT(*) FROM developer_accounts"
        )
        .fetch_one(self.pool.as_ref())
        .await?;

        let total_count = total_count.unwrap_or(0);
        let total_pages = (total_count + per_page - 1) / per_page;

        Ok(AdminDeveloperAccountList {
            accounts,
            total_count,
            page,
            per_page,
            total_pages,
        })
    }

    pub async fn get_access_tier(&self, tier_code: &str) -> Result<Option<AccessTier>, DeveloperPortalError> {
        let tier = sqlx::query_as!(
            AccessTier,
            "SELECT * FROM access_tiers WHERE code = $1",
            tier_code
        )
        .fetch_optional(self.pool.as_ref())
        .await?;

        Ok(tier)
    }
}

#[derive(Clone)]
pub struct DeveloperApplicationRepository {
    pool: Arc<PgPool>,
}

impl DeveloperApplicationRepository {
    pub fn new(pool: Arc<PgPool>) -> Self {
        Self { pool }
    }

    pub async fn create(
        &self,
        developer_account_id: Uuid,
        request: CreateApplicationRequest,
    ) -> Result<DeveloperApplication, DeveloperPortalError> {
        let application = sqlx::query_as!(
            DeveloperApplication,
            r#"
            INSERT INTO developer_applications (
                developer_account_id, name, description, intended_use_case
            ) VALUES ($1, $2, $3, $4)
            RETURNING *
            "#,
            developer_account_id,
            request.name,
            request.description,
            request.intended_use_case
        )
        .fetch_one(self.pool.as_ref())
        .await?;

        Ok(application)
    }

    pub async fn find_by_id(&self, id: Uuid) -> Result<Option<DeveloperApplication>, DeveloperPortalError> {
        let application = sqlx::query_as!(
            DeveloperApplication,
            "SELECT * FROM developer_applications WHERE id = $1",
            id
        )
        .fetch_optional(self.pool.as_ref())
        .await?;

        Ok(application)
    }

    pub async fn find_by_developer_account(
        &self,
        developer_account_id: Uuid,
    ) -> Result<Vec<DeveloperApplication>, DeveloperPortalError> {
        let applications = sqlx::query_as!(
            DeveloperApplication,
            "SELECT * FROM developer_applications WHERE developer_account_id = $1 AND status != 'deleted' ORDER BY created_at DESC",
            developer_account_id
        )
        .fetch_all(self.pool.as_ref())
        .await?;

        Ok(applications)
    }

    pub async fn update(
        &self,
        application_id: Uuid,
        request: UpdateApplicationRequest,
    ) -> Result<DeveloperApplication, DeveloperPortalError> {
        let application = sqlx::query_as!(
            DeveloperApplication,
            r#"
            UPDATE developer_applications 
            SET name = COALESCE($1, name),
                description = COALESCE($2, description),
                intended_use_case = COALESCE($3, intended_use_case),
                updated_at = now()
            WHERE id = $4
            RETURNING *
            "#,
            request.name,
            request.description,
            request.intended_use_case,
            application_id
        )
        .fetch_one(self.pool.as_ref())
        .await?;

        Ok(application)
    }

    pub async fn soft_delete(&self, application_id: Uuid) -> Result<DeveloperApplication, DeveloperPortalError> {
        let application = sqlx::query_as!(
            DeveloperApplication,
            r#"
            UPDATE developer_applications 
            SET status = 'deleted',
                updated_at = now()
            WHERE id = $1
            RETURNING *
            "#,
            application_id
        )
        .fetch_one(self.pool.as_ref())
        .await?;

        Ok(application)
    }

    pub async fn update_sandbox_wallet(
        &self,
        application_id: Uuid,
        wallet_address: &str,
        wallet_secret: &str,
    ) -> Result<DeveloperApplication, DeveloperPortalError> {
        let application = sqlx::query_as!(
            DeveloperApplication,
            r#"
            UPDATE developer_applications 
            SET sandbox_wallet_address = $1,
                sandbox_wallet_secret = $2,
                updated_at = now()
            WHERE id = $3
            RETURNING *
            "#,
            wallet_address,
            wallet_secret,
            application_id
        )
        .fetch_one(self.pool.as_ref())
        .await?;

        Ok(application)
    }

    pub async fn clear_sandbox_wallet(&self, application_id: Uuid) -> Result<DeveloperApplication, DeveloperPortalError> {
        let application = sqlx::query_as!(
            DeveloperApplication,
            r#"
            UPDATE developer_applications 
            SET sandbox_wallet_address = NULL,
                sandbox_wallet_secret = NULL,
                updated_at = now()
            WHERE id = $1
            RETURNING *
            "#,
            application_id
        )
        .fetch_one(self.pool.as_ref())
        .await?;

        Ok(application)
    }
}

#[derive(Clone)]
pub struct ApiKeyRepository {
    pool: Arc<PgPool>,
}

impl ApiKeyRepository {
    pub fn new(pool: Arc<PgPool>) -> Self {
        Self { pool }
    }

    pub async fn create(
        &self,
        application_id: Uuid,
        request: CreateApiKeyRequest,
        key_prefix: &str,
        key_hash: &str,
    ) -> Result<ApiKey, DeveloperPortalError> {
        let api_key = sqlx::query_as!(
            ApiKey,
            r#"
            INSERT INTO api_keys (
                application_id, key_prefix, key_hash, key_name, environment,
                expires_at, rate_limit_per_minute
            ) VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING *
            "#,
            application_id,
            key_prefix,
            key_hash,
            request.key_name,
            request.environment,
            request.expires_at,
            request.rate_limit_per_minute.unwrap_or(100)
        )
        .fetch_one(self.pool.as_ref())
        .await?;

        Ok(api_key)
    }

    pub async fn find_by_id(&self, id: Uuid) -> Result<Option<ApiKey>, DeveloperPortalError> {
        let api_key = sqlx::query_as!(
            ApiKey,
            "SELECT * FROM api_keys WHERE id = $1",
            id
        )
        .fetch_optional(self.pool.as_ref())
        .await?;

        Ok(api_key)
    }

    pub async fn find_by_key_hash(&self, key_hash: &str) -> Result<Option<ApiKey>, DeveloperPortalError> {
        let api_key = sqlx::query_as!(
            ApiKey,
            "SELECT * FROM api_keys WHERE key_hash = $1 AND status = 'active'",
            key_hash
        )
        .fetch_optional(self.pool.as_ref())
        .await?;

        Ok(api_key)
    }

    pub async fn find_by_application(&self, application_id: Uuid) -> Result<Vec<ApiKey>, DeveloperPortalError> {
        let api_keys = sqlx::query_as!(
            ApiKey,
            "SELECT * FROM api_keys WHERE application_id = $1 ORDER BY created_at DESC",
            application_id
        )
        .fetch_all(self.pool.as_ref())
        .await?;

        Ok(api_keys)
    }

    pub async fn revoke(&self, api_key_id: Uuid) -> Result<ApiKey, DeveloperPortalError> {
        let api_key = sqlx::query_as!(
            ApiKey,
            r#"
            UPDATE api_keys 
            SET status = 'revoked',
                updated_at = now()
            WHERE id = $1
            RETURNING *
            "#,
            api_key_id
        )
        .fetch_one(self.pool.as_ref())
        .await?;

        Ok(api_key)
    }

    pub async fn update_usage(&self, api_key_id: Uuid) -> Result<(), DeveloperPortalError> {
        sqlx::query!(
            r#"
            UPDATE api_keys 
            SET usage_count = usage_count + 1,
                last_used_at = now(),
                updated_at = now()
            WHERE id = $1
            "#,
            api_key_id
        )
        .execute(self.pool.as_ref())
        .await?;

        Ok(())
    }

    pub async fn revoke_by_application(&self, application_id: Uuid, environment: &str) -> Result<(), DeveloperPortalError> {
        sqlx::query!(
            r#"
            UPDATE api_keys 
            SET status = 'revoked',
                updated_at = now()
            WHERE application_id = $1 AND environment = $2
            "#,
            application_id,
            environment
        )
        .execute(self.pool.as_ref())
        .await?;

        Ok(())
    }
}

/// Repository for OAuth client CRUD operations.
#[derive(Clone)]
pub struct OAuthClientRepository {
    pool: Arc<PgPool>,
}

impl OAuthClientRepository {
    pub fn new(pool: Arc<PgPool>) -> Self {
        Self { pool }
    }

    pub async fn create(
        &self,
        application_id: Uuid,
        client_id: &str,
        client_secret_hash: &str,
        request: CreateOAuthClientRequest,
    ) -> Result<OAuthClient, DeveloperPortalError> {
        let client = sqlx::query_as!(
            OAuthClient,
            r#"
            INSERT INTO oauth_clients (
                application_id, client_id, client_secret_hash, client_name,
                environment, redirect_uris, scopes
            ) VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING *
            "#,
            application_id,
            client_id,
            client_secret_hash,
            request.client_name,
            request.environment,
            &request.redirect_uris,
            &request.scopes
        )
        .fetch_one(self.pool.as_ref())
        .await?;

        Ok(client)
    }

    pub async fn find_by_application_and_environment(
        &self,
        application_id: Uuid,
        environment: &str,
    ) -> Result<Vec<OAuthClient>, DeveloperPortalError> {
        let clients = sqlx::query_as!(
            OAuthClient,
            "SELECT * FROM oauth_clients WHERE application_id = $1 AND environment = $2 AND status = 'active' ORDER BY created_at DESC",
            application_id,
            environment
        )
        .fetch_all(self.pool.as_ref())
        .await?;

        Ok(clients)
    }

    pub async fn revoke_by_application_and_environment(
        &self,
        application_id: Uuid,
        environment: &str,
    ) -> Result<(), DeveloperPortalError> {
        sqlx::query!(
            r#"
            UPDATE oauth_clients
            SET status = 'revoked', updated_at = now()
            WHERE application_id = $1 AND environment = $2
            "#,
            application_id,
            environment
        )
        .execute(self.pool.as_ref())
        .await?;

        Ok(())
    }

    pub async fn rotate_secret(
        &self,
        client_id_str: &str,
        new_secret_hash: &str,
    ) -> Result<OAuthClient, DeveloperPortalError> {
        let client = sqlx::query_as!(
            OAuthClient,
            r#"
            UPDATE oauth_clients
            SET client_secret_hash = $1, updated_at = now()
            WHERE client_id = $2
            RETURNING *
            "#,
            new_secret_hash,
            client_id_str
        )
        .fetch_one(self.pool.as_ref())
        .await?;

        Ok(client)
    }

    pub async fn update_redirect_uris(
        &self,
        client_id_str: &str,
        redirect_uris: &[String],
    ) -> Result<OAuthClient, DeveloperPortalError> {
        let client = sqlx::query_as!(
            OAuthClient,
            r#"
            UPDATE oauth_clients
            SET redirect_uris = $1, updated_at = now()
            WHERE client_id = $2
            RETURNING *
            "#,
            redirect_uris,
            client_id_str
        )
        .fetch_one(self.pool.as_ref())
        .await?;

        Ok(client)
    }
}

/// Extension methods on DeveloperApplicationRepository for usage analytics queries.
impl DeveloperApplicationRepository {
    pub async fn get_usage_metrics(
        &self,
        application_id: Uuid,
        start: chrono::DateTime<chrono::Utc>,
        end: chrono::DateTime<chrono::Utc>,
        environment: Option<&str>,
    ) -> Result<super::models::UsageMetrics, DeveloperPortalError> {
        struct Row {
            total_requests: Option<i64>,
            successful_requests: Option<i64>,
            failed_requests: Option<i64>,
            avg_response_time: Option<f64>,
        }

        let row = if let Some(env) = environment {
            sqlx::query!(
                r#"
                SELECT
                    COUNT(*) as total_requests,
                    COUNT(CASE WHEN status_code < 400 THEN 1 END) as successful_requests,
                    COUNT(CASE WHEN status_code >= 400 THEN 1 END) as failed_requests,
                    AVG(response_time_ms::float8) as avg_response_time
                FROM usage_statistics
                WHERE application_id = $1
                  AND timestamp BETWEEN $2 AND $3
                  AND environment = $4
                "#,
                application_id,
                start,
                end,
                env
            )
            .fetch_one(self.pool.as_ref())
            .await
            .map(|r| (r.total_requests, r.successful_requests, r.failed_requests, r.avg_response_time))?
        } else {
            sqlx::query!(
                r#"
                SELECT
                    COUNT(*) as total_requests,
                    COUNT(CASE WHEN status_code < 400 THEN 1 END) as successful_requests,
                    COUNT(CASE WHEN status_code >= 400 THEN 1 END) as failed_requests,
                    AVG(response_time_ms::float8) as avg_response_time
                FROM usage_statistics
                WHERE application_id = $1
                  AND timestamp BETWEEN $2 AND $3
                "#,
                application_id,
                start,
                end
            )
            .fetch_one(self.pool.as_ref())
            .await
            .map(|r| (r.total_requests, r.successful_requests, r.failed_requests, r.avg_response_time))?
        };

        let total = row.0.unwrap_or(0);
        let success = row.1.unwrap_or(0);
        let failed = row.2.unwrap_or(0);
        let avg_rt = row.3.unwrap_or(0.0);
        let error_rate = if total > 0 { (failed as f64 / total as f64) * 100.0 } else { 0.0 };
        // rate_limit_utilization is approximate — left as 0 without a Redis counter
        let rate_limit_utilization = 0.0;
        // requests_per_minute over the window
        let window_minutes = (end - start).num_minutes().max(1);
        let rpm = total / window_minutes;

        Ok(super::models::UsageMetrics {
            total_requests: total,
            successful_requests: success,
            failed_requests: failed,
            average_response_time: avg_rt,
            requests_per_minute: rpm,
            rate_limit_utilization,
            error_rate,
        })
    }

    pub async fn get_endpoint_breakdown(
        &self,
        application_id: Uuid,
        start: chrono::DateTime<chrono::Utc>,
        end: chrono::DateTime<chrono::Utc>,
        environment: Option<&str>,
    ) -> Result<Vec<super::models::EndpointUsage>, DeveloperPortalError> {
        // Use a raw query since the env filter is optional
        let rows = sqlx::query!(
            r#"
            SELECT
                endpoint,
                method,
                COUNT(*) as request_count,
                AVG(response_time_ms::float8) as avg_rt,
                COUNT(CASE WHEN status_code >= 400 THEN 1 END)::float8 / NULLIF(COUNT(*), 0) * 100 as error_rate
            FROM usage_statistics
            WHERE application_id = $1
              AND timestamp BETWEEN $2 AND $3
              AND ($4::text IS NULL OR environment = $4)
            GROUP BY endpoint, method
            ORDER BY request_count DESC
            "#,
            application_id,
            start,
            end,
            environment
        )
        .fetch_all(self.pool.as_ref())
        .await?;

        let breakdown = rows
            .into_iter()
            .map(|r| super::models::EndpointUsage {
                endpoint: r.endpoint,
                method: r.method,
                request_count: r.request_count.unwrap_or(0),
                average_response_time: r.avg_rt.unwrap_or(0.0),
                error_rate: r.error_rate.unwrap_or(0.0),
            })
            .collect();

        Ok(breakdown)
    }

    pub async fn get_time_series(
        &self,
        application_id: Uuid,
        start: chrono::DateTime<chrono::Utc>,
        end: chrono::DateTime<chrono::Utc>,
        environment: Option<&str>,
        granularity: Option<&str>,
    ) -> Result<Vec<super::models::TimeSeriesDataPoint>, DeveloperPortalError> {
        let trunc = match granularity {
            Some("daily") => "day",
            Some("weekly") => "week",
            _ => "hour",
        };

        let rows = sqlx::query!(
            r#"
            SELECT
                date_trunc($5, timestamp) as bucket,
                COUNT(*) as request_count,
                AVG(response_time_ms::float8) as avg_rt,
                COUNT(CASE WHEN status_code >= 400 THEN 1 END)::float8 / NULLIF(COUNT(*), 0) * 100 as error_rate
            FROM usage_statistics
            WHERE application_id = $1
              AND timestamp BETWEEN $2 AND $3
              AND ($4::text IS NULL OR environment = $4)
            GROUP BY bucket
            ORDER BY bucket
            "#,
            application_id,
            start,
            end,
            environment,
            trunc
        )
        .fetch_all(self.pool.as_ref())
        .await?;

        let series = rows
            .into_iter()
            .filter_map(|r| {
                r.bucket.map(|b| super::models::TimeSeriesDataPoint {
                    timestamp: b,
                    request_count: r.request_count.unwrap_or(0),
                    average_response_time: r.avg_rt.unwrap_or(0.0),
                    error_rate: r.error_rate.unwrap_or(0.0),
                })
            })
            .collect();

        Ok(series)
    }
}
