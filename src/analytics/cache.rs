use std::time::Duration;

/// Cache TTL configuration for analytics endpoints
pub struct AnalyticsCacheTTL;

impl AnalyticsCacheTTL {
    /// Usage summary - 5 minutes (frequently updated)
    pub const USAGE_SUMMARY: Duration = Duration::from_secs(300);
    
    /// Endpoint usage - 10 minutes (moderate update frequency)
    pub const ENDPOINT_USAGE: Duration = Duration::from_secs(600);
    
    /// Feature adoption - 1 hour (low volatility)
    pub const FEATURE_ADOPTION: Duration = Duration::from_secs(3600);
    
    /// Health scores - 15 minutes (updated daily but cached for performance)
    pub const HEALTH_SCORES: Duration = Duration::from_secs(900);
    
    /// Consumer overview - 5 minutes (platform-wide stats)
    pub const CONSUMER_OVERVIEW: Duration = Duration::from_secs(300);
    
    /// Reports list - 1 hour (historical data)
    pub const REPORTS_LIST: Duration = Duration::from_secs(3600);
    
    /// Consumer detail - 10 minutes (comprehensive view)
    pub const CONSUMER_DETAIL: Duration = Duration::from_secs(600);
}

/// Generate cache keys for analytics data
pub fn cache_key_usage_summary(consumer_id: &str, period: &str) -> String {
    format!("analytics:usage_summary:{}:{}", consumer_id, period)
}

pub fn cache_key_endpoint_usage(consumer_id: &str) -> String {
    format!("analytics:endpoint_usage:{}", consumer_id)
}

pub fn cache_key_feature_adoption(consumer_id: &str) -> String {
    format!("analytics:feature_adoption:{}", consumer_id)
}

pub fn cache_key_health_scores() -> String {
    "analytics:health_scores:at_risk".to_string()
}

pub fn cache_key_consumer_overview() -> String {
    "analytics:consumer_overview".to_string()
}

pub fn cache_key_consumer_detail(consumer_id: &str) -> String {
    format!("analytics:consumer_detail:{}", consumer_id)
}
