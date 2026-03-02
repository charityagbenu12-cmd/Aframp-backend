use crate::cache::cache::{Cache, RedisCache};
use crate::services::exchange_rate::ExchangeRateService;
use axum::{
    extract::{Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use bigdecimal::BigDecimal;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info, warn};

/// State for the rates API
#[derive(Clone)]
pub struct RatesState {
    pub exchange_rate_service: Arc<ExchangeRateService>,
    pub cache: Option<Arc<RedisCache>>,
}

/// Query parameters for rates endpoint
#[derive(Debug, Deserialize)]
pub struct RatesQuery {
    /// Base currency (e.g., "NGN")
    pub from: Option<String>,
    /// Quote currency (e.g., "cNGN")
    pub to: Option<String>,
    /// Comma-separated pairs (e.g., "NGN/cNGN,USD/NGN")
    pub pairs: Option<String>,
}

/// Response for single rate query
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RateResponse {
    pub pair: String,
    pub base_currency: String,
    pub quote_currency: String,
    pub rate: String,
    pub inverse_rate: String,
    pub spread_percentage: String,
    pub last_updated: DateTime<Utc>,
    pub source: String,
    pub timestamp: DateTime<Utc>,
}

/// Response for multiple pairs query
#[derive(Debug, Serialize)]
pub struct MultipleRatesResponse {
    pub rates: Vec<RateInfo>,
    pub timestamp: DateTime<Utc>,
}

/// Rate info for multiple pairs
#[derive(Debug, Serialize)]
pub struct RateInfo {
    pub pair: String,
    pub rate: String,
    pub last_updated: DateTime<Utc>,
    pub source: String,
}

/// Response for all pairs query
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AllRatesResponse {
    pub rates: HashMap<String, RateDetail>,
    pub supported_currencies: Vec<String>,
    pub timestamp: DateTime<Utc>,
}

/// Rate detail for all pairs response
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RateDetail {
    pub rate: String,
    pub inverse_rate: String,
    pub spread: String,
    pub last_updated: DateTime<Utc>,
    pub source: String,
}

/// Error response
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: ErrorDetail,
}

/// Error detail
#[derive(Debug, Serialize)]
pub struct ErrorDetail {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supported_currencies: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supported_pairs: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after: Option<u64>,
}

/// Supported currency pairs
const SUPPORTED_PAIRS: &[(&str, &str)] = &[
    ("NGN", "cNGN"),
    ("cNGN", "NGN"),
];

/// Get supported currencies from pairs
fn get_supported_currencies() -> Vec<String> {
    let mut currencies: Vec<String> = SUPPORTED_PAIRS
        .iter()
        .flat_map(|(from, to)| vec![from.to_string(), to.to_string()])
        .collect();
    currencies.sort();
    currencies.dedup();
    currencies
}

/// Get supported pair strings
fn get_supported_pair_strings() -> Vec<String> {
    SUPPORTED_PAIRS
        .iter()
        .map(|(from, to)| format!("{}/{}", from, to))
        .collect()
}

/// Check if currency is supported
fn is_currency_supported(currency: &str) -> bool {
    SUPPORTED_PAIRS
        .iter()
        .any(|(from, to)| from == &currency || to == &currency)
}

/// Check if pair is supported
fn is_pair_supported(from: &str, to: &str) -> bool {
    SUPPORTED_PAIRS
        .iter()
        .any(|(f, t)| f == &from && t == &to)
}

/// Generate cache key for rate query
fn generate_cache_key(params: &RatesQuery) -> String {
    match (&params.from, &params.to, &params.pairs) {
        (Some(from), Some(to), _) => format!("api:rates:{}:{}", from, to),
        (_, _, Some(pairs)) => {
            let normalized = pairs.replace("/", "-").replace(",", "_");
            format!("api:rates:{}", normalized)
        }
        _ => "api:rates:all".to_string(),
    }
}

/// Generate ETag from rate data
fn generate_etag(data: &str, timestamp: &DateTime<Utc>) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    
    let mut hasher = DefaultHasher::new();
    data.hash(&mut hasher);
    timestamp.timestamp().hash(&mut hasher);
    format!("\"rate-{}\"", hasher.finish())
}

/// Get exchange rate(s) - Main endpoint handler
pub async fn get_rates(
    State(state): State<RatesState>,
    headers: HeaderMap,
    Query(params): Query<RatesQuery>,
) -> Result<Response, Response> {
    info!("GET /api/rates - params: {:?}", params);

    // Generate cache key
    let cache_key = generate_cache_key(&params);
    
    // Check cache first
    if let Some(ref cache) = state.cache {
        // Try single rate response
        let cached_result: Result<Option<RateResponse>, _> = cache.get(&cache_key).await;
        if let Ok(Some(cached)) = cached_result {
            debug!("Cache hit for {}", cache_key);
            return build_cached_response(cached, &headers);
        }
        
        // Try all rates response
        let cached_result: Result<Option<AllRatesResponse>, _> = cache.get(&cache_key).await;
        if let Ok(Some(cached)) = cached_result {
            debug!("Cache hit for {}", cache_key);
            return build_all_rates_cached_response(cached, &headers);
        }
    }

    // Cache miss - fetch from service
    debug!("Cache miss for {}", cache_key);
    
    match (&params.from, &params.to, &params.pairs) {
        // Single pair query: ?from=NGN&to=cNGN
        (Some(from), Some(to), _) => {
            handle_single_pair(&state, &cache_key, from, to).await
        }
        // Multiple pairs query: ?pairs=NGN/cNGN,USD/NGN
        (_, _, Some(pairs_str)) => {
            handle_multiple_pairs(&state, pairs_str).await
        }
        // All pairs query: no parameters
        (None, None, None) => {
            handle_all_pairs(&state, &cache_key).await
        }
        // Invalid: only from or only to
        _ => {
            warn!("Invalid query parameters: {:?}", params);
            Err(build_error_response(
                StatusCode::BAD_REQUEST,
                "INVALID_PARAMETERS",
                "Either provide both 'from' and 'to', or 'pairs', or no parameters for all rates",
                None,
                None,
                None,
            ))
        }
    }
}

/// Handle single pair query
async fn handle_single_pair(
    state: &RatesState,
    cache_key: &str,
    from: &str,
    to: &str,
) -> Result<Response, Response> {
    // Validate currencies
    if !is_currency_supported(from) {
        return Err(build_error_response(
            StatusCode::BAD_REQUEST,
            "INVALID_CURRENCY",
            &format!("Unsupported currency: {}", from),
            Some(get_supported_currencies()),
            None,
            None,
        ));
    }
    
    if !is_currency_supported(to) {
        return Err(build_error_response(
            StatusCode::BAD_REQUEST,
            "INVALID_CURRENCY",
            &format!("Unsupported currency: {}", to),
            Some(get_supported_currencies()),
            None,
            None,
        ));
    }
    
    // Validate pair
    if !is_pair_supported(from, to) {
        return Err(build_error_response(
            StatusCode::BAD_REQUEST,
            "INVALID_PAIR",
            &format!("Currency pair not supported: {}/{}", from, to),
            None,
            Some(get_supported_pair_strings()),
            None,
        ));
    }

    // Fetch rate from service
    match state.exchange_rate_service.get_rate(from, to).await {
        Ok(rate) => {
            let rate_str = rate.to_string();
            let inverse_rate = if rate > BigDecimal::from(0) {
                (BigDecimal::from(1) / &rate).to_string()
            } else {
                "0".to_string()
            };
            
            let response = RateResponse {
                pair: format!("{}/{}", from, to),
                base_currency: from.to_string(),
                quote_currency: to.to_string(),
                rate: rate_str.clone(),
                inverse_rate,
                spread_percentage: "0.0".to_string(), // Fixed peg has no spread
                last_updated: Utc::now(),
                source: if from == "NGN" && to == "cNGN" || from == "cNGN" && to == "NGN" {
                    "fixed_peg".to_string()
                } else {
                    "external_api".to_string()
                },
                timestamp: Utc::now(),
            };

            // Cache the response
            if let Some(ref cache) = state.cache {
                let ttl = Duration::from_secs(30);
                let _ = cache.set(cache_key, &response, Some(ttl)).await;
            }

            // Build response with headers
            let etag = generate_etag(&rate_str, &response.timestamp);
            let mut headers = HeaderMap::new();
            headers.insert(header::CACHE_CONTROL, "public, max-age=30".parse().unwrap());
            headers.insert(header::ETAG, etag.parse().unwrap());
            headers.insert(
                header::LAST_MODIFIED,
                response.last_updated.format("%a, %d %b %Y %H:%M:%S GMT").to_string().parse().unwrap(),
            );
            add_cors_headers(&mut headers);

            Ok((StatusCode::OK, headers, Json(response)).into_response())
        }
        Err(e) => {
            error!("Failed to fetch rate {}/{}: {}", from, to, e);
            Err(build_error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "RATE_SERVICE_UNAVAILABLE",
                "Exchange rate service temporarily unavailable",
                None,
                None,
                Some(60),
            ))
        }
    }
}

/// Handle multiple pairs query
async fn handle_multiple_pairs(
    state: &RatesState,
    pairs_str: &str,
) -> Result<Response, Response> {
    let pairs: Vec<&str> = pairs_str.split(',').map(|s| s.trim()).collect();
    let mut rates = Vec::new();

    for pair_str in pairs {
        let parts: Vec<&str> = pair_str.split('/').collect();
        if parts.len() != 2 {
            return Err(build_error_response(
                StatusCode::BAD_REQUEST,
                "INVALID_PAIR_FORMAT",
                &format!("Invalid pair format: {}. Expected format: FROM/TO", pair_str),
                None,
                None,
                None,
            ));
        }

        let from = parts[0];
        let to = parts[1];

        if !is_pair_supported(from, to) {
            return Err(build_error_response(
                StatusCode::BAD_REQUEST,
                "INVALID_PAIR",
                &format!("Currency pair not supported: {}", pair_str),
                None,
                Some(get_supported_pair_strings()),
                None,
            ));
        }

        match state.exchange_rate_service.get_rate(from, to).await {
            Ok(rate) => {
                rates.push(RateInfo {
                    pair: pair_str.to_string(),
                    rate: rate.to_string(),
                    last_updated: Utc::now(),
                    source: if from == "NGN" && to == "cNGN" || from == "cNGN" && to == "NGN" {
                        "fixed_peg".to_string()
                    } else {
                        "external_api".to_string()
                    },
                });
            }
            Err(e) => {
                error!("Failed to fetch rate for {}: {}", pair_str, e);
                return Err(build_error_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "RATE_SERVICE_UNAVAILABLE",
                    "Exchange rate service temporarily unavailable",
                    None,
                    None,
                    Some(60),
                ));
            }
        }
    }

    let response = MultipleRatesResponse {
        rates,
        timestamp: Utc::now(),
    };

    let mut headers = HeaderMap::new();
    headers.insert(header::CACHE_CONTROL, "public, max-age=30".parse().unwrap());
    add_cors_headers(&mut headers);

    Ok((StatusCode::OK, headers, Json(response)).into_response())
}

/// Handle all pairs query
async fn handle_all_pairs(
    state: &RatesState,
    cache_key: &str,
) -> Result<Response, Response> {
    let mut rates_map = HashMap::new();

    for (from, to) in SUPPORTED_PAIRS {
        match state.exchange_rate_service.get_rate(from, to).await {
            Ok(rate) => {
                let rate_str = rate.to_string();
                let inverse_rate = if rate > BigDecimal::from(0) {
                    (BigDecimal::from(1) / &rate).to_string()
                } else {
                    "0".to_string()
                };

                rates_map.insert(
                    format!("{}/{}", from, to),
                    RateDetail {
                        rate: rate_str,
                        inverse_rate,
                        spread: "0.0".to_string(),
                        last_updated: Utc::now(),
                        source: "fixed_peg".to_string(),
                    },
                );
            }
            Err(e) => {
                error!("Failed to fetch rate {}/{}: {}", from, to, e);
                // Continue with other pairs instead of failing completely
            }
        }
    }

    if rates_map.is_empty() {
        return Err(build_error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "RATE_SERVICE_UNAVAILABLE",
            "Exchange rate service temporarily unavailable",
            None,
            None,
            Some(60),
        ));
    }

    let response = AllRatesResponse {
        rates: rates_map,
        supported_currencies: get_supported_currencies(),
        timestamp: Utc::now(),
    };

    // Cache the response
    if let Some(ref cache) = state.cache {
        let ttl = Duration::from_secs(30);
        let _ = cache.set(cache_key, &response, Some(ttl)).await;
    }

    let etag = generate_etag(&format!("{:?}", response.rates), &response.timestamp);
    let mut headers = HeaderMap::new();
    headers.insert(header::CACHE_CONTROL, "public, max-age=30".parse().unwrap());
    headers.insert(header::ETAG, etag.parse().unwrap());
    add_cors_headers(&mut headers);

    Ok((StatusCode::OK, headers, Json(response)).into_response())
}

/// Build cached response with conditional request support
fn build_cached_response(
    cached: RateResponse,
    request_headers: &HeaderMap,
) -> Result<Response, Response> {
    let etag = generate_etag(&cached.rate, &cached.timestamp);
    
    // Check If-None-Match header
    if let Some(if_none_match) = request_headers.get(header::IF_NONE_MATCH) {
        if let Ok(client_etag) = if_none_match.to_str() {
            if client_etag == etag {
                // ETag matches - return 304 Not Modified
                let mut headers = HeaderMap::new();
                headers.insert(header::ETAG, etag.parse().unwrap());
                headers.insert(header::CACHE_CONTROL, "public, max-age=30".parse().unwrap());
                add_cors_headers(&mut headers);
                return Ok((StatusCode::NOT_MODIFIED, headers).into_response());
            }
        }
    }

    // Return full response
    let mut headers = HeaderMap::new();
    headers.insert(header::CACHE_CONTROL, "public, max-age=30".parse().unwrap());
    headers.insert(header::ETAG, etag.parse().unwrap());
    headers.insert(
        header::LAST_MODIFIED,
        cached.last_updated.format("%a, %d %b %Y %H:%M:%S GMT").to_string().parse().unwrap(),
    );
    add_cors_headers(&mut headers);

    Ok((StatusCode::OK, headers, Json(cached)).into_response())
}

/// Build cached response for all rates
fn build_all_rates_cached_response(
    cached: AllRatesResponse,
    request_headers: &HeaderMap,
) -> Result<Response, Response> {
    let etag = generate_etag(&format!("{:?}", cached.rates), &cached.timestamp);
    
    // Check If-None-Match header
    if let Some(if_none_match) = request_headers.get(header::IF_NONE_MATCH) {
        if let Ok(client_etag) = if_none_match.to_str() {
            if client_etag == etag {
                let mut headers = HeaderMap::new();
                headers.insert(header::ETAG, etag.parse().unwrap());
                headers.insert(header::CACHE_CONTROL, "public, max-age=30".parse().unwrap());
                add_cors_headers(&mut headers);
                return Ok((StatusCode::NOT_MODIFIED, headers).into_response());
            }
        }
    }

    let mut headers = HeaderMap::new();
    headers.insert(header::CACHE_CONTROL, "public, max-age=30".parse().unwrap());
    headers.insert(header::ETAG, etag.parse().unwrap());
    add_cors_headers(&mut headers);

    Ok((StatusCode::OK, headers, Json(cached)).into_response())
}

/// Build error response
fn build_error_response(
    status: StatusCode,
    code: &str,
    message: &str,
    supported_currencies: Option<Vec<String>>,
    supported_pairs: Option<Vec<String>>,
    retry_after: Option<u64>,
) -> Response {
    let error_response = ErrorResponse {
        error: ErrorDetail {
            code: code.to_string(),
            message: message.to_string(),
            supported_currencies,
            supported_pairs,
            retry_after,
        },
    };

    let mut headers = HeaderMap::new();
    if let Some(retry) = retry_after {
        headers.insert(header::RETRY_AFTER, retry.to_string().parse().unwrap());
    }
    add_cors_headers(&mut headers);

    (status, headers, Json(error_response)).into_response()
}

/// Add CORS headers for public API
fn add_cors_headers(headers: &mut HeaderMap) {
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        "*".parse().unwrap(),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        "GET, OPTIONS".parse().unwrap(),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        "Content-Type".parse().unwrap(),
    );
    headers.insert(
        header::ACCESS_CONTROL_MAX_AGE,
        "86400".parse().unwrap(),
    );
}

/// Handle OPTIONS preflight requests
pub async fn options_rates() -> Response {
    let mut headers = HeaderMap::new();
    add_cors_headers(&mut headers);
    (StatusCode::NO_CONTENT, headers).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_currency_supported() {
        assert!(is_currency_supported("NGN"));
        assert!(is_currency_supported("cNGN"));
        assert!(!is_currency_supported("USD"));
        assert!(!is_currency_supported("BTC"));
    }

    #[test]
    fn test_is_pair_supported() {
        assert!(is_pair_supported("NGN", "cNGN"));
        assert!(is_pair_supported("cNGN", "NGN"));
        assert!(!is_pair_supported("USD", "NGN"));
        assert!(!is_pair_supported("NGN", "USD"));
    }

    #[test]
    fn test_generate_cache_key() {
        let query1 = RatesQuery {
            from: Some("NGN".to_string()),
            to: Some("cNGN".to_string()),
            pairs: None,
        };
        assert_eq!(generate_cache_key(&query1), "api:rates:NGN:cNGN");

        let query2 = RatesQuery {
            from: None,
            to: None,
            pairs: Some("NGN/cNGN,USD/NGN".to_string()),
        };
        assert_eq!(generate_cache_key(&query2), "api:rates:NGN-cNGN_USD-NGN");

        let query3 = RatesQuery {
            from: None,
            to: None,
            pairs: None,
        };
        assert_eq!(generate_cache_key(&query3), "api:rates:all");
    }

    #[test]
    fn test_get_supported_currencies() {
        let currencies = get_supported_currencies();
        assert!(currencies.contains(&"NGN".to_string()));
        assert!(currencies.contains(&"cNGN".to_string()));
        assert_eq!(currencies.len(), 2);
    }
}
