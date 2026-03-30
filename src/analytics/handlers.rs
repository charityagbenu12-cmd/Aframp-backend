
use crate::analytics::models::*;
use crate::analytics::repository::AnalyticsRepository;
use crate::cache::{Cache, RedisCache};
use crate::error::Error;
use axum::{
    extract::{Query, State},
    response::Json,
};
use chrono::{Duration, Utc};
use serde_json::Value;
use sqlx::types::BigDecimal;
use std::sync::Arc;
use std::time::Duration as StdDuration;

const ANALYTICS_CACHE_TTL: StdDuration = StdDuration::from_secs(300); // 5 minutes

pub struct AnalyticsState {
    pub repo: AnalyticsRepository,
    pub cache: RedisCache<Value>,
}

// ── /analytics/transactions/volume ───────────────────────────────────────────

pub async fn transaction_volume_handler(
    State(state): State<Arc<AnalyticsState>>,
    Query(params): Query<DateRangeParams>,
) -> Result<Json<TransactionVolumeResponse>, Error> {
    params.validate().map_err(|e| Error::BadRequest(e))?;

    let cache_key = format!(
        "analytics:volume:{}:{}:{}",
        params.from.timestamp(),
        params.to.timestamp(),
        params.period
    );

    if let Ok(Some(cached)) = state.cache.get(&cache_key).await {
        let resp: TransactionVolumeResponse =
            serde_json::from_value(cached).map_err(|e| Error::Internal(e.to_string()))?;
        return Ok(Json(resp));
    }

    let data = state
        .repo
        .transaction_volume(params.from, params.to, &params.period)
        .await
        .map_err(|e| Error::Database(e.to_string()))?;

    let resp = TransactionVolumeResponse {
        from: params.from,
        to: params.to,
        period: params.period,
        data,
    };

    let _ = state
        .cache
        .set(
            &cache_key,
            &serde_json::to_value(&resp).unwrap_or_default(),
            Some(ANALYTICS_CACHE_TTL),
        )
        .await;

    Ok(Json(resp))
}

// ── /analytics/cngn/conversions ───────────────────────────────────────────────

pub async fn cngn_conversions_handler(
    State(state): State<Arc<AnalyticsState>>,
    Query(params): Query<DateRangeParams>,
) -> Result<Json<CngnConversionsResponse>, Error> {
    params.validate().map_err(|e| Error::BadRequest(e))?;

    let cache_key = format!(
        "analytics:cngn:{}:{}:{}",
        params.from.timestamp(),
        params.to.timestamp(),
        params.period
    );

    if let Ok(Some(cached)) = state.cache.get(&cache_key).await {
        let resp: CngnConversionsResponse =
            serde_json::from_value(cached).map_err(|e| Error::Internal(e.to_string()))?;
        return Ok(Json(resp));
    }

    let data = state
        .repo
        .cngn_conversions(params.from, params.to, &params.period)
        .await
        .map_err(|e| Error::Database(e.to_string()))?;

    let resp = CngnConversionsResponse {
        from: params.from,
        to: params.to,
        period: params.period,
        data,
    };

    let _ = state
        .cache
        .set(
            &cache_key,
            &serde_json::to_value(&resp).unwrap_or_default(),
            Some(ANALYTICS_CACHE_TTL),
        )
        .await;

    Ok(Json(resp))
}

// ── /analytics/providers/performance ─────────────────────────────────────────

pub async fn provider_performance_handler(
    State(state): State<Arc<AnalyticsState>>,
    Query(params): Query<DateRangeParams>,
) -> Result<Json<ProviderPerformanceResponse>, Error> {
    params.validate().map_err(|e| Error::BadRequest(e))?;

    let cache_key = format!(
        "analytics:providers:{}:{}:{}",
        params.from.timestamp(),
        params.to.timestamp(),
        params.period
    );

    if let Ok(Some(cached)) = state.cache.get(&cache_key).await {
        let resp: ProviderPerformanceResponse =
            serde_json::from_value(cached).map_err(|e| Error::Internal(e.to_string()))?;
        return Ok(Json(resp));
    }

    let (performance, failure_breakdown) = tokio::try_join!(
        state
            .repo
            .provider_performance(params.from, params.to, &params.period),
        state.repo.provider_failure_breakdown(params.from, params.to),
    )
    .map_err(|e| Error::Database(e.to_string()))?;

    let resp = ProviderPerformanceResponse {
        from: params.from,
        to: params.to,
        period: params.period,
        performance,
        failure_breakdown,
    };

    let _ = state
        .cache
        .set(
            &cache_key,
            &serde_json::to_value(&resp).unwrap_or_default(),
            Some(ANALYTICS_CACHE_TTL),
        )
        .await;

    Ok(Json(resp))
}

// ── /analytics/summary ────────────────────────────────────────────────────────

pub async fn summary_handler(
    State(state): State<Arc<AnalyticsState>>,
) -> Result<Json<SummaryResponse>, Error> {
    let cache_key = "analytics:summary";

    if let Ok(Some(cached)) = state.cache.get(cache_key).await {
        let resp: SummaryResponse =
            serde_json::from_value(cached).map_err(|e| Error::Internal(e.to_string()))?;
        return Ok(Json(resp));
    }

    let now = Utc::now();
    let today_start = now
        .date_naive()
        .and_hms_opt(0, 0, 0)
        .unwrap()
        .and_utc();
    let yesterday_start = today_start - Duration::days(1);

    let ((today_count, today_vol, today_cngn, today_wallets), (yest_count, yest_vol, yest_cngn, yest_wallets), rate_age, providers) =
        tokio::try_join!(
            state.repo.daily_totals(today_start, now),
            state.repo.daily_totals(yesterday_start, today_start),
            state.repo.rate_freshness_seconds(),
            state.repo.active_providers(),
        )
        .map_err(|e| Error::Database(e.to_string()))?;

    let resp = SummaryResponse {
        date: today_start.format("%Y-%m-%d").to_string(),
        total_transactions: build_delta(
            BigDecimal::from(today_count),
            BigDecimal::from(yest_count),
        ),
        total_volume_ngn: build_delta(today_vol, yest_vol),
        total_cngn_transferred: build_delta(today_cngn, yest_cngn),
        active_wallets: build_delta(
            BigDecimal::from(today_wallets),
            BigDecimal::from(yest_wallets),
        ),
        health: HealthIndicators {
            worker_status: "running".to_string(),
            rate_freshness_seconds: rate_age,
            active_providers: providers,
        },
    };

    let _ = state
        .cache
        .set(
            cache_key,
            &serde_json::to_value(&resp).unwrap_or_default(),
            Some(ANALYTICS_CACHE_TTL),
        )
        .await;

    Ok(Json(resp))
}

// ── helpers ───────────────────────────────────────────────────────────────────

fn build_delta(today: BigDecimal, yesterday: BigDecimal) -> DeltaMetric {
    use std::str::FromStr;
    let hundred = BigDecimal::from(100u32);
    let delta_pct = if yesterday == BigDecimal::from(0u32) {
        BigDecimal::from(0u32)
    } else {
        ((&today - &yesterday) / &yesterday * &hundred)
            .round(2)
    };
    DeltaMetric {
        today,
        yesterday,
        delta_pct,
    }

use super::models::*;
use super::repository::AnalyticsRepository;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Json},
};
use chrono::{Duration, Utc};
use serde_json::json;
use std::sync::Arc;
use tracing::error;

pub type AnalyticsState = Arc<AnalyticsRepository>;

// ── Consumer-facing endpoints ────────────────────────────────────────────────

pub async fn get_usage_summary(
    State(repo): State<AnalyticsState>,
    consumer_id: String, // Extracted from auth middleware
    Query(query): Query<UsageSummaryQuery>,
) -> Result<Json<UsageSummaryResponse>, (StatusCode, String)> {
    let (period_start, period_end, period_name) = match query.period.as_deref() {
        Some("current_hour") => {
            let now = Utc::now();
            let start = now - Duration::hours(1);
            (start, now, "current_hour")
        }
        Some("today") => {
            let now = Utc::now();
            let start = now.date_naive().and_hms_opt(0, 0, 0).unwrap().and_utc();
            (start, now, "today")
        }
        Some("this_week") => {
            let now = Utc::now();
            let start = now - Duration::days(7);
            (start, now, "this_week")
        }
        _ => {
            let now = Utc::now();
            let start = now - Duration::days(30);
            (start, now, "this_month")
        }
    };

    let snapshots = repo
        .get_consumer_snapshots(&consumer_id, SnapshotPeriod::Daily, 30)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let total_requests: i64 = snapshots.iter().map(|s| s.total_requests).sum();
    let failed_requests: i64 = snapshots.iter().map(|s| s.failed_requests).sum();
    let error_rate = if total_requests > 0 {
        failed_requests as f64 / total_requests as f64
    } else {
        0.0
    };

    let features = repo
        .get_consumer_feature_adoption(&consumer_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let active_features: Vec<String> = features
        .into_iter()
        .filter(|f| f.is_active)
        .map(|f| f.feature_name)
        .collect();

    let health_score = repo
        .get_latest_health_score(&consumer_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .map(|s| s.health_score);

    Ok(Json(UsageSummaryResponse {
        period: period_name.to_string(),
        period_start,
        period_end,
        total_requests,
        error_rate,
        rate_limit_utilization: 0.0, // Placeholder
        active_features,
        health_score,
    }))
}

pub async fn get_endpoint_usage(
    State(repo): State<AnalyticsState>,
    consumer_id: String,
) -> Result<Json<Vec<EndpointUsageResponse>>, (StatusCode, String)> {
    let period_end = Utc::now();
    let period_start = period_end - Duration::days(30);

    let usage = repo
        .get_consumer_endpoint_usage(&consumer_id, period_start, period_end)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let response: Vec<EndpointUsageResponse> = usage
        .into_iter()
        .map(|u| {
            let error_rate = if u.request_count > 0 {
                u.error_count as f64 / u.request_count as f64
            } else {
                0.0
            };
            EndpointUsageResponse {
                endpoint_path: u.endpoint_path,
                http_method: u.http_method,
                request_count: u.request_count,
                error_rate,
                avg_latency_ms: u.avg_latency_ms,
            }
        })
        .collect();

    Ok(Json(response))
}

pub async fn get_feature_adoption(
    State(repo): State<AnalyticsState>,
    consumer_id: String,
) -> Result<Json<Vec<FeatureAdoptionResponse>>, (StatusCode, String)> {
    let features = repo
        .get_consumer_feature_adoption(&consumer_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let response: Vec<FeatureAdoptionResponse> = features
        .into_iter()
        .map(|f| FeatureAdoptionResponse {
            feature_name: f.feature_name,
            first_used_at: f.first_used_at,
            last_used_at: f.last_used_at,
            total_usage_count: f.total_usage_count,
            is_active: f.is_active,
        })
        .collect();

    Ok(Json(response))
}

// ── Admin endpoints ──────────────────────────────────────────────────────────

pub async fn get_consumer_overview(
    State(repo): State<AnalyticsState>,
) -> Result<Json<ConsumerOverviewResponse>, (StatusCode, String)> {
    // Placeholder implementation
    Ok(Json(ConsumerOverviewResponse {
        total_registered_consumers: 0,
        active_consumers_by_tier: json!({}),
        new_consumers_this_period: 0,
        consumer_growth_trend: vec![],
    }))
}

pub async fn get_at_risk_consumers(
    State(repo): State<AnalyticsState>,
) -> Result<Json<Vec<AtRiskConsumer>>, (StatusCode, String)> {
    let scores = repo
        .get_at_risk_consumers(100)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let response: Vec<AtRiskConsumer> = scores
        .into_iter()
        .map(|s| {
            let risk_factors: Vec<String> = s
                .risk_factors
                .as_ref()
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();

            AtRiskConsumer {
                consumer_id: s.consumer_id,
                health_score: s.health_score,
                risk_factors,
                last_activity: s.score_timestamp,
            }
        })
        .collect();

    Ok(Json(response))
}

pub async fn get_platform_reports(
    State(repo): State<AnalyticsState>,
) -> Result<Json<Vec<PlatformUsageReport>>, (StatusCode, String)> {
    let reports = repo
        .get_platform_reports(None, 50)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(reports))
}

pub async fn get_consumer_detail(
    State(repo): State<AnalyticsState>,
    Path(consumer_id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let snapshots = repo
        .get_consumer_snapshots(&consumer_id, SnapshotPeriod::Daily, 30)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let health_score = repo
        .get_latest_health_score(&consumer_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let features = repo
        .get_consumer_feature_adoption(&consumer_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(json!({
        "consumer_id": consumer_id,
        "snapshots": snapshots,
        "health_score": health_score,
        "features": features
    })))

}
