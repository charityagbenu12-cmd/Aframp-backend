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
}
