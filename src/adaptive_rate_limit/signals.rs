//! Platform health signal collection.
//!
//! Collects CPU utilisation, database pool utilisation, Redis memory pressure,
//! request queue depth, error rate, and p99 response time at a configurable
//! sampling interval. Maintains a rolling average over a configurable window.

use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, warn};

use crate::adaptive_rate_limit::models::{RollingSignalAverage, SignalSnapshot};
use crate::cache::RedisCache;

/// Collects and maintains rolling averages of platform health signals.
#[derive(Clone)]
pub struct SignalCollector {
    cache: Arc<RedisCache>,
    db_pool: sqlx::PgPool,
    rolling: Arc<RwLock<RollingSignalAverage>>,
    /// Shared in-flight request counter (incremented/decremented by middleware).
    pub request_queue_depth: Arc<std::sync::atomic::AtomicU64>,
    /// Shared error counter (reset each sampling interval).
    pub error_counter: Arc<std::sync::atomic::AtomicU64>,
    /// Shared request counter (reset each sampling interval).
    pub request_counter: Arc<std::sync::atomic::AtomicU64>,
}

impl SignalCollector {
    pub fn new(
        cache: Arc<RedisCache>,
        db_pool: sqlx::PgPool,
        window_size: usize,
    ) -> Self {
        Self {
            cache,
            db_pool,
            rolling: Arc::new(RwLock::new(RollingSignalAverage::new(window_size))),
            request_queue_depth: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            error_counter: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            request_counter: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    /// Collect a fresh signal snapshot and push it into the rolling window.
    pub async fn collect(&self) -> SignalSnapshot {
        let snapshot = SignalSnapshot {
            captured_at: chrono::Utc::now(),
            cpu_utilisation: self.collect_cpu(),
            db_pool_utilisation: self.collect_db_pool(),
            redis_memory_pressure: self.collect_redis_memory().await,
            request_queue_depth: self
                .request_queue_depth
                .load(std::sync::atomic::Ordering::Relaxed),
            error_rate: self.collect_error_rate(),
            p99_response_time_ms: self.collect_p99_ms(),
        };

        let mut rolling = self.rolling.write().await;
        rolling.push(snapshot.clone());

        // Update Prometheus gauges
        crate::adaptive_rate_limit::metrics::signal_cpu()
            .set(snapshot.cpu_utilisation);
        crate::adaptive_rate_limit::metrics::signal_db_pool()
            .set(snapshot.db_pool_utilisation);
        crate::adaptive_rate_limit::metrics::signal_redis_memory()
            .set(snapshot.redis_memory_pressure);
        crate::adaptive_rate_limit::metrics::signal_queue_depth()
            .set(snapshot.request_queue_depth as f64);
        crate::adaptive_rate_limit::metrics::signal_error_rate()
            .set(snapshot.error_rate);
        crate::adaptive_rate_limit::metrics::signal_p99_ms()
            .set(snapshot.p99_response_time_ms);

        // Rolling averages
        let avg_cpu = rolling.avg_cpu();
        let avg_db = rolling.avg_db_pool();
        let avg_redis = rolling.avg_redis_memory();
        let avg_queue = rolling.avg_queue_depth();
        let avg_err = rolling.avg_error_rate();
        let avg_p99 = rolling.avg_p99_ms();

        crate::adaptive_rate_limit::metrics::rolling_avg_cpu().set(avg_cpu);
        crate::adaptive_rate_limit::metrics::rolling_avg_db_pool().set(avg_db);
        crate::adaptive_rate_limit::metrics::rolling_avg_redis().set(avg_redis);
        crate::adaptive_rate_limit::metrics::rolling_avg_queue_depth().set(avg_queue);
        crate::adaptive_rate_limit::metrics::rolling_avg_error_rate().set(avg_err);
        crate::adaptive_rate_limit::metrics::rolling_avg_p99_ms().set(avg_p99);

        debug!(
            cpu = snapshot.cpu_utilisation,
            db_pool = snapshot.db_pool_utilisation,
            redis = snapshot.redis_memory_pressure,
            queue = snapshot.request_queue_depth,
            error_rate = snapshot.error_rate,
            p99_ms = snapshot.p99_response_time_ms,
            "signal snapshot collected"
        );

        snapshot
    }

    /// Returns the current rolling averages as a synthetic snapshot.
    pub async fn rolling_averages(&self) -> SignalSnapshot {
        let rolling = self.rolling.read().await;
        SignalSnapshot {
            captured_at: chrono::Utc::now(),
            cpu_utilisation: rolling.avg_cpu(),
            db_pool_utilisation: rolling.avg_db_pool(),
            redis_memory_pressure: rolling.avg_redis_memory(),
            request_queue_depth: rolling.avg_queue_depth() as u64,
            error_rate: rolling.avg_error_rate(),
            p99_response_time_ms: rolling.avg_p99_ms(),
        }
    }

    /// Returns the latest raw snapshot (not averaged).
    pub async fn latest(&self) -> Option<SignalSnapshot> {
        let rolling = self.rolling.read().await;
        rolling.latest().cloned()
    }

    // ── Signal collectors ────────────────────────────────────────────────────

    fn collect_cpu(&self) -> f64 {
        // Read from the Prometheus process CPU gauge if available.
        // On Linux we can read /proc/stat; for portability we use the
        // prometheus process collector which tracks CPU seconds.
        // We approximate utilisation from the rate of CPU seconds consumed.
        // For now we expose the value via the existing metrics infrastructure.
        // A production deployment would integrate with a sysinfo crate or
        // read from the OS directly. We return 0.0 as a safe default when
        // the value cannot be determined.
        #[cfg(target_os = "linux")]
        {
            if let Ok(content) = std::fs::read_to_string("/proc/loadavg") {
                if let Some(load_str) = content.split_whitespace().next() {
                    if let Ok(load) = load_str.parse::<f64>() {
                        // Normalise by number of logical CPUs
                        let cpus = num_cpus_count();
                        return (load / cpus as f64).min(1.0);
                    }
                }
            }
        }
        0.0
    }

    fn collect_db_pool(&self) -> f64 {
        let stats = crate::database::get_pool_stats(&self.db_pool);
        // size = total connections (idle + active), num_idle = idle connections
        let active = stats.size.saturating_sub(stats.num_idle) as f64;
        // Use a reasonable max (pool max_connections default is 20)
        let max = self.db_pool.options().get_max_connections() as f64;
        if max == 0.0 {
            return 0.0;
        }
        (active / max).min(1.0)
    }

    async fn collect_redis_memory(&self) -> f64 {
        // Query Redis INFO memory to get used_memory / maxmemory.
        let mut conn = match self.cache.get_connection().await {
            Ok(c) => c,
            Err(_) => return 0.0,
        };
        let info: String = match redis::cmd("INFO")
            .arg("memory")
            .query_async(&mut *conn)
            .await
        {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %e, "failed to query Redis INFO memory");
                return 0.0;
            }
        };

        let used = parse_redis_info_field(&info, "used_memory").unwrap_or(0.0);
        let max = parse_redis_info_field(&info, "maxmemory").unwrap_or(0.0);

        if max == 0.0 {
            // maxmemory not configured — use used_memory_rss as a proxy
            let rss = parse_redis_info_field(&info, "used_memory_rss").unwrap_or(0.0);
            if rss == 0.0 {
                return 0.0;
            }
            // Treat 80% of RSS as "full" when no maxmemory is set
            return (used / (rss * 1.25)).min(1.0);
        }

        (used / max).min(1.0)
    }

    fn collect_error_rate(&self) -> f64 {
        let errors = self
            .error_counter
            .swap(0, std::sync::atomic::Ordering::Relaxed);
        let requests = self
            .request_counter
            .swap(0, std::sync::atomic::Ordering::Relaxed);
        if requests == 0 {
            return 0.0;
        }
        (errors as f64 / requests as f64).min(1.0)
    }

    #[allow(clippy::unused_self)]
    fn collect_p99_ms(&self) -> f64 {
        // p99 approximation from the Prometheus histogram is not directly
        // available in Rust. A production deployment would use a sliding-window
        // HDR histogram. We return 0.0 as a safe default; the signal is still
        // useful when overridden by a custom collector.
        0.0
    }

    /// Increment the in-flight request counter.
    pub fn request_started(&self) {
        self.request_queue_depth
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.request_counter
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Decrement the in-flight request counter and optionally record an error.
    pub fn request_finished(&self, is_error: bool) {
        self.request_queue_depth
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        if is_error {
            self.error_counter
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn parse_redis_info_field(info: &str, field: &str) -> Option<f64> {
    for line in info.lines() {
        if line.starts_with(field) {
            let parts: Vec<&str> = line.splitn(2, ':').collect();
            if parts.len() == 2 {
                return parts[1].trim().parse::<f64>().ok();
            }
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn num_cpus_count() -> usize {
    std::fs::read_to_string("/proc/cpuinfo")
        .ok()
        .map(|s| s.lines().filter(|l| l.starts_with("processor")).count())
        .unwrap_or(1)
        .max(1)
}
