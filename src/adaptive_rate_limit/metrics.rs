//! Prometheus metrics for the adaptive rate limiting system.

use prometheus::{
    register_counter_vec_with_registry, register_gauge_vec_with_registry,
    register_gauge_with_registry, CounterVec, Gauge, GaugeVec, Registry,
};
use std::sync::OnceLock;

// ── Current adaptation mode (0=normal, 1=elevated, 2=critical, 3=emergency) ─

static CURRENT_MODE: OnceLock<Gauge> = OnceLock::new();

pub fn current_mode() -> &'static Gauge {
    CURRENT_MODE.get().expect("adaptive rl metrics not initialised")
}

// ── Signal gauges ─────────────────────────────────────────────────────────────

static SIGNAL_CPU: OnceLock<Gauge> = OnceLock::new();
static SIGNAL_DB_POOL: OnceLock<Gauge> = OnceLock::new();
static SIGNAL_REDIS_MEMORY: OnceLock<Gauge> = OnceLock::new();
static SIGNAL_QUEUE_DEPTH: OnceLock<Gauge> = OnceLock::new();
static SIGNAL_ERROR_RATE: OnceLock<Gauge> = OnceLock::new();
static SIGNAL_P99_MS: OnceLock<Gauge> = OnceLock::new();

pub fn signal_cpu() -> &'static Gauge {
    SIGNAL_CPU.get().expect("adaptive rl metrics not initialised")
}
pub fn signal_db_pool() -> &'static Gauge {
    SIGNAL_DB_POOL.get().expect("adaptive rl metrics not initialised")
}
pub fn signal_redis_memory() -> &'static Gauge {
    SIGNAL_REDIS_MEMORY
        .get()
        .expect("adaptive rl metrics not initialised")
}
pub fn signal_queue_depth() -> &'static Gauge {
    SIGNAL_QUEUE_DEPTH
        .get()
        .expect("adaptive rl metrics not initialised")
}
pub fn signal_error_rate() -> &'static Gauge {
    SIGNAL_ERROR_RATE
        .get()
        .expect("adaptive rl metrics not initialised")
}
pub fn signal_p99_ms() -> &'static Gauge {
    SIGNAL_P99_MS.get().expect("adaptive rl metrics not initialised")
}

// ── Rolling average gauges ────────────────────────────────────────────────────

static ROLLING_AVG_CPU: OnceLock<Gauge> = OnceLock::new();
static ROLLING_AVG_DB_POOL: OnceLock<Gauge> = OnceLock::new();
static ROLLING_AVG_REDIS: OnceLock<Gauge> = OnceLock::new();
static ROLLING_AVG_QUEUE_DEPTH: OnceLock<Gauge> = OnceLock::new();
static ROLLING_AVG_ERROR_RATE: OnceLock<Gauge> = OnceLock::new();
static ROLLING_AVG_P99_MS: OnceLock<Gauge> = OnceLock::new();

pub fn rolling_avg_cpu() -> &'static Gauge {
    ROLLING_AVG_CPU
        .get()
        .expect("adaptive rl metrics not initialised")
}
pub fn rolling_avg_db_pool() -> &'static Gauge {
    ROLLING_AVG_DB_POOL
        .get()
        .expect("adaptive rl metrics not initialised")
}
pub fn rolling_avg_redis() -> &'static Gauge {
    ROLLING_AVG_REDIS
        .get()
        .expect("adaptive rl metrics not initialised")
}
pub fn rolling_avg_queue_depth() -> &'static Gauge {
    ROLLING_AVG_QUEUE_DEPTH
        .get()
        .expect("adaptive rl metrics not initialised")
}
pub fn rolling_avg_error_rate() -> &'static Gauge {
    ROLLING_AVG_ERROR_RATE
        .get()
        .expect("adaptive rl metrics not initialised")
}
pub fn rolling_avg_p99_ms() -> &'static Gauge {
    ROLLING_AVG_P99_MS
        .get()
        .expect("adaptive rl metrics not initialised")
}

// ── Effective multiplier gauges ───────────────────────────────────────────────

static EFFECTIVE_MULTIPLIER: OnceLock<GaugeVec> = OnceLock::new();

pub fn effective_multiplier() -> &'static GaugeVec {
    EFFECTIVE_MULTIPLIER
        .get()
        .expect("adaptive rl metrics not initialised")
}

// ── Counters ──────────────────────────────────────────────────────────────────

static MODE_TRANSITIONS_TOTAL: OnceLock<CounterVec> = OnceLock::new();
static CONSUMER_THROTTLE_APPLICATIONS_TOTAL: OnceLock<CounterVec> = OnceLock::new();
static REQUEST_SHEDDING_TOTAL: OnceLock<CounterVec> = OnceLock::new();

pub fn mode_transitions_total() -> &'static CounterVec {
    MODE_TRANSITIONS_TOTAL
        .get()
        .expect("adaptive rl metrics not initialised")
}

pub fn consumer_throttle_applications_total() -> &'static CounterVec {
    CONSUMER_THROTTLE_APPLICATIONS_TOTAL
        .get()
        .expect("adaptive rl metrics not initialised")
}

pub fn request_shedding_total() -> &'static CounterVec {
    REQUEST_SHEDDING_TOTAL
        .get()
        .expect("adaptive rl metrics not initialised")
}

// ── Registration ─────────────────────────────────────────────────────────────

pub fn register(r: &Registry) {
    CURRENT_MODE
        .set(
            register_gauge_with_registry!(
                "aframp_adaptive_rl_current_mode",
                "Current adaptation mode (0=normal, 1=elevated, 2=critical, 3=emergency)",
                r
            )
            .unwrap(),
        )
        .ok();

    macro_rules! reg_gauge {
        ($cell:expr, $name:expr, $help:expr) => {
            $cell
                .set(register_gauge_with_registry!($name, $help, r).unwrap())
                .ok();
        };
    }

    reg_gauge!(
        SIGNAL_CPU,
        "aframp_adaptive_rl_signal_cpu_utilisation",
        "Current CPU utilisation [0,1]"
    );
    reg_gauge!(
        SIGNAL_DB_POOL,
        "aframp_adaptive_rl_signal_db_pool_utilisation",
        "Current DB pool utilisation [0,1]"
    );
    reg_gauge!(
        SIGNAL_REDIS_MEMORY,
        "aframp_adaptive_rl_signal_redis_memory_pressure",
        "Current Redis memory pressure [0,1]"
    );
    reg_gauge!(
        SIGNAL_QUEUE_DEPTH,
        "aframp_adaptive_rl_signal_request_queue_depth",
        "Current request queue depth"
    );
    reg_gauge!(
        SIGNAL_ERROR_RATE,
        "aframp_adaptive_rl_signal_error_rate",
        "Current error rate [0,1]"
    );
    reg_gauge!(
        SIGNAL_P99_MS,
        "aframp_adaptive_rl_signal_p99_response_time_ms",
        "Current p99 response time in ms"
    );

    reg_gauge!(
        ROLLING_AVG_CPU,
        "aframp_adaptive_rl_rolling_avg_cpu",
        "Rolling average CPU utilisation"
    );
    reg_gauge!(
        ROLLING_AVG_DB_POOL,
        "aframp_adaptive_rl_rolling_avg_db_pool",
        "Rolling average DB pool utilisation"
    );
    reg_gauge!(
        ROLLING_AVG_REDIS,
        "aframp_adaptive_rl_rolling_avg_redis_memory",
        "Rolling average Redis memory pressure"
    );
    reg_gauge!(
        ROLLING_AVG_QUEUE_DEPTH,
        "aframp_adaptive_rl_rolling_avg_queue_depth",
        "Rolling average request queue depth"
    );
    reg_gauge!(
        ROLLING_AVG_ERROR_RATE,
        "aframp_adaptive_rl_rolling_avg_error_rate",
        "Rolling average error rate"
    );
    reg_gauge!(
        ROLLING_AVG_P99_MS,
        "aframp_adaptive_rl_rolling_avg_p99_ms",
        "Rolling average p99 response time ms"
    );

    EFFECTIVE_MULTIPLIER
        .set(
            register_gauge_vec_with_registry!(
                "aframp_adaptive_rl_effective_multiplier",
                "Effective rate limit multiplier per consumer priority tier",
                &["tier"],
                r
            )
            .unwrap(),
        )
        .ok();

    MODE_TRANSITIONS_TOTAL
        .set(
            register_counter_vec_with_registry!(
                "aframp_adaptive_rl_mode_transitions_total",
                "Total adaptation mode transitions",
                &["from_mode", "to_mode"],
                r
            )
            .unwrap(),
        )
        .ok();

    CONSUMER_THROTTLE_APPLICATIONS_TOTAL
        .set(
            register_counter_vec_with_registry!(
                "aframp_adaptive_rl_consumer_throttle_applications_total",
                "Total per-consumer adaptive throttle applications",
                &["consumer_id", "mode"],
                r
            )
            .unwrap(),
        )
        .ok();

    REQUEST_SHEDDING_TOTAL
        .set(
            register_counter_vec_with_registry!(
                "aframp_adaptive_rl_request_shedding_total",
                "Total requests shed from the emergency queue",
                &["endpoint"],
                r
            )
            .unwrap(),
        )
        .ok();
}
