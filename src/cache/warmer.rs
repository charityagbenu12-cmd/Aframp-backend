//! Cache warming — pre-populates L1 and L2 caches at startup.
//!
//! The application readiness gate must not return healthy until warming completes.
//! Warming duration and entry counts are logged as structured events.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;
use tracing::{error, info, warn};

use crate::cache::l1::L1Cache;
use crate::cache::cache::{Cache as CacheTrait, RedisCache};
use crate::cache::cache::ttl;
use crate::database::exchange_rate_repository::ExchangeRateRepository;
use crate::database::fee_structure_repository::FeeStructureRepository;

/// Shared flag indicating whether cache warming has completed.
#[derive(Clone)]
pub struct WarmingState {
    pub ready: Arc<AtomicBool>,
}

impl WarmingState {
    pub fn new() -> Self {
        Self {
            ready: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }

    pub fn mark_ready(&self) {
        self.ready.store(true, Ordering::Release);
    }
}

/// Known currency pairs to pre-warm in L2.
/// Extend this list as new pairs are added to the platform.
const CURRENCY_PAIRS: &[(&str, &str)] = &[
    ("CNGN", "USD"),
    ("CNGN", "EUR"),
    ("CNGN", "GBP"),
    ("CNGN", "KES"),
    ("CNGN", "GHS"),
    ("CNGN", "ZAR"),
    ("CNGN", "XOF"),
    ("USD", "CNGN"),
];

/// Known fee types to pre-warm in L1.
const FEE_TYPES: &[&str] = &[
    "onramp",
    "offramp",
    "transfer",
    "conversion",
    "withdrawal",
];

/// Warm both cache levels. Called once at startup before traffic is accepted.
pub async fn warm_caches(
    l1: &L1Cache,
    redis: &RedisCache,
    rate_repo: &ExchangeRateRepository,
    fee_repo: &FeeStructureRepository,
    warming_state: &WarmingState,
) {
    let start = Instant::now();
    info!("🔥 Starting cache warming...");

    let mut total_l1 = 0usize;
    let mut total_l2 = 0usize;

    // --- L1: fee structures ---
    for fee_type in FEE_TYPES {
        match fee_repo.get_active_by_type(fee_type, None).await {
            Ok(structures) if !structures.is_empty() => {
                let key = format!("v1:fee:structure:{}", fee_type);
                l1.fee_structures.insert(key, &structures).await;
                total_l1 += 1;
                info!(fee_type, count = structures.len(), "L1 warmed fee structures");
            }
            Ok(_) => {
                debug!(fee_type, "No active fee structures found during warming");
            }
            Err(e) => {
                warn!(fee_type, error = %e, "Failed to warm fee structures for type");
            }
        }
    }

    // --- L2: exchange rates for all known currency pairs ---
    for (from, to) in CURRENCY_PAIRS {
        let key = format!("v1:rate:{}:{}", from, to);
        match rate_repo.get_current_rate(from, to).await {
            Ok(Some(rate)) => {
                if let Err(e) = redis
                    .set(&key, &rate, Some(ttl::EXCHANGE_RATES))
                    .await
                {
                    warn!(from, to, error = %e, "Failed to warm L2 exchange rate");
                } else {
                    total_l2 += 1;
                    info!(from, to, "L2 warmed exchange rate");
                }
            }
            Ok(None) => {
                debug!(from, to, "No exchange rate found during warming");
            }
            Err(e) => {
                warn!(from, to, error = %e, "Failed to fetch exchange rate for warming");
            }
        }
    }

    let elapsed = start.elapsed();
    info!(
        elapsed_ms = elapsed.as_millis(),
        l1_entries = total_l1,
        l2_entries = total_l2,
        "✅ Cache warming complete"
    );

    warming_state.mark_ready();
}

// Allow dead_code for the debug macro used in non-debug builds
#[allow(unused_imports)]
use tracing::debug;
