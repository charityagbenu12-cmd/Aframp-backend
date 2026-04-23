use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{error, warn};

use crate::dex_market_maker::config::{CIRCUIT_BREAKER_DRAIN_RATE, CIRCUIT_BREAKER_PAUSE_SECS};

/// Tracks reserve drain rate and trips the circuit breaker on toxic flow.
///
/// Toxic flow is detected when the bot's inventory drains faster than
/// `CIRCUIT_BREAKER_DRAIN_RATE` (fraction of starting inventory per minute),
/// which indicates arbitrageurs are systematically picking off stale quotes.
pub struct CircuitBreaker {
    tripped: AtomicBool,
    /// Unix timestamp (secs) when the breaker was tripped.
    tripped_at: AtomicU64,
    /// Inventory at the start of the current measurement window.
    window_start_inventory: Arc<std::sync::Mutex<f64>>,
    /// Unix timestamp (secs) when the measurement window started.
    window_start_ts: AtomicU64,
}

impl CircuitBreaker {
    pub fn new(initial_inventory: f64) -> Self {
        let now = now_secs();
        Self {
            tripped: AtomicBool::new(false),
            tripped_at: AtomicU64::new(0),
            window_start_inventory: Arc::new(std::sync::Mutex::new(initial_inventory)),
            window_start_ts: AtomicU64::new(now),
        }
    }

    pub fn is_tripped(&self) -> bool {
        if !self.tripped.load(Ordering::Acquire) {
            return false;
        }
        // Auto-reset after pause duration.
        let tripped_at = self.tripped_at.load(Ordering::Acquire);
        if now_secs().saturating_sub(tripped_at) >= CIRCUIT_BREAKER_PAUSE_SECS {
            self.reset();
            return false;
        }
        true
    }

    /// Called each cycle with the current cNGN inventory.
    /// Returns `true` if the breaker just tripped.
    pub fn check(&self, current_inventory: f64) -> bool {
        if self.is_tripped() {
            return false;
        }

        let now = now_secs();
        let window_start_ts = self.window_start_ts.load(Ordering::Acquire);
        let elapsed_secs = now.saturating_sub(window_start_ts);

        // Reset measurement window every 60 seconds.
        if elapsed_secs >= 60 {
            let mut inv = self.window_start_inventory.lock().unwrap();
            *inv = current_inventory;
            self.window_start_ts.store(now, Ordering::Release);
            return false;
        }

        let start_inv = *self.window_start_inventory.lock().unwrap();
        if start_inv <= 0.0 {
            return false;
        }

        let drain_fraction = (start_inv - current_inventory) / start_inv;
        let elapsed_mins = (elapsed_secs as f64 / 60.0).max(0.01);
        let drain_per_min = drain_fraction / elapsed_mins;

        if drain_per_min > CIRCUIT_BREAKER_DRAIN_RATE {
            self.trip();
            error!(
                drain_per_min,
                threshold = CIRCUIT_BREAKER_DRAIN_RATE,
                "Circuit breaker tripped: toxic flow / rapid reserve drain detected"
            );
            return true;
        }
        false
    }

    fn trip(&self) {
        self.tripped.store(true, Ordering::Release);
        self.tripped_at.store(now_secs(), Ordering::Release);
        warn!(
            "DEX market maker circuit breaker TRIPPED — pausing for {} seconds",
            CIRCUIT_BREAKER_PAUSE_SECS
        );
    }

    pub fn reset(&self) {
        self.tripped.store(false, Ordering::Release);
        self.tripped_at.store(0, Ordering::Release);
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
