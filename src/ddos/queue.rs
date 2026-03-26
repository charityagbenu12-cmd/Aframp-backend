//! Fair queuing and WRED (Weighted Random Early Detection) for traffic shaping.
//!
//! Priority tiers:
//!   High     — verified partners, internal microservices, in-flight tx requests
//!   Standard — authenticated consumers
//!   Low      — unauthenticated / anonymous requests (shed first)

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use crate::ddos::config::DdosConfig;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PriorityTier {
    High = 2,
    Standard = 1,
    Low = 0,
}

impl std::fmt::Display for PriorityTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PriorityTier::High => write!(f, "high"),
            PriorityTier::Standard => write!(f, "standard"),
            PriorityTier::Low => write!(f, "low"),
        }
    }
}

/// Tracks slot usage per tier and enforces fair queuing.
pub struct FairQueue {
    config: Arc<DdosConfig>,
    high_in_use: AtomicU32,
    standard_in_use: AtomicU32,
    low_in_use: AtomicU32,
}

impl FairQueue {
    pub fn new(config: Arc<DdosConfig>) -> Arc<Self> {
        Arc::new(Self {
            config,
            high_in_use: AtomicU32::new(0),
            standard_in_use: AtomicU32::new(0),
            low_in_use: AtomicU32::new(0),
        })
    }

    /// Try to acquire a processing slot for the given tier.
    /// Returns true if the slot was granted, false if the request should be shed.
    pub fn try_acquire(&self, tier: PriorityTier) -> bool {
        let total_in_use = self.high_in_use.load(Ordering::Relaxed)
            + self.standard_in_use.load(Ordering::Relaxed)
            + self.low_in_use.load(Ordering::Relaxed);

        match tier {
            PriorityTier::High => {
                // High priority always gets its guaranteed minimum
                let in_use = self.high_in_use.load(Ordering::Relaxed);
                let limit = self.config.high_priority_min_slots
                    + (self.config.total_processing_slots - self.config.high_priority_min_slots - self.config.standard_priority_slots);
                if in_use < limit {
                    self.high_in_use.fetch_add(1, Ordering::Relaxed);
                    crate::ddos::metrics::queue_depth()
                        .with_label_values(&["high"])
                        .set(in_use as f64 + 1.0);
                    true
                } else {
                    false
                }
            }
            PriorityTier::Standard => {
                let in_use = self.standard_in_use.load(Ordering::Relaxed);
                // Standard gets proportional allocation from remaining slots
                let remaining = self.config.total_processing_slots.saturating_sub(
                    self.high_in_use.load(Ordering::Relaxed),
                );
                let limit = remaining.min(self.config.standard_priority_slots);
                if in_use < limit {
                    self.standard_in_use.fetch_add(1, Ordering::Relaxed);
                    crate::ddos::metrics::queue_depth()
                        .with_label_values(&["standard"])
                        .set(in_use as f64 + 1.0);
                    true
                } else {
                    false
                }
            }
            PriorityTier::Low => {
                // Low priority only gets leftover slots and is shed first
                if total_in_use >= self.config.total_processing_slots {
                    crate::ddos::metrics::dropped_requests()
                        .with_label_values(&["queue_full_low_priority"])
                        .inc();
                    return false;
                }
                let in_use = self.low_in_use.load(Ordering::Relaxed);
                let limit = self.config.total_processing_slots
                    .saturating_sub(self.config.high_priority_min_slots)
                    .saturating_sub(self.config.standard_priority_slots);
                if in_use < limit {
                    self.low_in_use.fetch_add(1, Ordering::Relaxed);
                    crate::ddos::metrics::queue_depth()
                        .with_label_values(&["low"])
                        .set(in_use as f64 + 1.0);
                    true
                } else {
                    crate::ddos::metrics::dropped_requests()
                        .with_label_values(&["queue_full_low_priority"])
                        .inc();
                    false
                }
            }
        }
    }

    pub fn release(&self, tier: PriorityTier) {
        match tier {
            PriorityTier::High => { self.high_in_use.fetch_sub(1, Ordering::Relaxed); }
            PriorityTier::Standard => { self.standard_in_use.fetch_sub(1, Ordering::Relaxed); }
            PriorityTier::Low => { self.low_in_use.fetch_sub(1, Ordering::Relaxed); }
        }
    }

    /// WRED drop probability for a given tier based on current queue fill.
    /// Returns a value 0.0–1.0; caller should drop if rand() < result.
    pub fn wred_drop_probability(&self, tier: PriorityTier) -> f64 {
        let total = self.config.total_processing_slots as f64;
        let in_use = (self.high_in_use.load(Ordering::Relaxed)
            + self.standard_in_use.load(Ordering::Relaxed)
            + self.low_in_use.load(Ordering::Relaxed)) as f64;
        let fill = in_use / total;

        let (low_thresh, high_thresh) = match tier {
            PriorityTier::High => (0.9, 1.0),     // only drop high-priority when nearly full
            PriorityTier::Standard => (self.config.wred_low_threshold, self.config.wred_high_threshold),
            PriorityTier::Low => (self.config.wred_low_threshold * 0.5, self.config.wred_high_threshold * 0.7),
        };

        if fill <= low_thresh {
            0.0
        } else if fill >= high_thresh {
            1.0
        } else {
            (fill - low_thresh) / (high_thresh - low_thresh)
        }
    }

    pub fn queue_stats(&self) -> QueueStats {
        QueueStats {
            high_in_use: self.high_in_use.load(Ordering::Relaxed),
            standard_in_use: self.standard_in_use.load(Ordering::Relaxed),
            low_in_use: self.low_in_use.load(Ordering::Relaxed),
            total_slots: self.config.total_processing_slots,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct QueueStats {
    pub high_in_use: u32,
    pub standard_in_use: u32,
    pub low_in_use: u32,
    pub total_slots: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> Arc<DdosConfig> {
        Arc::new(DdosConfig {
            total_processing_slots: 10,
            high_priority_min_slots: 3,
            standard_priority_slots: 5,
            wred_low_threshold: 0.5,
            wred_high_threshold: 0.9,
            ..DdosConfig::default()
        })
    }

    #[test]
    fn test_high_priority_always_gets_slots() {
        let q = FairQueue::new(test_config());
        // Fill up low and standard
        for _ in 0..5 { q.try_acquire(PriorityTier::Standard); }
        for _ in 0..2 { q.try_acquire(PriorityTier::Low); }
        // High priority should still get a slot
        assert!(q.try_acquire(PriorityTier::High));
    }

    #[test]
    fn test_low_priority_shed_first() {
        let q = FairQueue::new(test_config());
        // Fill all slots with high and standard
        for _ in 0..3 { q.try_acquire(PriorityTier::High); }
        for _ in 0..5 { q.try_acquire(PriorityTier::Standard); }
        for _ in 0..2 { q.try_acquire(PriorityTier::Low); }
        // Now queue is full — low priority should be rejected
        assert!(!q.try_acquire(PriorityTier::Low));
    }

    #[test]
    fn test_wred_drop_probability_zero_when_empty() {
        let q = FairQueue::new(test_config());
        assert_eq!(q.wred_drop_probability(PriorityTier::Low), 0.0);
        assert_eq!(q.wred_drop_probability(PriorityTier::Standard), 0.0);
    }

    #[test]
    fn test_wred_drop_probability_increases_with_fill() {
        let q = FairQueue::new(test_config());
        // Fill to 60% (6/10 slots)
        for _ in 0..6 { q.try_acquire(PriorityTier::Standard); }
        let p_low = q.wred_drop_probability(PriorityTier::Low);
        let p_std = q.wred_drop_probability(PriorityTier::Standard);
        assert!(p_low > 0.0, "low priority should have drop probability > 0 at 60% fill");
        assert!(p_std >= 0.0);
        assert!(p_low >= p_std, "low priority should have higher drop probability");
    }

    #[test]
    fn test_slot_release() {
        let q = FairQueue::new(test_config());
        assert!(q.try_acquire(PriorityTier::Standard));
        q.release(PriorityTier::Standard);
        let stats = q.queue_stats();
        assert_eq!(stats.standard_in_use, 0);
    }
}
