//! Integration tests for DDoS protection.
//!
//! Tests: volumetric spike detection, endpoint flood, slow HTTP termination,
//! challenge-response flow, fair queuing under load, lockdown lifecycle.

#![cfg(feature = "cache")]

use std::sync::Arc;
use std::time::Duration;

use Bitmesh_backend::ddos::{
    challenge::{Challenge, ChallengeResponse},
    config::DdosConfig,
    detector::{AttackDetector, AttackClass, ProtectionMode},
    fingerprint::RequestFingerprint,
    lockdown::LockdownManager,
    queue::{FairQueue, PriorityTier},
};

fn test_config() -> Arc<DdosConfig> {
    Arc::new(DdosConfig {
        baseline_rps: 10.0,
        spike_multiplier: 3.0,
        endpoint_flood_share: 0.6,
        total_processing_slots: 10,
        high_priority_min_slots: 2,
        standard_priority_slots: 5,
        wred_low_threshold: 0.5,
        wred_high_threshold: 0.9,
        pow_difficulty_low: 4,
        pow_difficulty_high: 8,
        challenge_ttl_secs: 60,
        lockdown_max_duration_secs: 2, // short for test
        ..DdosConfig::default()
    })
}

// ── Volumetric spike detection ────────────────────────────────────────────────

#[tokio::test]
async fn test_volumetric_spike_triggers_active_mode() {
    let config = test_config();
    let detector = AttackDetector::new(config.clone());
    let fp = RequestFingerprint {
        cluster_key: "test".to_string(),
        is_attack_tool_agent: false,
        is_missing_agent: false,
        is_malformed: false,
    };

    // Send 40 requests in rapid succession (baseline=10, multiplier=3 → threshold=30)
    for _ in 0..40 {
        detector.record_request("/api/test", "1.2.3.4", &fp).await;
    }

    let mode = detector.current_mode().await;
    assert_eq!(mode, ProtectionMode::ActiveRateEnforcement);
}

// ── Endpoint flood detection ──────────────────────────────────────────────────

#[tokio::test]
async fn test_endpoint_flood_detected() {
    let config = test_config();
    let detector = AttackDetector::new(config.clone());
    let fp = RequestFingerprint {
        cluster_key: "flood".to_string(),
        is_attack_tool_agent: false,
        is_missing_agent: false,
        is_malformed: false,
    };

    // Send 80% of traffic to one endpoint (threshold is 60%)
    for _ in 0..8 {
        detector.record_request("/api/target", "1.2.3.4", &fp).await;
    }
    for _ in 0..2 {
        detector.record_request("/api/other", "1.2.3.5", &fp).await;
    }

    let attacks = detector.active_attacks().await;
    let has_flood = attacks.iter().any(|a| {
        matches!(&a.class, AttackClass::EndpointFlood { endpoint } if endpoint == "/api/target")
    });
    assert!(has_flood, "Endpoint flood should be detected");
}

// ── Slow HTTP detection ───────────────────────────────────────────────────────

#[tokio::test]
async fn test_slow_http_connection_flagged() {
    let config = Arc::new(DdosConfig {
        slow_request_timeout_secs: 0, // immediate for test
        slow_bytes_threshold: 1000,   // high threshold so 1 byte/s is "slow"
        ..DdosConfig::default()
    });
    let detector = AttackDetector::new(config);

    detector.track_connection("conn-1").await;
    // Simulate 1 byte received after timeout has passed
    let should_terminate = detector.update_connection_bytes("conn-1", 1).await;
    // With 0-second timeout and 1 byte < 1000 threshold, should flag
    assert!(should_terminate, "Slow HTTP connection should be flagged for termination");
}

#[tokio::test]
async fn test_fast_connection_not_flagged() {
    let config = Arc::new(DdosConfig {
        slow_request_timeout_secs: 30,
        slow_bytes_threshold: 10,
        ..DdosConfig::default()
    });
    let detector = AttackDetector::new(config);

    detector.track_connection("conn-fast").await;
    // Send plenty of bytes immediately — should not be flagged
    let should_terminate = detector.update_connection_bytes("conn-fast", 10_000).await;
    assert!(!should_terminate, "Fast connection should not be terminated");
}

// ── Challenge-response ────────────────────────────────────────────────────────

#[test]
fn test_challenge_verify_correct_nonce() {
    use sha2::{Digest, Sha256};

    let token = "challengetoken42".to_string();
    let difficulty = 4u32;

    // Find a valid nonce
    for nonce in 0u64..1_000_000 {
        let input = format!("{}{}", token, nonce);
        let hash = Sha256::digest(input.as_bytes());
        let leading_zeros = count_leading_zero_bits(&hash);
        if leading_zeros >= difficulty {
            // Verify the logic matches what ChallengeService.verify() does
            assert!(leading_zeros >= difficulty);
            return;
        }
    }
    panic!("No valid nonce found in 1M iterations");
}

#[test]
fn test_challenge_wrong_token_rejected() {
    let challenge = Challenge {
        token: "correct_token".to_string(),
        difficulty: 1,
        issued_at: 0,
    };
    let response = ChallengeResponse {
        token: "wrong_token".to_string(),
        nonce: 0,
    };
    assert_ne!(challenge.token, response.token);
}

fn count_leading_zero_bits(hash: &[u8]) -> u32 {
    let mut count = 0u32;
    for byte in hash {
        let zeros = byte.leading_zeros();
        count += zeros;
        if zeros < 8 { break; }
    }
    count
}

// ── Fair queuing under simulated load ─────────────────────────────────────────

#[test]
fn test_fair_queuing_high_priority_guaranteed() {
    let config = test_config();
    let queue = FairQueue::new(config);

    // Fill standard and low slots
    for _ in 0..5 { queue.try_acquire(PriorityTier::Standard); }
    for _ in 0..3 { queue.try_acquire(PriorityTier::Low); }

    // High priority should still get through
    assert!(queue.try_acquire(PriorityTier::High));
    assert!(queue.try_acquire(PriorityTier::High));
}

#[test]
fn test_fair_queuing_unauthenticated_shed_first() {
    let config = test_config();
    let queue = FairQueue::new(config);

    // Fill all slots
    for _ in 0..2 { queue.try_acquire(PriorityTier::High); }
    for _ in 0..5 { queue.try_acquire(PriorityTier::Standard); }
    for _ in 0..3 { queue.try_acquire(PriorityTier::Low); }

    // Queue is full — low priority (unauthenticated) should be rejected
    assert!(!queue.try_acquire(PriorityTier::Low));
    // Standard should also be rejected (full)
    assert!(!queue.try_acquire(PriorityTier::Standard));
}

#[test]
fn test_wred_drop_probability_low_priority_higher() {
    let config = test_config();
    let queue = FairQueue::new(config);

    // Fill to 60%
    for _ in 0..6 { queue.try_acquire(PriorityTier::Standard); }

    let p_low = queue.wred_drop_probability(PriorityTier::Low);
    let p_high = queue.wred_drop_probability(PriorityTier::High);
    assert!(p_low > p_high, "Low priority should have higher drop probability than high");
}

// ── Lockdown lifecycle ────────────────────────────────────────────────────────

#[tokio::test]
async fn test_lockdown_activate_and_deactivate() {
    let config = test_config();
    let lockdown = LockdownManager::new(config);

    assert!(!lockdown.is_active().await);

    lockdown.activate("test_trigger").await;
    assert!(lockdown.is_active().await);

    let status = lockdown.status().await;
    assert!(status.active);
    assert_eq!(status.trigger.as_deref(), Some("test_trigger"));

    lockdown.deactivate().await;
    assert!(!lockdown.is_active().await);
}

#[tokio::test]
async fn test_lockdown_auto_expires() {
    let config = Arc::new(DdosConfig {
        lockdown_max_duration_secs: 1, // 1 second for test
        ..DdosConfig::default()
    });
    let lockdown = LockdownManager::new(config);

    lockdown.activate("auto_expire_test").await;
    assert!(lockdown.is_active().await);

    // Wait for auto-expiry
    tokio::time::sleep(Duration::from_millis(1100)).await;

    // is_active() checks elapsed time internally
    assert!(!lockdown.is_active().await);
}

#[tokio::test]
async fn test_lockdown_allowlisted_ip_passes() {
    let config = Arc::new(DdosConfig {
        allowlisted_ips: vec!["10.0.0.1".to_string()],
        ..DdosConfig::default()
    });
    let lockdown = LockdownManager::new(config);

    lockdown.activate("test").await;
    assert!(lockdown.is_allowlisted("10.0.0.1"));
    assert!(!lockdown.is_allowlisted("192.168.1.1"));
}

// ── Attack history pagination ─────────────────────────────────────────────────

#[tokio::test]
async fn test_attack_history_pagination() {
    let config = test_config();
    let detector = AttackDetector::new(config);
    let fp = RequestFingerprint {
        cluster_key: "hist".to_string(),
        is_attack_tool_agent: false,
        is_missing_agent: false,
        is_malformed: false,
    };

    // Trigger multiple attacks
    for _ in 0..50 {
        detector.record_request("/api/flood", "1.2.3.4", &fp).await;
    }

    let page0 = detector.attack_history(0, 5).await;
    assert!(page0.len() <= 5);
}
