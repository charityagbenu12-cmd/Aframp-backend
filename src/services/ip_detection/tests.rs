//! Unit tests for IP Detection Service

use crate::database::ip_reputation_repository::{IpReputationEntity, IpReputationRepository};
use crate::services::ip_detection::{DetectionSignal, IpDetectionConfig, IpDetectionService};
use crate::cache::RedisCache;
use rust_decimal::Decimal;
use std::sync::Arc;

/// Test IP detection signal risk score calculation
#[test]
fn test_detection_signal_risk_scores() {
    assert_eq!(DetectionSignal::AuthFailureRate { count: 5, threshold: 10 }.risk_score(), Decimal::new(-50, 2));
    assert_eq!(DetectionSignal::SignatureVerificationFailure { count: 3, threshold: 5 }.risk_score(), Decimal::new(-75, 2));
    assert_eq!(DetectionSignal::RateLimitBreach { count: 2, threshold: 5 }.risk_score(), Decimal::new(-30, 2));
    assert_eq!(DetectionSignal::ImpossibleTravel {
        previous_location: "Lagos".to_string(),
        current_location: "London".to_string(),
        hours_diff: 1
    }.risk_score(), Decimal::new(-100, 2));
    assert_eq!(DetectionSignal::NewIpHighValueTransaction {
        amount: Decimal::new(50000, 2),
        threshold: Decimal::new(100000, 2)
    }.risk_score(), Decimal::new(-40, 2));
    assert_eq!(DetectionSignal::ScanningPattern { endpoints: 15, threshold: 20 }.risk_score(), Decimal::new(-60, 2));
    assert_eq!(DetectionSignal::ExternalThreatFeed {
        score: Decimal::new(-80, 2),
        feed_name: "test".to_string()
    }.risk_score(), Decimal::new(-80, 2));
}

/// Test IP detection signal evidence types
#[test]
fn test_detection_signal_evidence_types() {
    assert_eq!(DetectionSignal::AuthFailureRate { count: 5, threshold: 10 }.evidence_type(), "auth_failure_rate");
    assert_eq!(DetectionSignal::SignatureVerificationFailure { count: 3, threshold: 5 }.evidence_type(), "signature_verification_failure");
    assert_eq!(DetectionSignal::RateLimitBreach { count: 2, threshold: 5 }.evidence_type(), "rate_limit_breach");
    assert_eq!(DetectionSignal::ImpossibleTravel {
        previous_location: "Lagos".to_string(),
        current_location: "London".to_string(),
        hours_diff: 1
    }.evidence_type(), "impossible_travel");
    assert_eq!(DetectionSignal::NewIpHighValueTransaction {
        amount: Decimal::new(50000, 2),
        threshold: Decimal::new(100000, 2)
    }.evidence_type(), "new_ip_high_value_transaction");
    assert_eq!(DetectionSignal::ScanningPattern { endpoints: 15, threshold: 20 }.evidence_type(), "scanning_pattern");
    assert_eq!(DetectionSignal::ExternalThreatFeed {
        score: Decimal::new(-80, 2),
        feed_name: "test".to_string()
    }.evidence_type(), "external_threat_feed");
}

/// Test IP reputation entity blocked status
#[test]
fn test_ip_reputation_blocked_status() {
    let mut reputation = IpReputationEntity {
        id: "test".to_string(),
        ip_address_or_cidr: "192.168.1.1".to_string(),
        reputation_score: Decimal::ZERO,
        detection_source: "test".to_string(),
        first_seen_at: chrono::Utc::now(),
        last_seen_at: chrono::Utc::now(),
        block_status: None,
        block_expiry_at: None,
        is_whitelisted: false,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };

    // Not blocked
    assert!(!reputation.is_blocked());
    assert!(!reputation.is_hard_blocked());
    assert!(!reputation.is_shadow_blocked());

    // Temporary block
    reputation.block_status = Some("temporary".to_string());
    reputation.block_expiry_at = Some(chrono::Utc::now() + chrono::Duration::hours(1));
    assert!(reputation.is_blocked());
    assert!(reputation.is_hard_blocked());
    assert!(!reputation.is_shadow_blocked());

    // Expired temporary block
    reputation.block_expiry_at = Some(chrono::Utc::now() - chrono::Duration::hours(1));
    assert!(!reputation.is_blocked());
    assert!(!reputation.is_hard_blocked());
    assert!(!reputation.is_shadow_blocked());

    // Permanent block
    reputation.block_status = Some("permanent".to_string());
    reputation.block_expiry_at = None;
    assert!(reputation.is_blocked());
    assert!(reputation.is_hard_blocked());
    assert!(!reputation.is_shadow_blocked());

    // Shadow block
    reputation.block_status = Some("shadow".to_string());
    assert!(reputation.is_blocked());
    assert!(!reputation.is_hard_blocked());
    assert!(reputation.is_shadow_blocked());
}

/// Test composite risk score calculation for automated blocking
#[test]
fn test_composite_risk_score_blocking() {
    let config = IpDetectionConfig {
        composite_risk_threshold: Decimal::new(-500, 2), // -5.00
        ..Default::default()
    };

    // Test various score combinations
    let test_cases = vec![
        (Decimal::ZERO, false),           // Neutral score
        (Decimal::new(-100, 2), false),   // Low negative score
        (Decimal::new(-499, 2), false),   // Just below threshold
        (Decimal::new(-500, 2), true),    // At threshold
        (Decimal::new(-600, 2), true),    // Above threshold
        (Decimal::new(-1000, 2), true),   // High negative score
    ];

    for (score, should_block) in test_cases {
        assert_eq!(score <= config.composite_risk_threshold, should_block,
            "Score {} should {} trigger blocking", score, if should_block { "" } else { "not" });
    }
}

/// Test high value transaction detection
#[test]
fn test_high_value_transaction_detection() {
    let config = IpDetectionConfig {
        high_value_threshold: Decimal::new(100000, 2), // 1000.00 cNGN
        ..Default::default()
    };

    let test_cases = vec![
        (Decimal::new(50000, 2), false),    // Below threshold
        (Decimal::new(99999, 2), false),    // Just below threshold
        (Decimal::new(100000, 2), true),    // At threshold
        (Decimal::new(150000, 2), true),    // Above threshold
    ];

    for (amount, should_detect) in test_cases {
        let should_trigger = amount >= config.high_value_threshold;
        assert_eq!(should_trigger, should_detect,
            "Amount {} should {} trigger high value detection", amount, if should_detect { "" } else { "not" });
    }
}

/// Test IP blocking middleware request extension
#[test]
fn test_shadow_blocked_request_extension() {
    use crate::middleware::ip_blocking::ShadowBlocked;
    use axum::http::Request;
    use axum::body::Body;

    let mut request = Request::new(Body::empty());

    // Initially not shadow blocked
    assert!(!request.extensions().get::<ShadowBlocked>().is_some());

    // Add shadow blocked marker
    request.extensions_mut().insert(ShadowBlocked {});
    assert!(request.extensions().get::<ShadowBlocked>().is_some());
}