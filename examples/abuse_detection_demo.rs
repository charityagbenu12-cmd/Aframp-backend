//! Abuse Detection System Demo
//!
//! This example demonstrates the comprehensive abuse detection and automated
//! response system, showing how to:
//! - Detect various abuse patterns
//! - Calculate confidence scores
//! - Apply automated responses
//! - Manage abuse cases

use aframp::abuse_detection::{
    config::AbuseDetectionConfig,
    detector::AbuseDetector,
    signals::{DetectionSignal, DetectionWindow},
    response::{ResponseTier, ResponseAction},
    case_management::{AbuseCase, AbuseCaseStatus},
};
use aframp::cache::RedisCache;
use chrono::Utc;
use rust_decimal::Decimal;
use std::sync::Arc;
use uuid::Uuid;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Abuse Detection System Demo ===\n");

    // Initialize configuration
    let config = Arc::new(AbuseDetectionConfig::default());
    println!("✓ Loaded abuse detection configuration");
    println!("  - Credential stuffing threshold: {}", config.credential_stuffing_threshold);
    println!("  - Soft response confidence: {}", config.soft_response_confidence_threshold);
    println!("  - Hard response confidence: {}", config.hard_response_confidence_threshold);
    println!("  - Critical response confidence: {}\n", config.critical_response_confidence_threshold);

    // Demo 1: Authentication Abuse Detection
    println!("--- Demo 1: Authentication Abuse Detection ---");
    demo_authentication_abuse();

    // Demo 2: Endpoint Abuse Detection
    println!("\n--- Demo 2: Endpoint Abuse Detection ---");
    demo_endpoint_abuse();

    // Demo 3: Transaction Abuse Detection
    println!("\n--- Demo 3: Transaction Abuse Detection ---");
    demo_transaction_abuse();

    // Demo 4: Coordinated Abuse Detection
    println!("\n--- Demo 4: Coordinated Abuse Detection ---");
    demo_coordinated_abuse();

    // Demo 5: Confidence Scoring and Response Selection
    println!("\n--- Demo 5: Confidence Scoring and Response Selection ---");
    demo_confidence_scoring();

    // Demo 6: Abuse Case Management
    println!("\n--- Demo 6: Abuse Case Management ---");
    demo_case_management();

    println!("\n=== Demo Complete ===");
    Ok(())
}

fn demo_authentication_abuse() {
    let consumer_id = Uuid::new_v4();
    let ip_address = "192.168.1.100";

    // Credential stuffing detection
    let signal = DetectionSignal::CredentialStuffing {
        consumer_id,
        ip_address: ip_address.to_string(),
        attempt_count: 75,
        threshold: 50,
        window: DetectionWindow::Short,
        varying_credentials: vec![
            "user1@***".to_string(),
            "user2@***".to_string(),
            "user3@***".to_string(),
        ],
    };

    println!("Detected: {}", signal.description());
    println!("Confidence: {}", signal.confidence_score());
    println!("Category: {:?}", signal.category());

    // Brute force detection
    let signal = DetectionSignal::BruteForce {
        consumer_id: Some(consumer_id),
        ip_address: ip_address.to_string(),
        target_account: "admin@***".to_string(),
        failure_count: 15,
        threshold: 10,
        window: DetectionWindow::Short,
    };

    println!("\nDetected: {}", signal.description());
    println!("Confidence: {}", signal.confidence_score());

    // Token harvesting detection
    let signal = DetectionSignal::TokenHarvesting {
        consumer_id,
        issuance_count: 150,
        usage_count: 10,
        ratio: Decimal::new(150, 1), // 15.0
        threshold: Decimal::new(50, 1), // 5.0
        window: DetectionWindow::Medium,
    };

    println!("\nDetected: {}", signal.description());
    println!("Confidence: {}", signal.confidence_score());
}

fn demo_endpoint_abuse() {
    let consumer_id = Uuid::new_v4();
    let ip_address = "10.0.0.50";

    // Scraping detection
    let signal = DetectionSignal::Scraping {
        consumer_id,
        ip_address: ip_address.to_string(),
        distinct_resources: 250,
        threshold: 100,
        resource_type: "transaction_ids".to_string(),
        window: DetectionWindow::Short,
    };

    println!("Detected: {}", signal.description());
    println!("Confidence: {}", signal.confidence_score());

    // Quote farming detection
    let signal = DetectionSignal::QuoteFarming {
        consumer_id,
        quote_count: 200,
        initiation_count: 5,
        ratio: Decimal::new(400, 1), // 40.0
        threshold: Decimal::new(100, 1), // 10.0
        window: DetectionWindow::Medium,
    };

    println!("\nDetected: {}", signal.description());
    println!("Confidence: {}", signal.confidence_score());

    // Status polling abuse
    let signal = DetectionSignal::StatusPollingAbuse {
        consumer_id,
        transaction_id: Uuid::new_v4(),
        poll_count: 150,
        frequency: Decimal::new(25, 1), // 2.5 req/sec
        threshold: 100,
        window: DetectionWindow::Short,
    };

    println!("\nDetected: {}", signal.description());
    println!("Confidence: {}", signal.confidence_score());

    // Error farming detection
    let signal = DetectionSignal::ErrorFarming {
        consumer_id,
        ip_address: ip_address.to_string(),
        error_count: 80,
        total_requests: 100,
        error_rate: Decimal::new(80, 2), // 0.80
        threshold: Decimal::new(50, 2), // 0.50
        window: DetectionWindow::Short,
    };

    println!("\nDetected: {}", signal.description());
    println!("Confidence: {}", signal.confidence_score());
}

fn demo_transaction_abuse() {
    let consumer_id = Uuid::new_v4();

    // Structuring detection
    let signal = DetectionSignal::Structuring {
        consumer_id,
        transaction_count: 7,
        amounts: vec![
            Decimal::new(9500, 2),
            Decimal::new(9600, 2),
            Decimal::new(9550, 2),
        ],
        reporting_threshold: Decimal::new(10000, 2),
        proximity_percent: Decimal::new(5, 2),
        window: DetectionWindow::Long,
    };

    println!("Detected: {}", signal.description());
    println!("Confidence: {}", signal.confidence_score());

    // Velocity abuse detection
    let signal = DetectionSignal::VelocityAbuse {
        consumer_id,
        current_velocity: Decimal::new(500, 1), // 50.0 tx/hour
        historical_average: Decimal::new(50, 1), // 5.0 tx/hour
        multiplier: Decimal::new(100, 1), // 10.0x
        threshold: Decimal::new(50, 1), // 5.0x
        window: DetectionWindow::Medium,
    };

    println!("\nDetected: {}", signal.description());
    println!("Confidence: {}", signal.confidence_score());

    // Round-trip detection
    let signal = DetectionSignal::RoundTrip {
        consumer_id,
        onramp_tx_id: Uuid::new_v4(),
        offramp_tx_id: Uuid::new_v4(),
        amount_similarity: Decimal::new(98, 2), // 0.98
        time_diff_secs: 300, // 5 minutes
        window: DetectionWindow::Medium,
    };

    println!("\nDetected: {}", signal.description());
    println!("Confidence: {}", signal.confidence_score());

    // New consumer high value
    let signal = DetectionSignal::NewConsumerHighValue {
        consumer_id,
        account_age_hours: 2,
        transaction_amount: Decimal::new(500000, 2), // 5000.00
        threshold: Decimal::new(100000, 2), // 1000.00
    };

    println!("\nDetected: {}", signal.description());
    println!("Confidence: {}", signal.confidence_score());
}

fn demo_coordinated_abuse() {
    let consumer_ids = vec![Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4()];

    // Multi-consumer coordination
    let signal = DetectionSignal::MultiConsumerCoordination {
        consumer_ids: consumer_ids.clone(),
        correlation_type: "same_ip_and_timing".to_string(),
        similarity_score: Decimal::new(92, 2), // 0.92
        evidence: serde_json::json!({
            "shared_ip": "203.0.113.50",
            "timing_correlation": 0.95,
            "amount_pattern": "identical"
        }),
        window: DetectionWindow::Medium,
    };

    println!("Detected: {}", signal.description());
    println!("Confidence: {}", signal.confidence_score());

    // Distributed credential stuffing
    let signal = DetectionSignal::DistributedCredentialStuffing {
        consumer_ids: consumer_ids.clone(),
        ip_addresses: vec![
            "192.168.1.10".to_string(),
            "192.168.1.11".to_string(),
            "192.168.1.12".to_string(),
        ],
        total_attempts: 250,
        threshold: 100,
        window: DetectionWindow::Medium,
    };

    println!("\nDetected: {}", signal.description());
    println!("Confidence: {}", signal.confidence_score());

    // Sybil detection
    let signal = DetectionSignal::SybilDetection {
        consumer_ids: vec![Uuid::new_v4(); 8],
        similarity_score: Decimal::new(88, 2), // 0.88
        similarity_factors: vec![
            "registration_ip".to_string(),
            "device_fingerprint".to_string(),
            "transaction_patterns".to_string(),
        ],
        account_count: 8,
        threshold: 5,
    };

    println!("\nDetected: {}", signal.description());
    println!("Confidence: {}", signal.confidence_score());
}

fn demo_confidence_scoring() {
    let consumer_id = Uuid::new_v4();

    // Low confidence - Monitor tier
    let signals = vec![DetectionSignal::StatusPollingAbuse {
        consumer_id,
        transaction_id: Uuid::new_v4(),
        poll_count: 60,
        frequency: Decimal::new(10, 1),
        threshold: 100,
        window: DetectionWindow::Short,
    }];

    let result = aframp::abuse_detection::signals::DetectionResult::new(
        signals,
        DetectionWindow::Short,
    );
    println!("Single signal confidence: {}", result.composite_confidence);
    let tier = ResponseTier::from_confidence(
        result.composite_confidence,
        Decimal::new(30, 2),
        Decimal::new(60, 2),
        Decimal::new(80, 2),
        Decimal::new(95, 2),
    );
    println!("Response tier: {:?}\n", tier);

    // Medium confidence - Soft tier
    let signals = vec![
        DetectionSignal::QuoteFarming {
            consumer_id,
            quote_count: 100,
            initiation_count: 5,
            ratio: Decimal::new(200, 1),
            threshold: Decimal::new(100, 1),
            window: DetectionWindow::Medium,
        },
        DetectionSignal::Scraping {
            consumer_id,
            ip_address: "10.0.0.1".to_string(),
            distinct_resources: 150,
            threshold: 100,
            resource_type: "wallets".to_string(),
            window: DetectionWindow::Short,
        },
    ];

    let result = aframp::abuse_detection::signals::DetectionResult::new(
        signals,
        DetectionWindow::Medium,
    );
    println!("Two signals confidence: {}", result.composite_confidence);
    let tier = ResponseTier::from_confidence(
        result.composite_confidence,
        Decimal::new(30, 2),
        Decimal::new(60, 2),
        Decimal::new(80, 2),
        Decimal::new(95, 2),
    );
    println!("Response tier: {:?}\n", tier);

    // High confidence - Hard tier
    let signals = vec![
        DetectionSignal::CredentialStuffing {
            consumer_id,
            ip_address: "192.168.1.1".to_string(),
            attempt_count: 150,
            threshold: 50,
            window: DetectionWindow::Short,
            varying_credentials: vec![],
        },
        DetectionSignal::BruteForce {
            consumer_id: Some(consumer_id),
            ip_address: "192.168.1.1".to_string(),
            target_account: "admin@***".to_string(),
            failure_count: 25,
            threshold: 10,
            window: DetectionWindow::Short,
        },
        DetectionSignal::ApiKeyEnumeration {
            ip_address: "192.168.1.1".to_string(),
            invalid_key_count: 50,
            unique_prefix_count: 20,
            threshold: 20,
            window: DetectionWindow::Short,
        },
    ];

    let result = aframp::abuse_detection::signals::DetectionResult::new(
        signals,
        DetectionWindow::Short,
    );
    println!("Three signals confidence: {}", result.composite_confidence);
    let tier = ResponseTier::from_confidence(
        result.composite_confidence,
        Decimal::new(30, 2),
        Decimal::new(60, 2),
        Decimal::new(80, 2),
        Decimal::new(95, 2),
    );
    println!("Response tier: {:?}\n", tier);

    // Critical confidence - Critical tier
    let signals = vec![
        DetectionSignal::MultiConsumerCoordination {
            consumer_ids: vec![Uuid::new_v4(); 5],
            correlation_type: "coordinated_attack".to_string(),
            similarity_score: Decimal::new(95, 2),
            evidence: serde_json::json!({}),
            window: DetectionWindow::Medium,
        },
        DetectionSignal::DistributedCredentialStuffing {
            consumer_ids: vec![Uuid::new_v4(); 10],
            ip_addresses: vec!["10.0.0.1".to_string(); 10],
            total_attempts: 500,
            threshold: 100,
            window: DetectionWindow::Medium,
        },
    ];

    let result = aframp::abuse_detection::signals::DetectionResult::new(
        signals,
        DetectionWindow::Medium,
    );
    println!("Coordinated attack confidence: {}", result.composite_confidence);
    let tier = ResponseTier::from_confidence(
        result.composite_confidence,
        Decimal::new(30, 2),
        Decimal::new(60, 2),
        Decimal::new(80, 2),
        Decimal::new(95, 2),
    );
    println!("Response tier: {:?}", tier);
}

fn demo_case_management() {
    let consumer_id = Uuid::new_v4();
    let admin_id = Uuid::new_v4();

    // Create an abuse case
    let signal = DetectionSignal::VelocityAbuse {
        consumer_id,
        current_velocity: Decimal::new(300, 1),
        historical_average: Decimal::new(50, 1),
        multiplier: Decimal::new(60, 1),
        threshold: Decimal::new(50, 1),
        window: DetectionWindow::Medium,
    };

    let mut case = AbuseCase::new(
        vec![consumer_id],
        vec![signal],
        Decimal::new(75, 2),
        ResponseTier::Soft,
    );

    println!("Created abuse case:");
    println!("  ID: {}", case.id);
    println!("  Status: {:?}", case.status);
    println!("  Confidence: {}", case.composite_confidence);
    println!("  Response tier: {:?}", case.response_tier);

    // Escalate the case
    case.escalate(admin_id, ResponseTier::Hard);
    println!("\nEscalated case:");
    println!("  Status: {:?}", case.status);
    println!("  New tier: {:?}", case.response_tier);
    println!("  Escalated by: {}", case.escalated_by.unwrap());

    // Resolve the case
    case.resolve(admin_id, "Confirmed abuse. Consumer warned and monitored.".to_string());
    println!("\nResolved case:");
    println!("  Status: {:?}", case.status);
    println!("  Resolved at: {}", case.resolved_at.unwrap());
    println!("  Resolution: {}", case.resolution_notes.as_ref().unwrap());

    // Demo false positive dismissal
    let mut fp_case = AbuseCase::new(
        vec![consumer_id],
        vec![DetectionSignal::QuoteFarming {
            consumer_id,
            quote_count: 60,
            initiation_count: 5,
            ratio: Decimal::new(120, 1),
            threshold: Decimal::new(100, 1),
            window: DetectionWindow::Medium,
        }],
        Decimal::new(45, 2),
        ResponseTier::Monitor,
    );

    fp_case.dismiss(
        admin_id,
        "Legitimate high-frequency trading pattern".to_string(),
        vec!["quote_farming".to_string()],
    );

    println!("\nDismissed false positive:");
    println!("  Status: {:?}", fp_case.status);
    println!("  False positive: {}", fp_case.false_positive);
    println!("  Whitelisted signals: {:?}", fp_case.whitelisted_signals);
}
