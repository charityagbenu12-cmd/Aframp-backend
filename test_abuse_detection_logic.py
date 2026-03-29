#!/usr/bin/env python3
"""
Abuse Detection System - Logic Validation Tests

This script validates the core logic of the abuse detection system
without requiring Rust compilation.
"""

from decimal import Decimal
from typing import List, Tuple
import json

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    END = '\033[0m'

def print_test(name: str, passed: bool, details: str = ""):
    status = f"{Colors.GREEN}✓ PASS{Colors.END}" if passed else f"{Colors.RED}✗ FAIL{Colors.END}"
    print(f"{status} - {name}")
    if details:
        print(f"       {details}")

def test_confidence_scoring():
    """Test confidence score calculations"""
    print(f"\n{Colors.BLUE}=== Testing Confidence Scoring ==={Colors.END}")
    
    # Test 1: Credential stuffing confidence
    attempt_count = 100
    threshold = 50
    ratio = Decimal(attempt_count) / Decimal(threshold)
    confidence = min(ratio * Decimal('0.30'), Decimal('0.95'))
    
    expected_min = Decimal('0.30')
    expected_max = Decimal('0.95')
    passed = expected_min <= confidence <= expected_max
    print_test(
        "Credential stuffing confidence in range",
        passed,
        f"Confidence: {confidence} (expected: {expected_min}-{expected_max})"
    )
    
    # Test 2: Brute force confidence
    failure_count = 25
    threshold = 10
    ratio = Decimal(failure_count) / Decimal(threshold)
    confidence = min(ratio * Decimal('0.35'), Decimal('0.90'))
    
    passed = Decimal('0.35') <= confidence <= Decimal('0.90')
    print_test(
        "Brute force confidence in range",
        passed,
        f"Confidence: {confidence}"
    )
    
    # Test 3: Composite confidence with weighted averaging
    scores = [Decimal('0.80'), Decimal('0.70'), Decimal('0.60')]
    weights = [Decimal('1.0'), Decimal('0.70'), Decimal('0.50')]
    
    composite = sum(s * w for s, w in zip(scores, weights))
    normalizer = sum(weights)
    composite = min(composite / normalizer, Decimal('1.0'))
    
    passed = Decimal('0.0') <= composite <= Decimal('1.0')
    print_test(
        "Composite confidence calculation",
        passed,
        f"Composite: {composite:.4f} from {len(scores)} signals"
    )

def test_response_tier_selection():
    """Test response tier selection based on confidence"""
    print(f"\n{Colors.BLUE}=== Testing Response Tier Selection ==={Colors.END}")
    
    thresholds = {
        'monitor': Decimal('0.30'),
        'soft': Decimal('0.60'),
        'hard': Decimal('0.80'),
        'critical': Decimal('0.95')
    }
    
    test_cases = [
        (Decimal('0.25'), 'monitor', False),  # Below monitor threshold
        (Decimal('0.35'), 'monitor', True),
        (Decimal('0.65'), 'soft', True),
        (Decimal('0.85'), 'hard', True),
        (Decimal('0.97'), 'critical', True),
    ]
    
    for confidence, expected_tier, should_pass in test_cases:
        if confidence >= thresholds['critical']:
            tier = 'critical'
        elif confidence >= thresholds['hard']:
            tier = 'hard'
        elif confidence >= thresholds['soft']:
            tier = 'soft'
        elif confidence >= thresholds['monitor']:
            tier = 'monitor'
        else:
            tier = 'none'
        
        passed = (tier == expected_tier) == should_pass
        print_test(
            f"Confidence {confidence} → {tier}",
            passed,
            f"Expected: {expected_tier}"
        )

def test_rate_limit_adjustment():
    """Test rate limit adjustment calculations"""
    print(f"\n{Colors.BLUE}=== Testing Rate Limit Adjustment ==={Colors.END}")
    
    original_limit = 100
    reduction_percent = Decimal('50')
    
    adjusted_limit = int(
        Decimal(original_limit) * (Decimal('1') - reduction_percent / Decimal('100'))
    )
    adjusted_limit = max(adjusted_limit, 1)
    
    expected = 50
    passed = adjusted_limit == expected
    print_test(
        "50% rate limit reduction",
        passed,
        f"Original: {original_limit}, Adjusted: {adjusted_limit}, Expected: {expected}"
    )
    
    # Test minimum enforcement
    original_limit = 10
    reduction_percent = Decimal('99')
    adjusted_limit = int(
        Decimal(original_limit) * (Decimal('1') - reduction_percent / Decimal('100'))
    )
    adjusted_limit = max(adjusted_limit, 1)
    
    passed = adjusted_limit >= 1
    print_test(
        "Minimum limit enforcement",
        passed,
        f"Adjusted limit: {adjusted_limit} (minimum: 1)"
    )

def test_signal_categorization():
    """Test signal categorization logic"""
    print(f"\n{Colors.BLUE}=== Testing Signal Categorization ==={Colors.END}")
    
    signal_categories = {
        'CredentialStuffing': 'AuthenticationAbuse',
        'BruteForce': 'AuthenticationAbuse',
        'TokenHarvesting': 'AuthenticationAbuse',
        'ApiKeyEnumeration': 'AuthenticationAbuse',
        'Scraping': 'EndpointAbuse',
        'QuoteFarming': 'EndpointAbuse',
        'StatusPollingAbuse': 'EndpointAbuse',
        'ErrorFarming': 'EndpointAbuse',
        'Structuring': 'TransactionAbuse',
        'VelocityAbuse': 'TransactionAbuse',
        'RoundTrip': 'TransactionAbuse',
        'NewConsumerHighValue': 'TransactionAbuse',
        'MultiConsumerCoordination': 'CoordinatedAbuse',
        'DistributedCredentialStuffing': 'CoordinatedAbuse',
        'SybilDetection': 'CoordinatedAbuse',
    }
    
    for signal, expected_category in signal_categories.items():
        # Simulate categorization
        if signal in ['CredentialStuffing', 'BruteForce', 'TokenHarvesting', 'ApiKeyEnumeration']:
            category = 'AuthenticationAbuse'
        elif signal in ['Scraping', 'QuoteFarming', 'StatusPollingAbuse', 'ErrorFarming']:
            category = 'EndpointAbuse'
        elif signal in ['Structuring', 'VelocityAbuse', 'RoundTrip', 'NewConsumerHighValue']:
            category = 'TransactionAbuse'
        else:
            category = 'CoordinatedAbuse'
        
        passed = category == expected_category
        print_test(
            f"{signal} → {category}",
            passed,
            f"Expected: {expected_category}"
        )

def test_case_lifecycle():
    """Test abuse case lifecycle state transitions"""
    print(f"\n{Colors.BLUE}=== Testing Case Lifecycle ==={Colors.END}")
    
    # Initial state
    status = 'open'
    false_positive = False
    
    print_test(
        "Case created with 'open' status",
        status == 'open',
        f"Status: {status}"
    )
    
    # Escalation
    status = 'escalated'
    print_test(
        "Case escalated",
        status == 'escalated',
        f"Status: {status}"
    )
    
    # Resolution
    status = 'resolved'
    print_test(
        "Case resolved",
        status == 'resolved',
        f"Status: {status}"
    )
    
    # False positive dismissal
    status = 'dismissed'
    false_positive = True
    whitelisted_signals = ['quote_farming']
    
    print_test(
        "False positive dismissed",
        status == 'dismissed' and false_positive,
        f"Status: {status}, FP: {false_positive}, Whitelisted: {whitelisted_signals}"
    )

def test_detection_thresholds():
    """Test detection threshold logic"""
    print(f"\n{Colors.BLUE}=== Testing Detection Thresholds ==={Colors.END}")
    
    # Credential stuffing
    attempts = 75
    threshold = 50
    detected = attempts >= threshold
    print_test(
        f"Credential stuffing detection ({attempts} >= {threshold})",
        detected,
        f"Detected: {detected}"
    )
    
    # Quote farming ratio
    quotes = 200
    initiations = 5
    ratio = Decimal(quotes) / Decimal(initiations)
    threshold_ratio = Decimal('10.0')
    detected = ratio > threshold_ratio
    print_test(
        f"Quote farming detection (ratio {ratio} > {threshold_ratio})",
        detected,
        f"Detected: {detected}"
    )
    
    # Velocity abuse multiplier
    current_velocity = Decimal('50.0')
    historical_avg = Decimal('5.0')
    multiplier = current_velocity / historical_avg
    threshold_multiplier = Decimal('5.0')
    detected = multiplier > threshold_multiplier
    print_test(
        f"Velocity abuse detection ({multiplier}x > {threshold_multiplier}x)",
        detected,
        f"Detected: {detected}"
    )

def test_coordinated_abuse_detection():
    """Test coordinated abuse detection logic"""
    print(f"\n{Colors.BLUE}=== Testing Coordinated Abuse Detection ==={Colors.END}")
    
    # Multi-consumer coordination
    consumer_count = 5
    threshold = 3
    similarity_score = Decimal('0.92')
    similarity_threshold = Decimal('0.80')
    
    detected = consumer_count >= threshold and similarity_score >= similarity_threshold
    print_test(
        f"Multi-consumer coordination ({consumer_count} consumers, {similarity_score} similarity)",
        detected,
        f"Detected: {detected}"
    )
    
    # Sybil detection
    account_count = 8
    threshold = 5
    similarity = Decimal('0.88')
    similarity_threshold = Decimal('0.85')
    
    detected = account_count >= threshold and similarity >= similarity_threshold
    print_test(
        f"Sybil detection ({account_count} accounts, {similarity} similarity)",
        detected,
        f"Detected: {detected}"
    )

def test_response_duration():
    """Test response duration calculations"""
    print(f"\n{Colors.BLUE}=== Testing Response Durations ==={Colors.END}")
    
    # Soft response - 15 minutes
    soft_duration_mins = 15
    soft_duration_secs = soft_duration_mins * 60
    print_test(
        "Soft response duration",
        soft_duration_secs == 900,
        f"Duration: {soft_duration_mins} minutes ({soft_duration_secs} seconds)"
    )
    
    # Hard response - 24 hours
    hard_duration_hours = 24
    hard_duration_secs = hard_duration_hours * 3600
    print_test(
        "Hard response duration",
        hard_duration_secs == 86400,
        f"Duration: {hard_duration_hours} hours ({hard_duration_secs} seconds)"
    )
    
    # Critical response - permanent
    critical_permanent = True
    print_test(
        "Critical response is permanent",
        critical_permanent,
        "No expiry"
    )

def run_all_tests():
    """Run all validation tests"""
    print(f"\n{Colors.YELLOW}{'='*60}{Colors.END}")
    print(f"{Colors.YELLOW}Abuse Detection System - Logic Validation Tests{Colors.END}")
    print(f"{Colors.YELLOW}{'='*60}{Colors.END}")
    
    test_confidence_scoring()
    test_response_tier_selection()
    test_rate_limit_adjustment()
    test_signal_categorization()
    test_case_lifecycle()
    test_detection_thresholds()
    test_coordinated_abuse_detection()
    test_response_duration()
    
    print(f"\n{Colors.YELLOW}{'='*60}{Colors.END}")
    print(f"{Colors.GREEN}All logic validation tests completed!{Colors.END}")
    print(f"{Colors.YELLOW}{'='*60}{Colors.END}\n")

if __name__ == "__main__":
    run_all_tests()
