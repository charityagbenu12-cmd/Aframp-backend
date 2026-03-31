//! Integration tests for abuse detection system

#[cfg(test)]
mod tests {
    use super::super::*;
    use chrono::Utc;
    use rust_decimal::Decimal;
    use uuid::Uuid;

    #[test]
    fn test_detection_signal_confidence_scoring() {
        let signal = signals::DetectionSignal::CredentialStuffing {
            consumer_id: Uuid::new_v4(),
            ip_address: "1.2.3.4".to_string(),
            attempt_count: 100,
            threshold: 50,
            window: signals::DetectionWindow::Short,
            varying_credentials: vec![],
        };

        let confidence = signal.confidence_score();
        assert!(confidence >= Decimal::new(30, 2)); // At least 0.30
        assert!(confidence <= Decimal::new(95, 2)); // At most 0.95
    }

    #[test]
    fn test_composite_confidence_calculation() {
        let signals = vec![
            signals::DetectionSignal::CredentialStuffing {
                consumer_id: Uuid::new_v4(),
                ip_address: "1.2.3.4".to_string(),
                attempt_count: 100,
                threshold: 50,
                window: signals::DetectionWindow::Short,
                varying_credentials: vec![],
            },
            signals::DetectionSignal::Scraping {
                consumer_id: Uuid::new_v4(),
                ip_address: "1.2.3.4".to_string(),
                distinct_resources: 150,
                threshold: 100,
                resource_type: "transactions".to_string(),
                window: signals::DetectionWindow::Short,
            },
        ];

        let result = signals::DetectionResult::new(signals, signals::DetectionWindow::Short);
        assert!(result.composite_confidence > Decimal::ZERO);
        assert!(result.composite_confidence <= Decimal::ONE);
    }

    #[test]
    fn test_response_tier_selection() {
        let tier = response::ResponseTier::from_confidence(
            Decimal::new(95, 2),
            Decimal::new(30, 2),
            Decimal::new(60, 2),
            Decimal::new(80, 2),
            Decimal::new(95, 2),
        );
        assert_eq!(tier, response::ResponseTier::Critical);

        let tier = response::ResponseTier::from_confidence(
            Decimal::new(70, 2),
            Decimal::new(30, 2),
            Decimal::new(60, 2),
            Decimal::new(80, 2),
            Decimal::new(95, 2),
        );
        assert_eq!(tier, response::ResponseTier::Soft);
    }

    #[test]
    fn test_abuse_case_lifecycle() {
        let consumer_id = Uuid::new_v4();
        let signal = signals::DetectionSignal::BruteForce {
            consumer_id: Some(consumer_id),
            ip_address: "1.2.3.4".to_string(),
            target_account: "test@example.com".to_string(),
            failure_count: 20,
            threshold: 10,
            window: signals::DetectionWindow::Short,
        };

        let mut case = case_management::AbuseCase::new(
            vec![consumer_id],
            vec![signal],
            Decimal::new(75, 2),
            response::ResponseTier::Soft,
        );

        assert_eq!(case.status, case_management::AbuseCaseStatus::Open);
        assert!(!case.false_positive);

        // Escalate
        let admin_id = Uuid::new_v4();
        case.escalate(admin_id, response::ResponseTier::Hard);
        assert_eq!(case.status, case_management::AbuseCaseStatus::Escalated);
        assert_eq!(case.response_tier, response::ResponseTier::Hard);

        // Resolve
        case.resolve(admin_id, "Confirmed abuse, consumer warned".to_string());
        assert_eq!(case.status, case_management::AbuseCaseStatus::Resolved);
        assert!(case.resolved_at.is_some());
    }

    #[test]
    fn test_abuse_case_dismissal() {
        let consumer_id = Uuid::new_v4();
        let signal = signals::DetectionSignal::QuoteFarming {
            consumer_id,
            quote_count: 60,
            initiation_count: 5,
            ratio: Decimal::new(120, 1),
            threshold: Decimal::new(100, 1),
            window: signals::DetectionWindow::Medium,
        };

        let mut case = case_management::AbuseCase::new(
            vec![consumer_id],
            vec![signal],
            Decimal::new(45, 2),
            response::ResponseTier::Monitor,
        );

        let admin_id = Uuid::new_v4();
        case.dismiss(
            admin_id,
            "Legitimate high-frequency trader".to_string(),
            vec!["quote_farming".to_string()],
        );

        assert_eq!(case.status, case_management::AbuseCaseStatus::Dismissed);
        assert!(case.false_positive);
        assert_eq!(case.whitelisted_signals.len(), 1);
    }

    #[test]
    fn test_rate_limit_adjustment() {
        let adjustment = response::RateLimitAdjustment::new(
            Uuid::new_v4(),
            100,
            Decimal::new(50, 0), // 50% reduction
            chrono::Duration::minutes(15),
        );

        assert_eq!(adjustment.adjusted_limit, 50);
        assert!(!adjustment.is_expired());
    }

    #[test]
    fn test_credential_suspension() {
        let suspension = response::CredentialSuspension::new(
            Uuid::new_v4(),
            vec![Uuid::new_v4()],
            vec!["jti_123".to_string()],
            response::ResponseTier::Hard,
            "Repeated abuse detected".to_string(),
            Some(chrono::Duration::hours(24)),
        );

        assert!(!suspension.is_expired());
        assert!(!suspension.is_permanent());
        assert!(suspension.appeal_url.is_some());
    }

    #[test]
    fn test_signal_categorization() {
        let auth_signal = signals::DetectionSignal::CredentialStuffing {
            consumer_id: Uuid::new_v4(),
            ip_address: "1.2.3.4".to_string(),
            attempt_count: 50,
            threshold: 50,
            window: signals::DetectionWindow::Short,
            varying_credentials: vec![],
        };
        assert_eq!(auth_signal.category(), signals::SignalCategory::AuthenticationAbuse);

        let endpoint_signal = signals::DetectionSignal::Scraping {
            consumer_id: Uuid::new_v4(),
            ip_address: "1.2.3.4".to_string(),
            distinct_resources: 100,
            threshold: 100,
            resource_type: "wallets".to_string(),
            window: signals::DetectionWindow::Short,
        };
        assert_eq!(endpoint_signal.category(), signals::SignalCategory::EndpointAbuse);

        let tx_signal = signals::DetectionSignal::Structuring {
            consumer_id: Uuid::new_v4(),
            transaction_count: 5,
            amounts: vec![],
            reporting_threshold: Decimal::new(10000, 2),
            proximity_percent: Decimal::new(5, 2),
            window: signals::DetectionWindow::Long,
        };
        assert_eq!(tx_signal.category(), signals::SignalCategory::TransactionAbuse);

        let coord_signal = signals::DetectionSignal::SybilDetection {
            consumer_ids: vec![Uuid::new_v4(), Uuid::new_v4()],
            similarity_score: Decimal::new(90, 2),
            similarity_factors: vec!["ip_address".to_string()],
            account_count: 5,
            threshold: 5,
        };
        assert_eq!(coord_signal.category(), signals::SignalCategory::CoordinatedAbuse);
    }

    #[test]
    fn test_detection_result_affected_consumers() {
        let consumer1 = Uuid::new_v4();
        let consumer2 = Uuid::new_v4();

        let signals = vec![
            signals::DetectionSignal::CredentialStuffing {
                consumer_id: consumer1,
                ip_address: "1.2.3.4".to_string(),
                attempt_count: 50,
                threshold: 50,
                window: signals::DetectionWindow::Short,
                varying_credentials: vec![],
            },
            signals::DetectionSignal::Scraping {
                consumer_id: consumer2,
                ip_address: "1.2.3.5".to_string(),
                distinct_resources: 100,
                threshold: 100,
                resource_type: "transactions".to_string(),
                window: signals::DetectionWindow::Short,
            },
        ];

        let result = signals::DetectionResult::new(signals, signals::DetectionWindow::Short);
        let affected = result.affected_consumers();

        assert_eq!(affected.len(), 2);
        assert!(affected.contains(&consumer1));
        assert!(affected.contains(&consumer2));
    }
}
