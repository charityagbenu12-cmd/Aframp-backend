/// Integration tests for wallet registration, auth, backup, recovery, and history flows.
/// These tests require a running database (DATABASE_URL env var).
#[cfg(test)]
#[cfg(feature = "integration")]
mod wallet_integration_tests {
    use sqlx::PgPool;
    use std::sync::Arc;
    use uuid::Uuid;

    async fn test_pool() -> PgPool {
        let url = std::env::var("DATABASE_URL").expect("DATABASE_URL required for integration tests");
        PgPool::connect(&url).await.expect("DB connect failed")
    }

    // ── Wallet Registration ──────────────────────────────────────────────────

    #[tokio::test]
    async fn test_wallet_registration_and_lookup() {
        use crate::wallet::repository::WalletRegistryRepository;
        let pool = test_pool().await;
        let repo = WalletRegistryRepository::new(pool);
        let user_id = Uuid::new_v4();
        // Use a syntactically valid-looking key for DB storage (real sig verification is unit-tested)
        let pubkey = format!("G{}", "A".repeat(55));
        let wallet = repo.create(user_id, &pubkey, Some("Test Wallet"), "personal", Some("127.0.0.1"), 0).await;
        assert!(wallet.is_ok());
        let w = wallet.unwrap();
        assert_eq!(w.stellar_public_key, pubkey);
        assert_eq!(w.wallet_type, "personal");

        let found = repo.find_by_public_key(&pubkey).await.unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().id, w.id);
    }

    #[tokio::test]
    async fn test_duplicate_pubkey_rejected() {
        use crate::wallet::repository::WalletRegistryRepository;
        let pool = test_pool().await;
        let repo = WalletRegistryRepository::new(pool);
        let user_id = Uuid::new_v4();
        let pubkey = format!("G{}", "B".repeat(55));
        let _ = repo.create(user_id, &pubkey, None, "personal", None, 0).await;
        let second = repo.create(user_id, &pubkey, None, "personal", None, 0).await;
        assert!(second.is_err());
    }

    // ── Auth Challenge ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_challenge_single_use() {
        use crate::wallet::repository::WalletRegistryRepository;
        let pool = test_pool().await;
        let repo = WalletRegistryRepository::new(pool);
        let pubkey = format!("G{}", "C".repeat(55));
        let challenge = repo.create_challenge(&pubkey, "test-challenge-value", 300).await.unwrap();

        // First consume succeeds
        let consumed = repo.consume_challenge(challenge.id).await.unwrap();
        assert!(consumed.is_some());

        // Second consume fails (already used)
        let consumed2 = repo.consume_challenge(challenge.id).await.unwrap();
        assert!(consumed2.is_none());
    }

    #[tokio::test]
    async fn test_expired_challenge_rejected() {
        use crate::wallet::repository::WalletRegistryRepository;
        let pool = test_pool().await;
        let repo = WalletRegistryRepository::new(pool);
        let pubkey = format!("G{}", "D".repeat(55));
        // TTL of -1 means already expired
        let challenge = repo.create_challenge(&pubkey, "expired-challenge", -1).await.unwrap();
        let consumed = repo.consume_challenge(challenge.id).await.unwrap();
        assert!(consumed.is_none());
    }

    // ── Backup Confirmation ──────────────────────────────────────────────────

    #[tokio::test]
    async fn test_backup_confirmation_flow() {
        use crate::wallet::repository::WalletRegistryRepository;
        let pool = test_pool().await;
        let repo = WalletRegistryRepository::new(pool);
        let user_id = Uuid::new_v4();
        let pubkey = format!("G{}", "E".repeat(55));
        let wallet = repo.create(user_id, &pubkey, None, "personal", None, 0).await.unwrap();

        // No backup initially
        let status = repo.get_backup_status(wallet.id).await.unwrap();
        assert!(status.is_none());

        // Confirm backup
        let _ = repo.confirm_backup(wallet.id).await.unwrap();
        let status = repo.get_backup_status(wallet.id).await.unwrap();
        assert!(status.is_some());
    }

    // ── Recovery Rate Limiting ───────────────────────────────────────────────

    #[tokio::test]
    async fn test_recovery_rate_limiting() {
        use crate::wallet::repository::WalletRegistryRepository;
        use chrono::{Duration, Utc};
        let pool = test_pool().await;
        let repo = WalletRegistryRepository::new(pool);
        let ip = "10.0.0.1";

        // Record failed attempts with cooloff
        let cooloff = Utc::now() + Duration::minutes(5);
        let _ = repo.record_recovery_attempt(ip, None, false, Some(cooloff)).await;

        let active_cooloff = repo.get_cooloff(ip).await.unwrap();
        assert!(active_cooloff.is_some());
        assert!(active_cooloff.unwrap() > Utc::now());
    }

    // ── Guardian Management ──────────────────────────────────────────────────

    #[tokio::test]
    async fn test_guardian_designation() {
        use crate::wallet::repository::WalletRegistryRepository;
        let pool = test_pool().await;
        let repo = WalletRegistryRepository::new(pool);
        let user_id = Uuid::new_v4();
        let pubkey = format!("G{}", "F".repeat(55));
        let wallet = repo.create(user_id, &pubkey, None, "personal", None, 0).await.unwrap();

        let guardians = vec![
            (None, Some("guardian1@example.com".to_string())),
            (None, Some("guardian2@example.com".to_string())),
            (None, Some("guardian3@example.com".to_string())),
        ];
        repo.set_guardians(wallet.id, &guardians).await.unwrap();

        let stored = repo.get_guardians(wallet.id).await.unwrap();
        assert_eq!(stored.len(), 3);
    }

    // ── Transaction History ──────────────────────────────────────────────────

    #[tokio::test]
    async fn test_history_insert_and_paginate() {
        use crate::wallet::models::HistoryQuery;
        use crate::wallet::repository::{InsertHistoryEntry, TransactionHistoryRepository, WalletRegistryRepository};
        use sqlx::types::BigDecimal;
        use std::str::FromStr;

        let pool = test_pool().await;
        let wallet_repo = WalletRegistryRepository::new(pool.clone());
        let history_repo = TransactionHistoryRepository::new(pool);

        let user_id = Uuid::new_v4();
        let pubkey = format!("G{}", "H".repeat(55));
        let wallet = wallet_repo.create(user_id, &pubkey, None, "personal", None, 0).await.unwrap();

        let entry = InsertHistoryEntry {
            wallet_id: wallet.id,
            entry_type: "payment".to_string(),
            direction: "credit".to_string(),
            asset_code: "cNGN".to_string(),
            asset_issuer: None,
            amount: BigDecimal::from_str("100.00").unwrap(),
            fiat_equivalent: Some(BigDecimal::from_str("100.00").unwrap()),
            fiat_currency: Some("NGN".to_string()),
            exchange_rate: Some(BigDecimal::from_str("1.0").unwrap()),
            counterparty: Some("GSENDER".to_string()),
            platform_transaction_id: None,
            stellar_transaction_hash: Some("abc123".to_string()),
            parent_entry_id: None,
            status: Some("confirmed".to_string()),
            description: Some("Test payment".to_string()),
            failure_reason: None,
            horizon_cursor: Some("cursor1".to_string()),
            confirmed_at: None,
        };
        history_repo.insert(&entry).await.unwrap();

        let query = HistoryQuery {
            cursor: None,
            limit: Some(10),
            entry_type: None,
            direction: None,
            asset_code: None,
            status: None,
            date_from: None,
            date_to: None,
            sort: None,
        };
        let (entries, next_cursor) = history_repo.list_paginated(wallet.id, &query).await.unwrap();
        assert!(!entries.is_empty());
        assert!(next_cursor.is_none()); // only 1 entry, no next page
    }

    #[tokio::test]
    async fn test_history_deduplication_by_stellar_hash() {
        use crate::wallet::repository::{InsertHistoryEntry, TransactionHistoryRepository, WalletRegistryRepository};
        use sqlx::types::BigDecimal;
        use std::str::FromStr;

        let pool = test_pool().await;
        let wallet_repo = WalletRegistryRepository::new(pool.clone());
        let history_repo = TransactionHistoryRepository::new(pool);

        let user_id = Uuid::new_v4();
        let pubkey = format!("G{}", "I".repeat(55));
        let wallet = wallet_repo.create(user_id, &pubkey, None, "personal", None, 0).await.unwrap();

        let hash = "dedup_test_hash_xyz";
        let entry = InsertHistoryEntry {
            wallet_id: wallet.id,
            entry_type: "payment".to_string(),
            direction: "debit".to_string(),
            asset_code: "XLM".to_string(),
            asset_issuer: None,
            amount: BigDecimal::from_str("5.0").unwrap(),
            fiat_equivalent: None,
            fiat_currency: None,
            exchange_rate: None,
            counterparty: None,
            platform_transaction_id: None,
            stellar_transaction_hash: Some(hash.to_string()),
            parent_entry_id: None,
            status: Some("confirmed".to_string()),
            description: None,
            failure_reason: None,
            horizon_cursor: None,
            confirmed_at: None,
        };
        history_repo.insert(&entry).await.unwrap();

        // Check dedup guard
        let exists = history_repo.exists_by_stellar_hash(wallet.id, hash).await.unwrap();
        assert!(exists);
        let not_exists = history_repo.exists_by_stellar_hash(wallet.id, "other_hash").await.unwrap();
        assert!(!not_exists);
    }

    // ── Stellar Sync Cursor ──────────────────────────────────────────────────

    #[tokio::test]
    async fn test_sync_cursor_upsert() {
        use crate::wallet::repository::{TransactionHistoryRepository, WalletRegistryRepository};
        let pool = test_pool().await;
        let wallet_repo = WalletRegistryRepository::new(pool.clone());
        let history_repo = TransactionHistoryRepository::new(pool);

        let user_id = Uuid::new_v4();
        let pubkey = format!("G{}", "J".repeat(55));
        let wallet = wallet_repo.create(user_id, &pubkey, None, "personal", None, 0).await.unwrap();

        // No cursor initially
        let cursor = history_repo.get_sync_cursor(wallet.id).await.unwrap();
        assert!(cursor.is_none());

        // Set cursor
        history_repo.update_sync_cursor(wallet.id, "cursor_abc").await.unwrap();
        let cursor = history_repo.get_sync_cursor(wallet.id).await.unwrap();
        assert_eq!(cursor.unwrap(), "cursor_abc");

        // Update cursor
        history_repo.update_sync_cursor(wallet.id, "cursor_xyz").await.unwrap();
        let cursor = history_repo.get_sync_cursor(wallet.id).await.unwrap();
        assert_eq!(cursor.unwrap(), "cursor_xyz");
    }

    // ── Portfolio Preferences ────────────────────────────────────────────────

    #[tokio::test]
    async fn test_portfolio_currency_preference() {
        use crate::wallet::repository::PortfolioRepository;
        let pool = test_pool().await;
        let repo = PortfolioRepository::new(pool);
        let user_id = Uuid::new_v4();

        // Default is NGN
        let currency = repo.get_preferred_currency(user_id).await.unwrap();
        assert_eq!(currency, "NGN");

        // Update to USD
        repo.set_preferred_currency(user_id, "USD").await.unwrap();
        let currency = repo.get_preferred_currency(user_id).await.unwrap();
        assert_eq!(currency, "USD");
    }

    // ── Multi-wallet enforcement ─────────────────────────────────────────────

    #[tokio::test]
    async fn test_max_wallet_count() {
        use crate::wallet::repository::WalletRegistryRepository;
        let pool = test_pool().await;
        let repo = WalletRegistryRepository::new(pool);
        let user_id = Uuid::new_v4();

        for i in 0..3 {
            let pubkey = format!("G{}{}", "K".repeat(54), i);
            let w = repo.create(user_id, &pubkey, None, "personal", None, 0).await.unwrap();
            repo.update_status(w.id, "active").await.unwrap();
        }

        let count = repo.count_active_wallets(user_id).await.unwrap();
        assert_eq!(count, 3);
    }
}
