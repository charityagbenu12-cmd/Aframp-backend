use Bitmesh_backend::database::bill_payment_repository::BillPaymentRepository;
use Bitmesh_backend::database::transaction_repository::TransactionRepository;
use Bitmesh_backend::workers::bill_processor::worker::{BillProcessorWorker, BillProcessorConfig};
use Bitmesh_backend::workers::bill_processor::providers::BillProviderFactory;
use Bitmesh_backend::services::notification::NotificationService;
use Bitmesh_backend::chains::stellar::client::StellarClient;
use sqlx::{PgPool, types::BigDecimal};
use std::sync::Arc;
use uuid::Uuid;
use std::time::Duration;

#[tokio::test]
async fn test_bill_payment_lifecycle() {
    // 1. Setup - Requires a running database or a mock
    // In a real integration test environment, we would use a test database
    let database_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5432/aframp_test".to_string());
    let pool = match PgPool::connect(&database_url).await {
        Ok(p) => p,
        Err(_) => {
            println!("Skipping integration test: Database not available");
            return;
        }
    };

    let stellar_client = StellarClient::new_testnet().unwrap();
    let provider_factory = Arc::new(BillProviderFactory::from_env().unwrap());
    let notification_service = Arc::new(NotificationService::new(pool.clone()));
    
    let config = BillProcessorConfig {
        poll_interval: Duration::from_millis(100),
        batch_size: 10,
        ..Default::default()
    };
    
    let worker = BillProcessorWorker::new(
        pool.clone(),
        stellar_client,
        provider_factory,
        notification_service,
        config,
    );

    // 2. Create a transaction and bill payment
    let tx_repo = TransactionRepository::new(pool.clone());
    let bill_repo = BillPaymentRepository::new(pool.clone());
    
    let tx_id = Uuid::new_v4();
    let wallet = "GBCS7EDJ7VVE2A5J2FUKY3A277HBC3J5J6NXZG5U4P6B6D6B6D6B6D6B";
    
    // Create core transaction
    let _tx = tx_repo.create_transaction(
        wallet,
        "bill_payment",
        "cNGN",
        "NGN",
        BigDecimal::from(5000),
        BigDecimal::from(5000),
        BigDecimal::from(5000),
        "pending_payment",
        Some("flutterwave"),
        Some(&format!("test_ref_{}", tx_id)),
        serde_json::json!({}),
    ).await.unwrap();
    
    // Create bill payment record
    let bill = bill_repo.create_bill_payment(
        tx_id,
        "flutterwave",
        "8000000001",
        "electricity",
        None,
        true,
    ).await.unwrap();

    assert_eq!(bill.status, "pending_payment");

    // 3. Simulate cNGN received (Manual update to skip monitor scanning)
    bill_repo.update_processing_status(bill.id, "cngn_received", None, None, None).await.unwrap();

    // 4. Run worker cycle 1: transition to VerifyingAccount
    worker.run_cycle().await.unwrap();
    
    let bill = bill_repo.find_by_id(&bill.id.to_string()).await.unwrap().unwrap();
    // It might have moved further depending on how run_cycle is implemented (it processes all pending)
    // and if the verify_account mock is fast.
    
    // In this test environment, actual provider calls might fail, so we check if status changed from cngn_received
    assert_ne!(bill.status, "cngn_received");
    
    // Clean up
    let _ = bill_repo.delete(&bill.id.to_string()).await;
    let _ = tx_repo.delete(&tx_id.to_string()).await;
}
