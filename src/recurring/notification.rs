//! Recurring payment notifications (structured logging; wire to email/SMS/push as needed).

use tracing::{error, info, warn};
use uuid::Uuid;

pub fn notify_success(
    schedule_id: Uuid,
    wallet_address: &str,
    transaction_id: Uuid,
    amount: &str,
    currency: &str,
) {
    info!(
        schedule_id = %schedule_id,
        wallet = %wallet_address,
        transaction_id = %transaction_id,
        amount = %amount,
        currency = %currency,
        "🔔 RECURRING: Payment executed successfully"
    );
}

pub fn notify_failure(
    schedule_id: Uuid,
    wallet_address: &str,
    failure_count: i32,
    reason: &str,
) {
    warn!(
        schedule_id = %schedule_id,
        wallet = %wallet_address,
        failure_count = failure_count,
        reason = %reason,
        "🔔 RECURRING: Payment execution failed"
    );
}

pub fn notify_suspended(
    schedule_id: Uuid,
    wallet_address: &str,
    failure_count: i32,
) {
    error!(
        schedule_id = %schedule_id,
        wallet = %wallet_address,
        failure_count = failure_count,
        "🔔 RECURRING: Schedule automatically suspended after consecutive failures"
    );
}
