use crate::cache::RedisPool;
use crate::database::error::DatabaseError;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use tracing::{debug, error, info};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MintType {
    Standard,
    Refund,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MintRequest {
    pub transaction_id: Uuid,
    pub priority: i32,
    pub partner_tier: String,
    pub mint_type: MintType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub linked_burn_hash: Option<String>,
}

#[derive(Clone)]
pub struct MintQueueService {
    pool: RedisPool,
}

impl MintQueueService {
    pub fn new(pool: RedisPool) -> Self {
        Self { pool }
    }

    /// Enqueue a mint request based on priority.
    /// Gold Tier or priority_level > 0 goes to the high-priority queue.
    pub async fn enqueue(&self, request: MintRequest) -> Result<(), String> {
        let mut conn = self.pool.get().await.map_err(|e| e.to_string())?;

        let queue_key = if request.priority > 0 || request.partner_tier == "gold" {
            "mint_queue:high_priority"
        } else {
            "mint_queue:standard"
        };

        let payload = serde_json::to_string(&request).map_err(|e| e.to_string())?;

        let _: () = redis::cmd("LPUSH")
            .arg(queue_key)
            .arg(payload)
            .query_async(&mut *conn)
            .await
            .map_err(|e| e.to_string())?;

        info!(
            tx_id = %request.transaction_id,
            queue = queue_key,
            "Mint request enqueued"
        );

        Ok(())
    }

    /// Pop a request from the queue, prioritizing high-priority.
    pub async fn pop_next(&self) -> Result<Option<MintRequest>, String> {
        let mut conn = self.pool.get().await.map_err(|e| e.to_string())?;

        // BRPOP returns [key, value]
        // We check high_priority then standard.
        // Using RPOP to keep it non-blocking for simplicity in the worker loop if needed,
        // but BRPOP with a short timeout is better.
        
        let result: Option<(String, String)> = redis::cmd("BRPOP")
            .arg("mint_queue:high_priority")
            .arg("mint_queue:standard")
            .arg(1) // 1 second timeout
            .query_async(&mut *conn)
            .await
            .map_err(|e| e.to_string())?;

        match result {
            Some((_key, payload)) => {
                let request: MintRequest = serde_json::from_str(&payload).map_err(|e| e.to_string())?;
                Ok(Some(request))
            }
            None => Ok(None),
        }
    }
}
