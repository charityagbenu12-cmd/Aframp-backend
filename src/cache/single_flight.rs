//! Single-flight pattern for cache stampede protection.
//!
//! When multiple concurrent requests miss the cache for the same key,
//! only one rebuild is triggered. All other waiters receive the same result
//! once the rebuild completes, preventing a thundering-herd against the DB.

use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;
use tokio::sync::{Mutex, broadcast};
use tracing::{debug, info};

type SharedResult<T> = Arc<Result<T, String>>;

/// A map of in-flight rebuild operations keyed by cache key.
pub struct SingleFlight<T: Clone + Send + 'static> {
    in_flight: Mutex<HashMap<String, broadcast::Sender<SharedResult<T>>>>,
}

impl<T: Clone + Send + 'static> SingleFlight<T> {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            in_flight: Mutex::new(HashMap::new()),
        })
    }

    /// Execute `rebuild` for `key`, or wait for an in-flight rebuild to finish.
    ///
    /// Returns `Ok(value)` on success, `Err(msg)` if the rebuild failed.
    pub async fn get_or_rebuild<F, Fut>(&self, key: &str, rebuild: F) -> Result<T, String>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<T, String>>,
    {
        {
            let map = self.in_flight.lock().await;

            if let Some(tx) = map.get(key) {
                // Another request is already rebuilding — subscribe and wait.
                let mut rx = tx.subscribe();
                drop(map); // release lock before awaiting

                debug!(key, "single-flight: waiting for in-flight rebuild");
                match rx.recv().await {
                    Ok(result) => {
                        return (*result).clone().map_err(|e| e.clone());
                    }
                    Err(_) => {
                        // Sender dropped without sending — treat as miss and rebuild.
                    }
                }
            }
        }

        // We are the leader for this key.
        let (tx, _rx) = broadcast::channel::<SharedResult<T>>(1);
        let mut map = self.in_flight.lock().await;
        map.insert(key.to_string(), tx.clone());
        drop(map); // release lock before doing the expensive rebuild

        info!(key, "single-flight: leader rebuilding cache entry");
        let result = rebuild().await;
        let shared: SharedResult<T> = Arc::new(result.clone().map_err(|e| e.to_string()));

        // Broadcast result to all waiters (ignore send errors — no subscribers is fine).
        let _ = tx.send(shared);

        // Remove from in-flight map.
        let mut map = self.in_flight.lock().await;
        map.remove(key);

        result
    }
}
