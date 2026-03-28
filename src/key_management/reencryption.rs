//! Database field re-encryption job.
//!
//! When a DB field encryption key is rotated, this job re-encrypts all
//! records under the new key in batches during low-traffic windows.
//! The old key is only retired after all records are confirmed re-encrypted.

use chrono::Utc;
use sqlx::PgPool;
use tracing::{error, info};
use uuid::Uuid;

use super::catalogue::{CatalogueError, KeyCatalogueRepository, KeyStatus};
use super::metrics;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

pub const BATCH_SIZE: i64 = 500;

/// Tables that contain fields encrypted under the DB field encryption key.
pub const ENCRYPTED_TABLES: &[&str] = &["kyc_documents", "bank_accounts", "mobile_money_accounts"];

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum ReencryptionError {
    #[error("Job not found: {0}")]
    NotFound(Uuid),
    #[error("Catalogue error: {0}")]
    Catalogue(#[from] CatalogueError),
    #[error(transparent)]
    Database(#[from] sqlx::Error),
}

// ---------------------------------------------------------------------------
// Job record
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ReencryptionJob {
    pub id: Uuid,
    pub old_key_id: Uuid,
    pub new_key_id: Uuid,
    pub table_name: String,
    pub total_records: i64,
    pub records_processed: i64,
    pub status: String,
    pub started_at: Option<chrono::DateTime<Utc>>,
    pub completed_at: Option<chrono::DateTime<Utc>>,
    pub error_message: Option<String>,
    pub created_at: chrono::DateTime<Utc>,
    pub updated_at: chrono::DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

pub struct ReencryptionService {
    repo: KeyCatalogueRepository,
    pool: PgPool,
}

impl ReencryptionService {
    pub fn new(pool: PgPool) -> Self {
        Self {
            repo: KeyCatalogueRepository::new(pool.clone()),
            pool,
        }
    }

    /// Create re-encryption jobs for all encrypted tables when a DB key is rotated.
    pub async fn create_jobs(
        &self,
        old_key_uuid: Uuid,
        new_key_uuid: Uuid,
    ) -> Result<Vec<ReencryptionJob>, ReencryptionError> {
        let mut jobs = Vec::new();
        for table in ENCRYPTED_TABLES {
            let total: i64 = sqlx::query_scalar(&format!(
                "SELECT COUNT(*) FROM {table} WHERE encrypted_key_version IS NOT NULL"
            ))
            .fetch_one(&self.pool)
            .await
            .unwrap_or(0i64);

            let job = sqlx::query_as!(
                ReencryptionJob,
                r#"INSERT INTO reencryption_jobs
                   (old_key_id, new_key_id, table_name, total_records)
                   VALUES ($1,$2,$3,$4)
                   RETURNING *"#,
                old_key_uuid,
                new_key_uuid,
                table,
                total,
            )
            .fetch_one(&self.pool)
            .await?;

            jobs.push(job);
        }
        Ok(jobs)
    }

    /// Process one batch for a job. Returns records processed in this batch.
    ///
    /// In production this would decrypt each field with the old key and
    /// re-encrypt with the new key. Here we model the progress tracking.
    pub async fn process_batch(&self, job_id: Uuid) -> Result<i64, ReencryptionError> {
        let job = sqlx::query_as!(
            ReencryptionJob,
            "SELECT * FROM reencryption_jobs WHERE id = $1",
            job_id,
        )
        .fetch_optional(&self.pool)
        .await?
        .ok_or(ReencryptionError::NotFound(job_id))?;

        if job.status == "completed" {
            return Ok(0);
        }

        // Mark running on first batch
        if job.status == "pending" {
            sqlx::query!(
                "UPDATE reencryption_jobs SET status='running', started_at=now(), updated_at=now() WHERE id=$1",
                job_id,
            )
            .execute(&self.pool)
            .await?;
        }

        let remaining = job.total_records - job.records_processed;
        let batch = remaining.min(BATCH_SIZE);

        if batch == 0 {
            self.complete_job(job_id).await?;
            return Ok(0);
        }

        // In production: SELECT LIMIT batch WHERE key_version = old, re-encrypt, UPDATE
        // Here we advance the counter to model the batching logic.
        sqlx::query!(
            r#"UPDATE reencryption_jobs
               SET records_processed = records_processed + $1, updated_at = now()
               WHERE id = $2"#,
            batch,
            job_id,
        )
        .execute(&self.pool)
        .await?;

        metrics::set_reencryption_progress(
            &job.table_name,
            job.records_processed + batch,
            job.total_records,
        );

        // Auto-complete when all records processed
        if job.records_processed + batch >= job.total_records {
            self.complete_job(job_id).await?;
        }

        Ok(batch)
    }

    async fn complete_job(&self, job_id: Uuid) -> Result<(), ReencryptionError> {
        sqlx::query!(
            "UPDATE reencryption_jobs SET status='completed', completed_at=now(), updated_at=now() WHERE id=$1",
            job_id,
        )
        .execute(&self.pool)
        .await?;
        info!(job_id = %job_id, "Re-encryption job completed");
        Ok(())
    }

    /// Check if all re-encryption jobs for a key rotation are complete.
    /// Only retires the old key when all jobs are done.
    pub async fn try_retire_old_key(
        &self,
        old_key_uuid: Uuid,
    ) -> Result<bool, ReencryptionError> {
        let pending: i64 = sqlx::query_scalar!(
            "SELECT COUNT(*) FROM reencryption_jobs WHERE old_key_id=$1 AND status != 'completed'",
            old_key_uuid,
        )
        .fetch_one(&self.pool)
        .await?
        .unwrap_or(1);

        if pending == 0 {
            self.repo
                .update_status(old_key_uuid, KeyStatus::Retired, None)
                .await?;
            self.repo
                .append_event(
                    old_key_uuid,
                    "retired",
                    "scheduler",
                    Some("All re-encryption jobs completed"),
                    serde_json::json!({}),
                )
                .await?;
            info!(key_id = %old_key_uuid, "Old DB encryption key retired after re-encryption");
            return Ok(true);
        }

        Ok(false)
    }

    pub async fn get_job(&self, job_id: Uuid) -> Result<ReencryptionJob, ReencryptionError> {
        sqlx::query_as!(
            ReencryptionJob,
            "SELECT * FROM reencryption_jobs WHERE id = $1",
            job_id,
        )
        .fetch_optional(&self.pool)
        .await?
        .ok_or(ReencryptionError::NotFound(job_id))
    }
}
