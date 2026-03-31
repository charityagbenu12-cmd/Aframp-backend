//! AML database repository

use super::case_management::AmlCase;
use super::models::AmlCaseStatus;
use sqlx::PgPool;
use uuid::Uuid;

pub struct AmlRepository {
    pool: PgPool,
}

impl AmlRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn create_case(
        &self,
        transaction_id: Uuid,
        wallet_address: &str,
        risk_score: f64,
        flag_level: &str,
        flags_json: serde_json::Value,
    ) -> Result<AmlCase, anyhow::Error> {
        let case = sqlx::query_as::<_, AmlCase>(
            r#"
            INSERT INTO aml_cases
                (transaction_id, wallet_address, risk_score, flag_level, flags_json, status)
            VALUES ($1, $2, $3, $4, $5, 'PendingComplianceReview')
            RETURNING *
            "#,
        )
        .bind(transaction_id)
        .bind(wallet_address)
        .bind(risk_score)
        .bind(flag_level)
        .bind(flags_json)
        .fetch_one(&self.pool)
        .await?;

        Ok(case)
    }

    pub async fn update_case_status(
        &self,
        case_id: Uuid,
        status: AmlCaseStatus,
        officer_id: &str,
        notes: &str,
    ) -> Result<AmlCase, anyhow::Error> {
        let status_str = match status {
            AmlCaseStatus::Cleared => "Cleared",
            AmlCaseStatus::PermanentlyBlocked => "PermanentlyBlocked",
            AmlCaseStatus::PendingComplianceReview => "PendingComplianceReview",
        };

        let case = sqlx::query_as::<_, AmlCase>(
            r#"
            UPDATE aml_cases
            SET status = $2, reviewed_by = $3, review_notes = $4, updated_at = NOW()
            WHERE id = $1
            RETURNING *
            "#,
        )
        .bind(case_id)
        .bind(status_str)
        .bind(officer_id)
        .bind(notes)
        .fetch_one(&self.pool)
        .await?;

        Ok(case)
    }

    pub async fn is_transaction_cleared(&self, transaction_id: Uuid) -> Result<bool, anyhow::Error> {
        let row: Option<(String,)> = sqlx::query_as(
            "SELECT status FROM aml_cases WHERE transaction_id = $1 ORDER BY created_at DESC LIMIT 1",
        )
        .bind(transaction_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(match row {
            None => true, // No case = no flag = cleared
            Some((status,)) => status == "Cleared",
        })
    }

    pub async fn get_pending_cases(&self) -> Result<Vec<AmlCase>, anyhow::Error> {
        let cases = sqlx::query_as::<_, AmlCase>(
            "SELECT * FROM aml_cases WHERE status = 'PendingComplianceReview' ORDER BY risk_score DESC",
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(cases)
    }
}
