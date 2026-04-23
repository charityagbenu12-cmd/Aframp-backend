use crate::wallet::models::*;
use anyhow::Result;
use chrono::{Duration, Utc};
use sqlx::PgPool;
use uuid::Uuid;

pub struct WalletRegistryRepository {
    pool: PgPool,
}

impl WalletRegistryRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn find_by_public_key(&self, pubkey: &str) -> Result<Option<WalletRecord>> {
        Ok(sqlx::query_as!(
            WalletRecord,
            r#"SELECT id, user_account_id, stellar_public_key, wallet_label, wallet_type,
               status, is_primary, kyc_tier_at_registration,
               registration_ip::text as registration_ip,
               last_activity_at, created_at, updated_at
               FROM wallet_registry WHERE stellar_public_key = $1"#,
            pubkey
        )
        .fetch_optional(&self.pool)
        .await?)
    }

    pub async fn find_by_user(&self, user_id: Uuid) -> Result<Vec<WalletRecord>> {
        Ok(sqlx::query_as!(
            WalletRecord,
            r#"SELECT id, user_account_id, stellar_public_key, wallet_label, wallet_type,
               status, is_primary, kyc_tier_at_registration,
               registration_ip::text as registration_ip,
               last_activity_at, created_at, updated_at
               FROM wallet_registry WHERE user_account_id = $1 ORDER BY is_primary DESC, created_at ASC"#,
            user_id
        )
        .fetch_all(&self.pool)
        .await?)
    }

    pub async fn find_by_id(&self, wallet_id: Uuid) -> Result<Option<WalletRecord>> {
        Ok(sqlx::query_as!(
            WalletRecord,
            r#"SELECT id, user_account_id, stellar_public_key, wallet_label, wallet_type,
               status, is_primary, kyc_tier_at_registration,
               registration_ip::text as registration_ip,
               last_activity_at, created_at, updated_at
               FROM wallet_registry WHERE id = $1"#,
            wallet_id
        )
        .fetch_optional(&self.pool)
        .await?)
    }

    pub async fn create(
        &self,
        user_id: Uuid,
        pubkey: &str,
        label: Option<&str>,
        wallet_type: &str,
        ip: Option<&str>,
        kyc_tier: i32,
    ) -> Result<WalletRecord> {
        Ok(sqlx::query_as!(
            WalletRecord,
            r#"INSERT INTO wallet_registry
               (user_account_id, stellar_public_key, wallet_label, wallet_type, kyc_tier_at_registration, registration_ip)
               VALUES ($1, $2, $3, $4, $5, $6::inet)
               RETURNING id, user_account_id, stellar_public_key, wallet_label, wallet_type,
               status, is_primary, kyc_tier_at_registration,
               registration_ip::text as registration_ip,
               last_activity_at, created_at, updated_at"#,
            user_id,
            pubkey,
            label,
            wallet_type,
            kyc_tier,
            ip
        )
        .fetch_one(&self.pool)
        .await?)
    }

    pub async fn update_status(&self, wallet_id: Uuid, status: &str) -> Result<()> {
        sqlx::query!(
            "UPDATE wallet_registry SET status = $1, updated_at = NOW() WHERE id = $2",
            status,
            wallet_id
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn set_primary(&self, user_id: Uuid, wallet_id: Uuid) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query!(
            "UPDATE wallet_registry SET is_primary = false WHERE user_account_id = $1",
            user_id
        )
        .execute(&mut *tx)
        .await?;
        sqlx::query!(
            "UPDATE wallet_registry SET is_primary = true, updated_at = NOW() WHERE id = $2 AND user_account_id = $1",
            user_id,
            wallet_id
        )
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn count_active_wallets(&self, user_id: Uuid) -> Result<i64> {
        let row = sqlx::query!(
            "SELECT COUNT(*) as cnt FROM wallet_registry WHERE user_account_id = $1 AND status = 'active'",
            user_id
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(row.cnt.unwrap_or(0))
    }

    // Auth challenges
    pub async fn create_challenge(&self, pubkey: &str, challenge: &str, ttl_secs: i64) -> Result<WalletAuthChallenge> {
        let expires_at = Utc::now() + Duration::seconds(ttl_secs);
        Ok(sqlx::query_as!(
            WalletAuthChallenge,
            r#"INSERT INTO wallet_auth_challenges (stellar_public_key, challenge, expires_at)
               VALUES ($1, $2, $3)
               RETURNING id, stellar_public_key, challenge, used, expires_at, created_at"#,
            pubkey,
            challenge,
            expires_at
        )
        .fetch_one(&self.pool)
        .await?)
    }

    pub async fn consume_challenge(&self, challenge_id: Uuid) -> Result<Option<WalletAuthChallenge>> {
        Ok(sqlx::query_as!(
            WalletAuthChallenge,
            r#"UPDATE wallet_auth_challenges SET used = true
               WHERE id = $1 AND used = false AND expires_at > NOW()
               RETURNING id, stellar_public_key, challenge, used, expires_at, created_at"#,
            challenge_id
        )
        .fetch_optional(&self.pool)
        .await?)
    }

    // Metadata
    pub async fn upsert_metadata(&self, wallet_id: Uuid, network: &str) -> Result<()> {
        sqlx::query!(
            r#"INSERT INTO wallet_metadata (wallet_id, network)
               VALUES ($1, $2)
               ON CONFLICT (wallet_id) DO UPDATE SET network = EXCLUDED.network, updated_at = NOW()"#,
            wallet_id,
            network
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn update_stellar_state(
        &self,
        wallet_id: Uuid,
        account_exists: bool,
        xlm_balance: Option<&str>,
        cngn_trustline: bool,
        cursor: Option<&str>,
    ) -> Result<()> {
        let balance: Option<sqlx::types::BigDecimal> = xlm_balance
            .and_then(|b| b.parse().ok());
        let min_met = balance.as_ref().map(|b| b >= &"1".parse().unwrap()).unwrap_or(false);
        sqlx::query!(
            r#"UPDATE wallet_metadata SET
               account_created_on_stellar = $2,
               xlm_balance = $3,
               min_xlm_balance_met = $4,
               cngn_trustline_active = $5,
               horizon_cursor = COALESCE($6, horizon_cursor),
               last_horizon_sync_at = NOW(),
               updated_at = NOW()
               WHERE wallet_id = $1"#,
            wallet_id,
            account_exists,
            balance,
            min_met,
            cngn_trustline,
            cursor
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_metadata(&self, wallet_id: Uuid) -> Result<Option<WalletMetadata>> {
        Ok(sqlx::query_as!(
            WalletMetadata,
            "SELECT * FROM wallet_metadata WHERE wallet_id = $1",
            wallet_id
        )
        .fetch_optional(&self.pool)
        .await?)
    }

    // Backup
    pub async fn confirm_backup(&self, wallet_id: Uuid) -> Result<BackupConfirmation> {
        Ok(sqlx::query_as!(
            BackupConfirmation,
            r#"INSERT INTO wallet_backup_confirmations (wallet_id)
               VALUES ($1)
               ON CONFLICT DO NOTHING
               RETURNING id, wallet_id, confirmed_at, confirmation_method, last_reminder_sent_at, created_at"#,
            wallet_id
        )
        .fetch_one(&self.pool)
        .await?)
    }

    pub async fn get_backup_status(&self, wallet_id: Uuid) -> Result<Option<BackupConfirmation>> {
        Ok(sqlx::query_as!(
            BackupConfirmation,
            "SELECT id, wallet_id, confirmed_at, confirmation_method, last_reminder_sent_at, created_at FROM wallet_backup_confirmations WHERE wallet_id = $1",
            wallet_id
        )
        .fetch_optional(&self.pool)
        .await?)
    }

    pub async fn count_unconfirmed_backups(&self) -> Result<i64> {
        let row = sqlx::query!(
            r#"SELECT COUNT(*) as cnt FROM wallet_registry w
               WHERE w.status = 'active'
               AND NOT EXISTS (SELECT 1 FROM wallet_backup_confirmations b WHERE b.wallet_id = w.id)"#
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(row.cnt.unwrap_or(0))
    }

    // Recovery attempts
    pub async fn record_recovery_attempt(
        &self,
        ip: &str,
        pubkey: Option<&str>,
        success: bool,
        cooloff_until: Option<chrono::DateTime<Utc>>,
    ) -> Result<()> {
        sqlx::query!(
            "INSERT INTO wallet_recovery_attempts (ip_address, wallet_public_key, success, cooloff_until) VALUES ($1::inet, $2, $3, $4)",
            ip,
            pubkey,
            success,
            cooloff_until
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn count_recent_attempts(&self, ip: &str, window_secs: i64) -> Result<i64> {
        let since = Utc::now() - Duration::seconds(window_secs);
        let row = sqlx::query!(
            "SELECT COUNT(*) as cnt FROM wallet_recovery_attempts WHERE ip_address = $1::inet AND attempt_at > $2",
            ip,
            since
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(row.cnt.unwrap_or(0))
    }

    pub async fn get_cooloff(&self, ip: &str) -> Result<Option<chrono::DateTime<Utc>>> {
        let row = sqlx::query!(
            "SELECT cooloff_until FROM wallet_recovery_attempts WHERE ip_address = $1::inet AND cooloff_until > NOW() ORDER BY cooloff_until DESC LIMIT 1",
            ip
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.and_then(|r| r.cooloff_until))
    }

    // Recovery sessions
    pub async fn create_recovery_session(
        &self,
        method: &str,
        ip: Option<&str>,
    ) -> Result<RecoverySession> {
        Ok(sqlx::query_as!(
            RecoverySession,
            r#"INSERT INTO wallet_recovery_sessions (recovery_method, ip_address)
               VALUES ($1, $2::inet)
               RETURNING id, recovered_public_key, recovery_method, status,
               ip_address::text as ip_address, failure_reason, initiated_at, completed_at"#,
            method,
            ip
        )
        .fetch_one(&self.pool)
        .await?)
    }

    pub async fn complete_recovery_session(
        &self,
        session_id: Uuid,
        pubkey: &str,
        success: bool,
        failure_reason: Option<&str>,
    ) -> Result<()> {
        let status = if success { "completed" } else { "failed" };
        sqlx::query!(
            "UPDATE wallet_recovery_sessions SET status = $2, recovered_public_key = $3, failure_reason = $4, completed_at = NOW() WHERE id = $1",
            session_id,
            status,
            pubkey,
            failure_reason
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    // Guardians
    pub async fn set_guardians(&self, wallet_id: Uuid, guardians: &[(Option<Uuid>, Option<String>)]) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query!("DELETE FROM wallet_guardians WHERE wallet_id = $1", wallet_id)
            .execute(&mut *tx)
            .await?;
        for (i, (user_id, email)) in guardians.iter().enumerate() {
            sqlx::query!(
                "INSERT INTO wallet_guardians (wallet_id, guardian_user_id, guardian_email, share_index) VALUES ($1, $2, $3, $4)",
                wallet_id,
                user_id.as_ref(),
                email.as_deref(),
                i as i32
            )
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    pub async fn get_guardians(&self, wallet_id: Uuid) -> Result<Vec<WalletGuardian>> {
        Ok(sqlx::query_as!(
            WalletGuardian,
            "SELECT id, wallet_id, guardian_user_id, guardian_email, share_index, status, created_at FROM wallet_guardians WHERE wallet_id = $1 AND status = 'active' ORDER BY share_index",
            wallet_id
        )
        .fetch_all(&self.pool)
        .await?)
    }

    // Social recovery
    pub async fn create_social_recovery_request(&self, wallet_id: Uuid, threshold: i32) -> Result<SocialRecoveryRequest> {
        Ok(sqlx::query_as!(
            SocialRecoveryRequest,
            r#"INSERT INTO social_recovery_requests (wallet_id, threshold_required)
               VALUES ($1, $2)
               RETURNING id, wallet_id, status, threshold_required, shares_collected, initiated_at, completed_at, expires_at"#,
            wallet_id,
            threshold
        )
        .fetch_one(&self.pool)
        .await?)
    }

    pub async fn add_guardian_approval(
        &self,
        recovery_id: Uuid,
        guardian_id: Uuid,
        signature: &str,
    ) -> Result<i32> {
        let mut tx = self.pool.begin().await?;
        sqlx::query!(
            "INSERT INTO guardian_approvals (recovery_request_id, guardian_id, signature) VALUES ($1, $2, $3)",
            recovery_id,
            guardian_id,
            signature
        )
        .execute(&mut *tx)
        .await?;
        let row = sqlx::query!(
            "UPDATE social_recovery_requests SET shares_collected = shares_collected + 1 WHERE id = $1 RETURNING shares_collected",
            recovery_id
        )
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(row.shares_collected)
    }

    pub async fn complete_social_recovery(&self, recovery_id: Uuid) -> Result<()> {
        sqlx::query!(
            "UPDATE social_recovery_requests SET status = 'completed', completed_at = NOW() WHERE id = $1",
            recovery_id
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    // Migration
    pub async fn create_migration(
        &self,
        old_wallet_id: Uuid,
        new_wallet_id: Uuid,
        old_sig: &str,
        new_sig: &str,
    ) -> Result<WalletMigration> {
        Ok(sqlx::query_as!(
            WalletMigration,
            r#"INSERT INTO wallet_migrations (old_wallet_id, new_wallet_id, old_wallet_signature, new_wallet_signature)
               VALUES ($1, $2, $3, $4)
               RETURNING id, old_wallet_id, new_wallet_id, status, old_wallet_signature, new_wallet_signature, initiated_at, completed_at"#,
            old_wallet_id,
            new_wallet_id,
            old_sig,
            new_sig
        )
        .fetch_one(&self.pool)
        .await?)
    }

    pub async fn complete_migration(&self, migration_id: Uuid) -> Result<()> {
        sqlx::query!(
            "UPDATE wallet_migrations SET status = 'completed', completed_at = NOW() WHERE id = $1",
            migration_id
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

pub struct TransactionHistoryRepository {
    pool: PgPool,
}

impl TransactionHistoryRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn insert(&self, entry: &InsertHistoryEntry) -> Result<TransactionHistoryEntry> {
        Ok(sqlx::query_as!(
            TransactionHistoryEntry,
            r#"INSERT INTO wallet_transaction_history
               (wallet_id, entry_type, direction, asset_code, asset_issuer, amount,
                fiat_equivalent, fiat_currency, exchange_rate, counterparty,
                platform_transaction_id, stellar_transaction_hash, parent_entry_id,
                status, description, failure_reason, horizon_cursor, confirmed_at)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)
               RETURNING *"#,
            entry.wallet_id,
            entry.entry_type,
            entry.direction,
            entry.asset_code,
            entry.asset_issuer.as_deref(),
            entry.amount,
            entry.fiat_equivalent.as_ref(),
            entry.fiat_currency.as_deref(),
            entry.exchange_rate.as_ref(),
            entry.counterparty.as_deref(),
            entry.platform_transaction_id,
            entry.stellar_transaction_hash.as_deref(),
            entry.parent_entry_id,
            entry.status.as_deref().unwrap_or("confirmed"),
            entry.description.as_deref(),
            entry.failure_reason.as_deref(),
            entry.horizon_cursor.as_deref(),
            entry.confirmed_at.unwrap_or_else(Utc::now)
        )
        .fetch_one(&self.pool)
        .await?)
    }

    pub async fn exists_by_stellar_hash(&self, wallet_id: Uuid, hash: &str) -> Result<bool> {
        let row = sqlx::query!(
            "SELECT 1 as exists FROM wallet_transaction_history WHERE wallet_id = $1 AND stellar_transaction_hash = $2 LIMIT 1",
            wallet_id,
            hash
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.is_some())
    }

    pub async fn list_paginated(
        &self,
        wallet_id: Uuid,
        query: &HistoryQuery,
    ) -> Result<(Vec<TransactionHistoryEntry>, Option<String>)> {
        let limit = query.limit.unwrap_or(50).clamp(1, 200);
        let cursor_ts = if let Some(ref c) = query.cursor {
            c.parse::<chrono::DateTime<Utc>>().ok()
        } else {
            None
        };

        let entries = sqlx::query_as!(
            TransactionHistoryEntry,
            r#"SELECT * FROM wallet_transaction_history
               WHERE wallet_id = $1
               AND ($2::timestamptz IS NULL OR confirmed_at < $2)
               AND ($3::text IS NULL OR entry_type = $3)
               AND ($4::text IS NULL OR direction = $4)
               AND ($5::text IS NULL OR asset_code = $5)
               AND ($6::text IS NULL OR status = $6)
               AND ($7::timestamptz IS NULL OR confirmed_at >= $7)
               AND ($8::timestamptz IS NULL OR confirmed_at <= $8)
               ORDER BY confirmed_at DESC
               LIMIT $9"#,
            wallet_id,
            cursor_ts,
            query.entry_type.as_deref(),
            query.direction.as_deref(),
            query.asset_code.as_deref(),
            query.status.as_deref(),
            query.date_from,
            query.date_to,
            limit + 1
        )
        .fetch_all(&self.pool)
        .await?;

        let next_cursor = if entries.len() as i64 > limit {
            entries.last().map(|e| e.confirmed_at.to_rfc3339())
        } else {
            None
        };
        let entries = entries.into_iter().take(limit as usize).collect();
        Ok((entries, next_cursor))
    }

    pub async fn get_sync_cursor(&self, wallet_id: Uuid) -> Result<Option<String>> {
        let row = sqlx::query!(
            "SELECT last_cursor FROM stellar_sync_cursors WHERE wallet_id = $1",
            wallet_id
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.and_then(|r| r.last_cursor))
    }

    pub async fn update_sync_cursor(&self, wallet_id: Uuid, cursor: &str) -> Result<()> {
        sqlx::query!(
            r#"INSERT INTO stellar_sync_cursors (wallet_id, last_cursor)
               VALUES ($1, $2)
               ON CONFLICT (wallet_id) DO UPDATE SET last_cursor = $2, last_synced_at = NOW()"#,
            wallet_id,
            cursor
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

pub struct PortfolioRepository {
    pool: PgPool,
}

impl PortfolioRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn save_snapshot(&self, snapshot: &InsertPortfolioSnapshot) -> Result<PortfolioSnapshot> {
        Ok(sqlx::query_as!(
            PortfolioSnapshot,
            r#"INSERT INTO portfolio_snapshots
               (user_account_id, total_value_fiat, fiat_currency, asset_breakdown, exchange_rates_applied)
               VALUES ($1, $2, $3, $4, $5)
               RETURNING *"#,
            snapshot.user_account_id,
            snapshot.total_value_fiat,
            snapshot.fiat_currency,
            snapshot.asset_breakdown,
            snapshot.exchange_rates_applied
        )
        .fetch_one(&self.pool)
        .await?)
    }

    pub async fn get_history(
        &self,
        user_id: Uuid,
        limit: i64,
    ) -> Result<Vec<PortfolioSnapshot>> {
        Ok(sqlx::query_as!(
            PortfolioSnapshot,
            "SELECT * FROM portfolio_snapshots WHERE user_account_id = $1 ORDER BY snapshot_at DESC LIMIT $2",
            user_id,
            limit
        )
        .fetch_all(&self.pool)
        .await?)
    }

    pub async fn get_preferred_currency(&self, user_id: Uuid) -> Result<String> {
        let row = sqlx::query!(
            "SELECT preferred_fiat_currency FROM portfolio_preferences WHERE user_account_id = $1",
            user_id
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| r.preferred_fiat_currency).unwrap_or_else(|| "NGN".to_string()))
    }

    pub async fn set_preferred_currency(&self, user_id: Uuid, currency: &str) -> Result<()> {
        sqlx::query!(
            r#"INSERT INTO portfolio_preferences (user_account_id, preferred_fiat_currency)
               VALUES ($1, $2)
               ON CONFLICT (user_account_id) DO UPDATE SET preferred_fiat_currency = $2, updated_at = NOW()"#,
            user_id,
            currency
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

pub struct StatementRepository {
    pool: PgPool,
}

impl StatementRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn create(&self, req: &CreateStatementRecord) -> Result<FinancialStatement> {
        let verification_code = format!("{:x}", rand_hex());
        Ok(sqlx::query_as!(
            FinancialStatement,
            r#"INSERT INTO financial_statements
               (user_account_id, wallet_id, statement_type, date_from, date_to, format, verification_code)
               VALUES ($1, $2, $3, $4, $5, $6, $7)
               RETURNING *"#,
            req.user_account_id,
            req.wallet_id,
            req.statement_type,
            req.date_from,
            req.date_to,
            req.format,
            verification_code
        )
        .fetch_one(&self.pool)
        .await?)
    }

    pub async fn update_completed(&self, id: Uuid, file_url: &str, expires_at: chrono::DateTime<Utc>) -> Result<()> {
        sqlx::query!(
            "UPDATE financial_statements SET status = 'completed', file_url = $2, download_expires_at = $3, generated_at = NOW() WHERE id = $1",
            id,
            file_url,
            expires_at
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn find_by_id(&self, id: Uuid) -> Result<Option<FinancialStatement>> {
        Ok(sqlx::query_as!(
            FinancialStatement,
            "SELECT * FROM financial_statements WHERE id = $1",
            id
        )
        .fetch_optional(&self.pool)
        .await?)
    }

    pub async fn list_for_user(&self, user_id: Uuid) -> Result<Vec<FinancialStatement>> {
        Ok(sqlx::query_as!(
            FinancialStatement,
            "SELECT * FROM financial_statements WHERE user_account_id = $1 ORDER BY created_at DESC LIMIT 50",
            user_id
        )
        .fetch_all(&self.pool)
        .await?)
    }
}

fn rand_hex() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

// Insert helpers
pub struct InsertHistoryEntry {
    pub wallet_id: Uuid,
    pub entry_type: String,
    pub direction: String,
    pub asset_code: String,
    pub asset_issuer: Option<String>,
    pub amount: sqlx::types::BigDecimal,
    pub fiat_equivalent: Option<sqlx::types::BigDecimal>,
    pub fiat_currency: Option<String>,
    pub exchange_rate: Option<sqlx::types::BigDecimal>,
    pub counterparty: Option<String>,
    pub platform_transaction_id: Option<Uuid>,
    pub stellar_transaction_hash: Option<String>,
    pub parent_entry_id: Option<Uuid>,
    pub status: Option<String>,
    pub description: Option<String>,
    pub failure_reason: Option<String>,
    pub horizon_cursor: Option<String>,
    pub confirmed_at: Option<chrono::DateTime<Utc>>,
}

pub struct InsertPortfolioSnapshot {
    pub user_account_id: Uuid,
    pub total_value_fiat: sqlx::types::BigDecimal,
    pub fiat_currency: String,
    pub asset_breakdown: serde_json::Value,
    pub exchange_rates_applied: serde_json::Value,
}

pub struct CreateStatementRecord {
    pub user_account_id: Uuid,
    pub wallet_id: Option<Uuid>,
    pub statement_type: String,
    pub date_from: chrono::NaiveDate,
    pub date_to: chrono::NaiveDate,
    pub format: String,
}
