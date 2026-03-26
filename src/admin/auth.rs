use crate::admin::models::*;
use crate::admin::repositories::*;
use crate::database::error::DatabaseError;
use chrono::{Duration, Utc};
use rand::Rng;
use serde_json::json;
use std::collections::HashMap;
use uuid::Uuid;
use base64::{Engine as _, engine::general_purpose};
use sha2::{Sha256, Digest};

pub struct AdminAuthService {
    account_repo: AdminAccountRepository,
    session_repo: AdminSessionRepository,
    audit_repo: AdminAuditRepository,
    security_event_repo: AdminSecurityEventRepository,
    permission_repo: AdminPermissionRepository,
    config: AdminSecurityConfig,
}

impl AdminAuthService {
    pub fn new(
        pool: sqlx::PgPool,
        config: AdminSecurityConfig,
    ) -> Self {
        Self {
            account_repo: AdminAccountRepository::new(pool.clone()),
            session_repo: AdminSessionRepository::new(pool.clone()),
            audit_repo: AdminAuditRepository::new(pool.clone()),
            security_event_repo: AdminSecurityEventRepository::new(pool.clone()),
            permission_repo: AdminPermissionRepository::new(pool.clone()),
            config,
        }
    }

    pub async fn authenticate(
        &self,
        login_request: AdminLoginRequest,
        ip_address: &str,
        user_agent: &str,
    ) -> Result<AdminLoginResponse, crate::error::Error> {
        // Get admin account by email
        let admin = self.account_repo
            .get_by_email(&login_request.email)
            .await?
            .ok_or_else(|| crate::error::Error::Authentication("Invalid credentials".to_string()))?;

        // Check if account is locked
        if let Some(locked_until) = admin.account_locked_until {
            if locked_until > Utc::now() {
                self.audit_repo.create_audit_entry(
                    Some(admin.id),
                    None,
                    AuditActionType::LoginFailure,
                    Some("admin_account".to_string()),
                    Some(admin.id),
                    Some(json!({"reason": "account_locked"})),
                    None,
                    None,
                    Some(ip_address.to_string()),
                    Some(user_agent.to_string()),
                ).await?;

                return Err(crate::error::Error::Authentication("Account is locked".to_string()));
            } else {
                // Auto-unlock account if lock period has expired
                self.account_repo.unlock_account(admin.id).await?;
            }
        }

        // Check account status
        match admin.status {
            AdminStatus::PendingSetup => {
                return Err(crate::error::Error::Authentication("Account setup required".to_string()));
            }
            AdminStatus::Suspended => {
                return Err(crate::error::Error::Authentication("Account is suspended".to_string()));
            }
            AdminStatus::Locked => {
                return Err(crate::error::Error::Authentication("Account is locked".to_string()));
            }
            AdminStatus::Active => {}
        }

        // Verify password
        if !bcrypt::verify(&login_request.password, &admin.password_hash)
            .map_err(|_| crate::error::Error::Authentication("Authentication failed".to_string()))? {
            
            // Increment failed login count
            self.account_repo.increment_failed_login(admin.id).await?;

            // Check if account should be locked
            let updated_admin = self.account_repo.get_by_id(admin.id).await?.unwrap();
            if updated_admin.failed_login_count >= self.config.max_failed_login_attempts {
                self.account_repo.lock_account(
                    admin.id,
                    self.config.account_lockout_duration_minutes,
                ).await?;

                self.audit_repo.create_audit_entry(
                    Some(admin.id),
                    None,
                    AuditActionType::AccountLocked,
                    Some("admin_account".to_string()),
                    Some(admin.id),
                    Some(json!({"reason": "too_many_failed_attempts", "failed_count": updated_admin.failed_login_count + 1})),
                    None,
                    None,
                    Some(ip_address.to_string()),
                    Some(user_agent.to_string()),
                ).await?;

                return Err(crate::error::Error::Authentication("Account locked due to too many failed attempts".to_string()));
            }

            self.audit_repo.create_audit_entry(
                Some(admin.id),
                None,
                AuditActionType::LoginFailure,
                Some("admin_account".to_string()),
                Some(admin.id),
                Some(json!({"reason": "invalid_password"})),
                None,
                None,
                Some(ip_address.to_string()),
                Some(user_agent.to_string()),
            ).await?;

            return Err(crate::error::Error::Authentication("Invalid credentials".to_string()));
        }

        // Reset failed login count on successful password verification
        self.account_repo.reset_failed_login(admin.id).await?;

        // Check for suspicious login patterns
        self.check_suspicious_login(&admin, ip_address, user_agent).await?;

        // Determine if MFA is required
        let requires_mfa = self.config.mfa_required_for_all_roles || 
                          (admin.role == AdminRole::SuperAdmin && self.config.fido2_required_for_super_admin) ||
                          !matches!(admin.mfa_status, MfaStatus::NotConfigured);

        let mut mfa_methods = Vec::new();
        if admin.mfa_secret.is_some() {
            mfa_methods.push("totp".to_string());
        }
        if admin.fido2_credentials.is_some() {
            mfa_methods.push("fido2".to_string());
        }

        // Create session (but don't activate until MFA is verified if required)
        let role_config = self.permission_repo.get_role_config(admin.role).await?;
        let expires_at = Utc::now() + Duration::minutes(role_config.session_lifetime_minutes as i64);

        let session = self.session_repo.create_session(
            admin.id,
            expires_at,
            ip_address,
            user_agent,
        ).await?;

        // Log successful authentication
        self.audit_repo.create_audit_entry(
            Some(admin.id),
            Some(session.id),
            AuditActionType::LoginSuccess,
            Some("admin_account".to_string()),
            Some(admin.id),
            Some(json!({"mfa_required": requires_mfa})),
            None,
            None,
            Some(ip_address.to_string()),
            Some(user_agent.to_string()),
        ).await?;

        // Update last login
        self.account_repo.update_last_login(admin.id, ip_address).await?;

        // If MFA is not required, mark session as MFA verified
        if !requires_mfa {
            self.session_repo.update_mfa_verified(session.id).await?;
        }

        Ok(AdminLoginResponse {
            session_id: session.id,
            expires_at,
            admin,
            requires_mfa,
            mfa_methods,
        })
    }

    pub async fn verify_mfa(
        &self,
        session_id: Uuid,
        totp_code: Option<String>,
        fido2_assertion: Option<serde_json::Value>,
    ) -> Result<(), crate::error::Error> {
        let session = self.session_repo.get_by_id(session_id).await?
            .ok_or_else(|| crate::error::Error::Authentication("Invalid session".to_string()))?;

        if session.mfa_verified {
            return Ok(());
        }

        if session.status != SessionStatus::Active {
            return Err(crate::error::Error::Authentication("Session is not active".to_string()));
        }

        if session.expires_at < Utc::now() {
            return Err(crate::error::Error::Authentication("Session has expired".to_string()));
        }

        let admin = self.account_repo.get_by_id(session.admin_id).await?
            .ok_or_else(|| crate::error::Error::Authentication("Admin not found".to_string()))?;

        let mut verification_success = false;

        // Try TOTP verification if code provided
        if let (Some(totp_code), Some(secret)) = (totp_code, admin.mfa_secret) {
            verification_success = self.verify_totp(&secret, &totp_code)?;
        }

        // Try FIDO2 verification if assertion provided
        if let Some(assertion) = fido2_assertion {
            if let Some(credentials) = admin.fido2_credentials {
                verification_success = self.verify_fido2_assertion(&credentials, &assertion).await?;
            }
        }

        if !verification_success {
            self.audit_repo.create_audit_entry(
                Some(admin.id),
                Some(session.id),
                AuditActionType::LoginFailure,
                Some("admin_session".to_string()),
                Some(session.id),
                Some(json!({"reason": "mfa_verification_failed"})),
                None,
                None,
                Some(session.ip_address.clone()),
                Some(session.user_agent.clone()),
            ).await?;

            return Err(crate::error::Error::Authentication("MFA verification failed".to_string()));
        }

        // Mark session as MFA verified
        self.session_repo.update_mfa_verified(session_id).await?;

        // Log successful MFA verification
        self.audit_repo.create_audit_entry(
            Some(admin.id),
            Some(session.id),
            AuditActionType::LoginSuccess,
            Some("admin_session".to_string()),
            Some(session.id),
            Some(json!({"mfa_verified": true})),
            None,
            None,
            Some(session.ip_address.clone()),
            Some(session.user_agent.clone()),
        ).await?;

        Ok(())
    }

    pub async fn setup_mfa(
        &self,
        admin_id: Uuid,
        setup_request: MfaSetupRequest,
    ) -> Result<MfaSetupResponse, crate::error::Error> {
        let admin = self.account_repo.get_by_id(admin_id).await?
            .ok_or_else(|| crate::error::Error::NotFound("Admin not found".to_string()))?;

        match setup_request.method.as_str() {
            "totp" => {
                let secret = self.generate_totp_secret();
                let qr_code_url = format!(
                    "otpauth://totp/Aframp:{}?secret={}&issuer=Aframp",
                    admin.email, secret
                );

                // Store the secret temporarily (not activating MFA yet)
                self.account_repo.update_mfa_secret(admin_id, &secret).await?;

                Ok(MfaSetupResponse {
                    qr_code_url: Some(qr_code_url),
                    secret: Some(secret),
                    challenge: None,
                })
            }
            "fido2" => {
                let challenge = self.generate_fido2_challenge().await?;
                Ok(MfaSetupResponse {
                    qr_code_url: None,
                    secret: None,
                    challenge: Some(challenge),
                })
            }
            _ => Err(crate::error::Error::BadRequest("Invalid MFA method".to_string())),
        }
    }

    pub async fn confirm_mfa_setup(
        &self,
        admin_id: Uuid,
        method: &str,
        verification_data: serde_json::Value,
    ) -> Result<(), crate::error::Error> {
        match method {
            "totp" => {
                let totp_code = verification_data.get("totp_code")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| crate::error::Error::BadRequest("TOTP code required".to_string()))?;

                let admin = self.account_repo.get_by_id(admin_id).await?
                    .ok_or_else(|| crate::error::Error::NotFound("Admin not found".to_string()))?;

                let secret = admin.mfa_secret
                    .ok_or_else(|| crate::error::Error::BadRequest("TOTP secret not found".to_string()))?;

                if !self.verify_totp(&secret, totp_code)? {
                    return Err(crate::error::Error::Authentication("Invalid TOTP code".to_string()));
                }

                // Update admin status to active if this was pending setup
                if admin.status == AdminStatus::PendingSetup {
                    sqlx::query!("UPDATE admin_accounts SET status = 'active' WHERE id = $1", admin_id)
                        .execute(&self.account_repo.pool)
                        .await
                        .map_err(DatabaseError::from_sqlx)?;
                }

                self.audit_repo.create_audit_entry(
                    Some(admin_id),
                    None,
                    AuditActionType::MfaConfigured,
                    Some("admin_account".to_string()),
                    Some(admin_id),
                    Some(json!({"method": "totp"})),
                    None,
                    None,
                    None,
                    None,
                ).await?;
            }
            "fido2" => {
                let credential = verification_data.get("credential")
                    .ok_or_else(|| crate::error::Error::BadRequest("FIDO2 credential required".to_string()))?;

                self.account_repo.update_fido2_credentials(admin_id, credential.clone()).await?;

                let admin = self.account_repo.get_by_id(admin_id).await?
                    .ok_or_else(|| crate::error::Error::NotFound("Admin not found".to_string()))?;

                // Update admin status to active if this was pending setup
                if admin.status == AdminStatus::PendingSetup {
                    sqlx::query!("UPDATE admin_accounts SET status = 'active' WHERE id = $1", admin_id)
                        .execute(&self.account_repo.pool)
                        .await
                        .map_err(DatabaseError::from_sqlx)?;
                }

                self.audit_repo.create_audit_entry(
                    Some(admin_id),
                    None,
                    AuditActionType::MfaConfigured,
                    Some("admin_account".to_string()),
                    Some(admin_id),
                    Some(json!({"method": "fido2"})),
                    None,
                    None,
                    None,
                    None,
                ).await?;
            }
            _ => return Err(crate::error::Error::BadRequest("Invalid MFA method".to_string())),
        }

        Ok(())
    }

    pub async fn change_password(
        &self,
        admin_id: Uuid,
        request: PasswordChangeRequest,
    ) -> Result<(), crate::error::Error> {
        let admin = self.account_repo.get_by_id(admin_id).await?
            .ok_or_else(|| crate::error::Error::NotFound("Admin not found".to_string()))?;

        // Verify current password
        if !bcrypt::verify(&request.current_password, &admin.password_hash)
            .map_err(|_| crate::error::Error::Authentication("Invalid current password".to_string()))? {
            return Err(crate::error::Error::Authentication("Invalid current password".to_string()));
        }

        // Validate new password complexity
        validate_password_complexity(&request.new_password, &self.config)
            .map_err(|e| crate::error::Error::BadRequest(e))?;

        // Update password
        self.account_repo.update_password(admin_id, &request.new_password).await?;

        // Log password change
        self.audit_repo.create_audit_entry(
            Some(admin_id),
            None,
            AuditActionType::PasswordChanged,
            Some("admin_account".to_string()),
            Some(admin_id),
            None,
            None,
            None,
            None,
            None,
        ).await?;

        Ok(())
    }

    pub async fn validate_session(&self, session_id: Uuid, ip_address: &str, user_agent: &str) -> Result<Option<AdminAccount>, crate::error::Error> {
        let session = self.session_repo.get_by_id(session_id).await?
            .ok_or_else(|| crate::error::Error::Authentication("Invalid session".to_string()))?;

        // Check session status
        if session.status != SessionStatus::Active {
            return Ok(None);
        }

        // Check session expiry
        if session.expires_at < Utc::now() {
            self.session_repo.terminate_session(session_id, "expired").await?;
            return Ok(None);
        }

        // Check IP address binding
        if session.ip_address != ip_address {
            self.session_repo.terminate_session(session_id, "ip_address_mismatch").await?;
            
            self.security_event_repo.create_security_event(
                Some(session.admin_id),
                "ip_address_mismatch",
                json!({
                    "session_id": session_id,
                    "expected_ip": session.ip_address,
                    "actual_ip": ip_address
                }),
                "high",
            ).await?;

            return Ok(None);
        }

        // Check user agent binding
        if session.user_agent != user_agent {
            self.session_repo.terminate_session(session_id, "user_agent_mismatch").await?;
            
            self.security_event_repo.create_security_event(
                Some(session.admin_id),
                "user_agent_mismatch",
                json!({
                    "session_id": session_id,
                    "expected_user_agent": session.user_agent,
                    "actual_user_agent": user_agent
                }),
                "medium",
            ).await?;

            return Ok(None);
        }

        // Check MFA verification
        if !session.mfa_verified {
            return Ok(None);
        }

        // Update last activity
        self.session_repo.update_last_activity(session_id).await?;

        // Get admin account
        let admin = self.account_repo.get_by_id(session.admin_id).await?;
        Ok(admin)
    }

    async fn check_suspicious_login(&self, admin: &AdminAccount, ip_address: &str, user_agent: &str) -> Result<(), crate::error::Error> {
        let mut suspicious_events = Vec::new();

        // Check for impossible travel
        if let (Some(last_login_ip), Some(last_login_at)) = (&admin.last_login_ip, admin.last_login_at) {
            if let (Some(distance), Some(time_diff)) = self.calculate_distance_and_time(last_login_ip, ip_address, last_login_at) {
                if self.is_impossible_travel(distance, time_diff) {
                    suspicious_events.push(("impossible_travel", json!({
                        "previous_ip": last_login_ip,
                        "current_ip": ip_address,
                        "distance_km": distance,
                        "time_minutes": time_diff
                    })));
                }
            }
        }

        // Check for new device
        // This is a simplified check - in production, you'd maintain a device fingerprint database
        let user_agent_hash = format!("{:x}", Sha256::digest(user_agent.as_bytes()));
        if self.is_new_device(admin.id, &user_agent_hash).await? {
            suspicious_events.push(("new_device", json!({
                "user_agent_hash": user_agent_hash
            })));
        }

        // Check for unusual hours (simplified - outside 9am-6pm local time)
        let current_hour = Utc::now().hour();
        if current_hour < 9 || current_hour > 18 {
            suspicious_events.push(("unusual_hours", json!({
                "hour": current_hour,
                "timezone": "UTC"
            })));
        }

        // Create security events for suspicious activity
        for (event_type, event_data) in suspicious_events {
            self.security_event_repo.create_security_event(
                Some(admin.id),
                event_type,
                event_data,
                "medium",
            ).await?;
        }

        Ok(())
    }

    fn verify_totp(&self, secret: &str, code: &str) -> Result<bool, crate::error::Error> {
        // This is a simplified TOTP verification
        // In production, you'd use a proper TOTP library like totp-lite
        use std::time::{SystemTime, UNIX_EPOCH};
        
        let time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| crate::error::Error::Internal("Time error".to_string()))?
            .as_secs() / 30;

        let expected_code = self.generate_totp_code(secret, time)?;
        Ok(code == expected_code)
    }

    fn generate_totp_code(&self, secret: &str, time_counter: u64) -> Result<String, crate::error::Error> {
        // Simplified TOTP code generation
        // In production, use a proper TOTP implementation
        let hash = hmac_sha1(secret, &time_counter.to_be_bytes());
        let offset = (hash[19] & 0x0f) as usize;
        let code = ((hash[offset] & 0x7f) as u32) << 24
            | ((hash[offset + 1] & 0xff) as u32) << 16
            | ((hash[offset + 2] & 0xff) as u32) << 8
            | ((hash[offset + 3] & 0xff) as u32);
        
        Ok(format!("{:06}", code % 1_000_000))
    }

    fn generate_totp_secret(&self) -> String {
        // Generate a random 32-byte base32-encoded secret
        let mut rng = rand::thread_rng();
        let mut bytes = [0u8; 32];
        rng.fill(&mut bytes);
        base32::encode(base32::Alphabet::RFC4648 { padding: true }, &bytes)
    }

    async fn verify_fido2_assertion(&self, credentials: &serde_json::Value, assertion: &serde_json::Value) -> Result<bool, crate::error::Error> {
        // Simplified FIDO2 verification
        // In production, you'd use a proper WebAuthn library
        Ok(true) // Placeholder
    }

    async fn generate_fido2_challenge(&self) -> Result<serde_json::Value, crate::error::Error> {
        // Generate a random FIDO2 challenge
        let mut rng = rand::thread_rng();
        let mut challenge = [0u8; 32];
        rng.fill(&mut challenge);
        
        Ok(json!({
            "challenge": general_purpose::STANDARD.encode(challenge),
            "userVerification": "required"
        }))
    }

    fn calculate_distance_and_time(&self, ip1: &str, ip2: &str, previous_login: chrono::DateTime<Utc>) -> Option<(f64, f64)> {
        // Simplified distance calculation
        // In production, you'd use a proper IP geolocation service
        let distance = 1000.0; // Placeholder distance in km
        let time_diff = (Utc::now() - previous_login).num_minutes() as f64;
        Some((distance, time_diff))
    }

    fn is_impossible_travel(&self, distance_km: f64, time_minutes: f64) -> bool {
        // Consider it impossible if traveling faster than 900 km/h (commercial aircraft speed)
        if time_minutes <= 0.0 {
            return false;
        }
        let speed_kmh = distance_km / (time_minutes / 60.0);
        speed_kmh > 900.0
    }

    async fn is_new_device(&self, admin_id: Uuid, user_agent_hash: &str) -> Result<bool, crate::error::Error> {
        // Simplified new device detection
        // In production, you'd maintain a database of known device fingerprints
        Ok(true) // Placeholder - always consider new for demo
    }
}

// Helper functions
fn hmac_sha1(key: &str, data: &[u8]) -> [u8; 20] {
    use hmac::{Hmac, Mac};
    type HmacSha1 = Hmac<sha1::Sha1>;

    let mut mac = HmacSha1::new_from_slice(key.as_bytes())
        .expect("HMAC can take key of any size");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

// Simple base32 implementation for TOTP secret generation
mod base32 {
    use std::collections::HashMap;

    pub struct Alphabet {
        pub padding: bool,
    }

    pub const RFC4648: Alphabet = Alphabet { padding: true };

    pub fn encode(alphabet: Alphabet, data: &[u8]) -> String {
        const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        let mut result = String::new();
        
        for chunk in data.chunks(5) {
            let mut buffer = [0u8; 5];
            buffer[..chunk.len()].copy_from_slice(chunk);
            
            let bits = u64::from_be_bytes([
                0, buffer[0], buffer[1], buffer[2], buffer[3], buffer[4], 0, 0
            ]);
            
            for i in 0..8 {
                if i * 5 < chunk.len() * 8 {
                    let index = ((bits >> (35 - i * 5)) & 0x1f) as usize;
                    result.push(CHARS[index] as char);
                }
            }
        }

        if alphabet.padding {
            while result.len() % 8 != 0 {
                result.push('=');
            }
        }

        result
    }
}
