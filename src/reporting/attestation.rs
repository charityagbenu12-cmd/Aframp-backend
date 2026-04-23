use chrono::{DateTime, Utc, Datelike, NaiveDate, Duration};
use sqlx::{PgPool, types::BigDecimal};
use std::sync::Arc;
use serde::{Serialize, Deserialize};
use uuid::Uuid;
use crate::audit::models::{AuditLogEntry, AuditLogFilter};
use crate::audit::repository::AuditLogRepository;
use crate::services::transparency::{TransparencyService, ReserveDataPoint};
use tracing::{info, error};

pub struct AttestationReportData {
    pub month_name: String,
    pub year: i32,
    pub average_collateral_ratio: BigDecimal,
    pub daily_breakdown: Vec<ReserveDataPoint>,
    pub exceptional_events: Vec<AuditLogEntry>,
}

pub struct AttestationService {
    db: PgPool,
    transparency: Arc<TransparencyService>,
    audit_repo: Arc<AuditLogRepository>,
}

impl AttestationService {
    pub fn new(db: PgPool, transparency: Arc<TransparencyService>, audit_repo: Arc<AuditLogRepository>) -> Self {
        Self { db, transparency, audit_repo }
    }

    /// Generates a signed PDF report for the preceding month.
    pub async fn generate_preceding_month_report(&self) -> Result<Vec<u8>, anyhow::Error> {
        let now = Utc::now();
        let (year, month) = if now.month() == 1 {
            (now.year() - 1, 12)
        } else {
            (now.year(), now.month() - 1)
        };
        
        self.generate_report(year, month).await
    }

    pub async fn generate_report(&self, year: i32, month: u32) -> Result<Vec<u8>, anyhow::Error> {
        info!("Generating attestation report for {:04}-{:02}", year, month);

        // 1. Calculate date range
        let start_date = NaiveDate::from_ymd_opt(year, month, 1).unwrap();
        let next_month = if month == 12 { 1 } else { month + 1 };
        let next_year = if month == 12 { year + 1 } else { year };
        let end_date = NaiveDate::from_ymd_opt(next_year, next_month, 1).unwrap() - Duration::days(1);
        
        let days_in_month = (end_date - start_date).num_days() + 1;

        // 2. Aggregate Data
        // History from Transparency Service
        let history = self.transparency.get_history(days_in_month as u32).await?;
        
        // Exceptional events from Audit Log (e.g. circuit breaker)
        let audit_filter = AuditLogFilter {
            event_category: None,
            actor_id: None,
            actor_type: None,
            target_resource_type: Some("circuit_breaker".to_string()),
            target_resource_id: None,
            outcome: None,
            environment: None,
            date_from: Some(start_date.and_hms_opt(0, 0, 0).unwrap().and_utc()),
            date_to: Some(end_date.and_hms_opt(23, 59, 59).unwrap().and_utc()),
            page: Some(1),
            page_size: Some(100),
        };
        let audit_events = self.audit_repo.query(&audit_filter).await?;

        // Calculate average collateral ratio
        let mut total_ratio = BigDecimal::from(0);
        let count = history.data_points.len();
        for dp in &history.data_points {
            if let Ok(r) = dp.collateral_ratio.parse::<BigDecimal>() {
                total_ratio += r;
            }
        }
        let avg_ratio = if count > 0 {
            total_ratio / BigDecimal::from(count)
        } else {
            BigDecimal::from(0)
        };

        let data = AttestationReportData {
            month_name: month_name(month),
            year,
            average_collateral_ratio: avg_ratio,
            daily_breakdown: history.data_points,
            exceptional_events: audit_events.entries,
        };

        // 3. Generate PDF
        // Using a simplified mock PDF generation for this environment
        let pdf_bytes = self.create_pdf_buffer(&data).await?;

        // 4. Digital Signature
        let signed_pdf = self.sign_pdf_bytes(pdf_bytes).await?;

        Ok(signed_pdf)
    }

    async fn create_pdf_buffer(&self, _data: &AttestationReportData) -> Result<Vec<u8>, anyhow::Error> {
        // In a real implementation, this would use typst or genpdf.
        // For now, we return a mock PDF header + serialized data to simulate the document.
        let mut buffer = Vec::from("%PDF-1.4\n");
        buffer.extend_from_slice(format!("%% Month: {}, Year: {}\n", _data.month_name, _data.year).as_bytes());
        buffer.extend_from_slice(format!("%% Avg Ratio: {}\n", _data.average_collateral_ratio).as_bytes());
        buffer.extend_from_slice(b"%% [PDF CONTENT WOULD BE HERE]\n");
        Ok(buffer)
    }

    async fn sign_pdf_bytes(&self, pdf_bytes: Vec<u8>) -> Result<Vec<u8>, anyhow::Error> {
        // Load corporate key from env
        let key_hex = std::env::var("ATTESTATION_CORPORATE_KEY_HEX")
            .unwrap_or_else(|_| "0".repeat(64)); // Dev fallback
        
        let bytes = hex::decode(key_hex)?;
        let arr: [u8; 32] = bytes.try_into().map_err(|_| anyhow::anyhow!("Invalid key length"))?;
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&arr);
        
        use ed25519_dalek::Signer;
        let signature = signing_key.sign(&pdf_bytes);
        
        let mut final_pdf = pdf_bytes;
        final_pdf.extend_from_slice(b"\n%% SIGNATURE: ");
        final_pdf.extend_from_slice(hex::encode(signature.to_bytes()).as_bytes());
        Ok(final_pdf)
    }
}

fn month_name(month: u32) -> String {
    match month {
        1 => "January", 2 => "February", 3 => "March", 4 => "April",
        5 => "May", 6 => "June", 7 => "July", 8 => "August",
        9 => "September", 10 => "October", 11 => "November", 12 => "December",
        _ => "Unknown",
    }.to_string()
}
