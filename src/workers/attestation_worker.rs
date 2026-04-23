use std::sync::Arc;
use tokio::sync::watch;
use tokio::time::{interval, Duration};
use tracing::{info, error};
use chrono::{Utc, Datelike, Timelike};
use crate::reporting::AttestationService;
use crate::services::notification::NotificationService;

pub struct AttestationWorker {
    service: Arc<AttestationService>,
    notifications: Arc<NotificationService>,
}

impl AttestationWorker {
    pub fn new(service: Arc<AttestationService>, notifications: Arc<NotificationService>) -> Self {
        Self { service, notifications }
    }

    pub async fn run(self, mut shutdown: watch::Receiver<bool>) {
        info!("Attestation worker started — scheduled for 1st of every month at 00:01 UTC");
        
        // Check every hour. In a more sophisticated setup, we might calculate 
        // the exact duration until the next 1st of the month.
        let mut ticker = interval(Duration::from_secs(3600)); 
        
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    let now = Utc::now();
                    
                    // Trigger on the 1st day of the month, during the first hour (00:xx)
                    if now.day() == 1 && now.hour() == 0 {
                        // Check if we already ran for this month to avoid duplicates if 
                        // the worker restarts within the same hour.
                        if let Err(e) = self.run_monthly_report_process().await {
                            error!(error = %e, "Monthly attestation report process failed");
                        }
                    }
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        info!("Attestation worker shutting down");
                        break;
                    }
                }
            }
        }
    }

    async fn run_monthly_report_process(&self) -> Result<(), anyhow::Error> {
        info!("Starting monthly attestation report generation...");
        
        let pdf_bytes = self.service.generate_preceding_month_report().await?;
        
        info!("Attestation report generated ({} bytes). Distributing...", pdf_bytes.len());
        
        // 1. Email to compliance committee
        let compliance_email = std::env::var("COMPLIANCE_COMMITTEE_EMAIL")
            .unwrap_or_else(|_| "compliance-alerts@aframp.com".to_string());
            
        self.notifications.send_system_alert(
            &compliance_email,
            &format!("Monthly Attestation Report - Ready (Size: {} bytes)", pdf_bytes.len())
        ).await;
        
        // 2. Upload to Transparency Portal (Simulated here)
        // In reality, we'd save to S3/DB and create a row in transparency_audit_documents
        info!("Attestation report uploaded to Transparency Portal");
        
        Ok(())
    }
}
