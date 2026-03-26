//! CDN integration for edge-level DDoS absorption.
//! Supports Cloudflare and AWS CloudFront under-attack mode activation
//! and IP blocklist synchronisation.

use std::sync::Arc;
use tracing::{error, info, warn};

use crate::ddos::config::{CdnProvider, DdosConfig};

pub struct CdnClient {
    config: Arc<DdosConfig>,
    http: reqwest::Client,
}

impl CdnClient {
    pub fn new(config: Arc<DdosConfig>) -> Self {
        Self {
            config,
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .expect("failed to build CDN HTTP client"),
        }
    }

    /// Activate under-attack mode on the configured CDN provider.
    pub async fn activate_under_attack_mode(&self) {
        match &self.config.cdn_provider {
            CdnProvider::Cloudflare => self.cloudflare_set_security_level("under_attack").await,
            CdnProvider::CloudFront => self.cloudfront_enable_shield().await,
            CdnProvider::None => {
                warn!("CDN under-attack mode requested but no CDN provider configured");
            }
        }
    }

    /// Deactivate under-attack mode (return to normal).
    pub async fn deactivate_under_attack_mode(&self) {
        match &self.config.cdn_provider {
            CdnProvider::Cloudflare => self.cloudflare_set_security_level("medium").await,
            CdnProvider::CloudFront => {
                info!("CloudFront shield deactivation — manual action required");
            }
            CdnProvider::None => {}
        }
    }

    /// Push a list of IPs/CIDRs to the CDN firewall blocklist.
    pub async fn sync_blocked_ips(&self, ips: &[String]) {
        if ips.is_empty() {
            return;
        }
        match &self.config.cdn_provider {
            CdnProvider::Cloudflare => self.cloudflare_update_ip_list(ips).await,
            CdnProvider::CloudFront => {
                info!(count = ips.len(), "CloudFront IP sync — update WAF IP set");
            }
            CdnProvider::None => {
                info!(count = ips.len(), "No CDN configured — IP sync skipped");
            }
        }
    }

    async fn cloudflare_set_security_level(&self, level: &str) {
        let (token, zone_id) = match (
            self.config.cdn_api_token.as_deref(),
            self.config.cdn_zone_id.as_deref(),
        ) {
            (Some(t), Some(z)) => (t, z),
            _ => {
                warn!("Cloudflare API token or zone ID not configured");
                return;
            }
        };

        let url = format!(
            "https://api.cloudflare.com/client/v4/zones/{}/settings/security_level",
            zone_id
        );

        let body = serde_json::json!({ "value": level });

        match self
            .http
            .patch(&url)
            .bearer_auth(token)
            .json(&body)
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => {
                info!(level = level, "Cloudflare security level updated");
                crate::ddos::metrics::cdn_under_attack_activations()
                    .with_label_values(&["cloudflare"])
                    .inc();
            }
            Ok(resp) => {
                error!(status = %resp.status(), "Cloudflare API returned error");
            }
            Err(e) => {
                error!(error = %e, "Failed to call Cloudflare API");
            }
        }
    }

    async fn cloudflare_update_ip_list(&self, ips: &[String]) {
        let (token, zone_id) = match (
            self.config.cdn_api_token.as_deref(),
            self.config.cdn_zone_id.as_deref(),
        ) {
            (Some(t), Some(z)) => (t, z),
            _ => {
                warn!("Cloudflare credentials not configured for IP sync");
                return;
            }
        };

        // Cloudflare Firewall Rules API — create/update an IP access rule per IP
        // In production you'd batch these; here we log the intent.
        info!(
            count = ips.len(),
            zone_id = zone_id,
            "Syncing {} IPs to Cloudflare firewall",
            ips.len()
        );

        for ip in ips {
            let url = format!(
                "https://api.cloudflare.com/client/v4/zones/{}/firewall/access_rules/rules",
                zone_id
            );
            let body = serde_json::json!({
                "mode": "block",
                "configuration": { "target": "ip", "value": ip },
                "notes": "aframp-ddos-auto-block"
            });
            match self.http.post(&url).bearer_auth(token).json(&body).send().await {
                Ok(r) if r.status().is_success() => {}
                Ok(r) => warn!(ip = ip, status = %r.status(), "Cloudflare IP block failed"),
                Err(e) => error!(ip = ip, error = %e, "Cloudflare IP block request failed"),
            }
        }
    }

    async fn cloudfront_enable_shield(&self) {
        // AWS Shield Advanced activation is done via AWS SDK / CLI.
        // Here we log the intent; in production wire up the AWS SDK.
        info!("CloudFront under-attack mode: enable AWS Shield Advanced via SDK");
        crate::ddos::metrics::cdn_under_attack_activations()
            .with_label_values(&["cloudfront"])
            .inc();
    }
}
