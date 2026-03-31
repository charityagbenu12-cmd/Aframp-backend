use crate::database::transaction_repository::Transaction;
use minijinja::{path_loader, Environment, Value};
use serde_json::json;
use std::sync::Arc;

/// TemplateService for rendering notifications with Minijinja
pub struct TemplateService {
    env: Environment<'static>,
}

impl TemplateService {
    pub fn new(template_dir: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let mut env = Environment::new();
        env.set_loader(path_loader(template_dir));
        // Global functions/helpers
        env.add_template("base", include_str!("../templates/base.html"))?;
        env.add_global("format_amount", |args: &[Value]| -> Result<Value, minijinja::Error> {
            let amount = args.get(0).unwrap().as_f64().unwrap_or(0.0);
            Ok(Value::from(format!("NGN {:.2}", amount)))
        });
        env.add_global("stellar_explorer", |args: &[Value]| -> Result<Value, minijinja::Error> {
            let tx_hash = args.get(0).unwrap().as_str().unwrap_or("");
            Ok(Value::from(format!("https://stellar.expert/explorer/public/tx/{}", tx_hash)))
        });
        Ok(Self { env })
    }

    /// Render webhook JSON template
    pub fn render_webhook(&self, event_type: &str, tx: &Arc<Transaction>) -> Result<String, Box<dyn std::error::Error>> {
        let ctx = json!({
            "event": event_type,
            "timestamp": tx.updated_at,
            "transaction": {
                "id": tx.transaction_id.to_string(),
                "amount_ngn": tx.from_amount.to_string(),
                "amount_cngn": tx.cngn_amount.to_string(),
                "wallet_address": tx.wallet_address,
                "status": tx.status,
                "tx_hash": tx.blockchain_tx_hash.as_deref().unwrap_or(""),
                "reason": tx.error_message.as_deref().unwrap_or("")
            }
        });
        let tmpl = format!("{}.json", event_type.to_lowercase().replace("_", "-"));
        let rendered = self.env.render(&tmpl, ctx)?;
        Ok(rendered)
    }

    /// Render email HTML template
    pub fn render_email(&self, event_type: &str, tx: &Arc<Transaction>) -> Result<String, Box<dyn std::error::Error>> {
        let ctx = json!({
            "event": event_type,
            "timestamp": tx.updated_at,
            "transaction": {
                "id": tx.transaction_id.to_string(),
                "amount_ngn": tx.from_amount.to_string(),
                "amount_cngn": tx.cngn_amount.to_string(),
                "wallet": tx.wallet_address,
                "status": tx.status,
                "tx_hash": tx.blockchain_tx_hash.as_deref().unwrap_or(""),
                "reason": tx.error_message.as_deref().unwrap_or(""),
                "support_email": "support@aframp.com"
            }
        });
        let tmpl = format!("{}.html", event_type.to_lowercase().replace("_", "-"));
        let rendered = self.env.render(&tmpl, ctx)?;
        Ok(rendered)
    }
}

