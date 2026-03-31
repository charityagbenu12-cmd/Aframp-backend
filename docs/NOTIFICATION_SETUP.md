# Notification System Setup

## Env Vars
```
NOTIFICATION_SMTP_SERVER=smtp.gmail.com
NOTIFICATION_SMTP_PORT=587
NOTIFICATION_SMTP_USER=your-app@gmail.com
NOTIFICATION_SMTP_PASS=app-password
NOTIFICATION_WEBHOOK_SECRET=your-hmac-secret
NOTIFICATION_PARTNER_WEBHOOK=https://partner.com/webhook
NOTIFICATION_SUPPORT_EMAIL=support@aframp.com
```

## Wiring in main.rs
```rust
let notification_service = NotificationService::new(
    notification_repo,
    tx_repo,
    templates,
    smtp_server,
    smtp_port,
    smtp_user,
    smtp_pass,
    webhook_secret,
    partner_url,
    support_email,
)?;
let processor = OnrampProcessor::new(db.clone(), stellar, orchestrator, config, Arc::new(notification_service));
```

## DB Migration
```bash
sqlx migrate run
```

## Test
1. POST /api/onramp/quote
2. Simulate webhook success
3. Check notification_history + email/webhook delivery

