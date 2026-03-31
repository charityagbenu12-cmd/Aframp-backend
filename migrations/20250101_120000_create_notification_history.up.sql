-- Create notification_history table for audit trail
-- Stores all sent notifications for each mint request (tx_id)

CREATE TABLE IF NOT EXISTS notification_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    transaction_id UUID NOT NULL REFERENCES transactions(transaction_id) ON DELETE CASCADE,
    event_type VARCHAR(50) NOT NULL,  -- MINT_RECEIVED, FIAT_CONFIRMED, etc.
    channel VARCHAR(20) NOT NULL CHECK (channel IN ('webhook', 'email', 'internal')),  -- Delivery channel
    recipient VARCHAR(500),  -- Webhook URL or email address
    payload JSONB NOT NULL,  -- Rendered template content
    status VARCHAR(20) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'delivered', 'failed')),
    retry_count INTEGER DEFAULT 0,
    error_message TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_notification_history_tx_id ON notification_history(transaction_id);
CREATE INDEX IF NOT EXISTS idx_notification_history_status ON notification_history(status);
CREATE INDEX IF NOT EXISTS idx_notification_history_created ON notification_history(created_at);

-- Trigger for updated_at
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_notification_history_updated_at
    BEFORE UPDATE ON notification_history
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

