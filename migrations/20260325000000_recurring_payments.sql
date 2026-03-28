-- migrate:up
-- Recurring payments schema: schedules + execution history

CREATE TYPE recurring_frequency AS ENUM ('daily', 'weekly', 'monthly', 'custom');
CREATE TYPE recurring_status AS ENUM ('active', 'paused', 'cancelled', 'suspended');
CREATE TYPE execution_outcome AS ENUM ('success', 'failed', 'skipped');

CREATE TABLE recurring_payment_schedules (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    wallet_address      VARCHAR(255) NOT NULL
                            REFERENCES wallets(wallet_address) ON UPDATE CASCADE ON DELETE RESTRICT,
    transaction_type    TEXT NOT NULL CHECK (transaction_type IN ('bill_payment', 'onramp', 'offramp')),
    provider            TEXT,
    amount              NUMERIC(36, 18) NOT NULL CHECK (amount > 0),
    currency            TEXT NOT NULL,
    frequency           recurring_frequency NOT NULL,
    -- For custom frequency: interval in days (NULL for non-custom)
    custom_interval_days INT CHECK (custom_interval_days > 0),
    -- Payment-specific metadata (meter number, account number, etc.)
    payment_metadata    JSONB NOT NULL DEFAULT '{}'::jsonb,
    status              recurring_status NOT NULL DEFAULT 'active',
    failure_count       INT NOT NULL DEFAULT 0,
    -- Configurable threshold; NULL means use system default
    failure_threshold   INT NOT NULL DEFAULT 3,
    next_execution_at   TIMESTAMPTZ NOT NULL,
    last_executed_at    TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE recurring_payment_schedules IS 'User-defined recurring payment schedules.';
COMMENT ON COLUMN recurring_payment_schedules.custom_interval_days IS 'Only set when frequency = custom; number of days between executions.';
COMMENT ON COLUMN recurring_payment_schedules.payment_metadata IS 'Provider-specific fields (meter_number, account_number, etc.).';
COMMENT ON COLUMN recurring_payment_schedules.failure_count IS 'Consecutive failure count; reset to 0 on success.';
COMMENT ON COLUMN recurring_payment_schedules.failure_threshold IS 'Consecutive failures before auto-suspension.';

CREATE TABLE recurring_payment_executions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    schedule_id     UUID NOT NULL
                        REFERENCES recurring_payment_schedules(id) ON DELETE CASCADE,
    -- The scheduled timestamp this execution was for (idempotency key)
    scheduled_at    TIMESTAMPTZ NOT NULL,
    executed_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    outcome         execution_outcome NOT NULL,
    transaction_id  UUID REFERENCES transactions(transaction_id) ON DELETE SET NULL,
    error_message   TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE recurring_payment_executions IS 'Execution history for recurring payment schedules.';
COMMENT ON COLUMN recurring_payment_executions.scheduled_at IS 'The next_execution_at timestamp this run was for — used for idempotency.';

-- Idempotency: one execution record per (schedule, scheduled_at)
CREATE UNIQUE INDEX idx_recurring_executions_idempotency
    ON recurring_payment_executions(schedule_id, scheduled_at);

-- Worker query: find all active schedules due for execution
CREATE INDEX idx_recurring_schedules_due
    ON recurring_payment_schedules(next_execution_at, status)
    WHERE status = 'active';

CREATE INDEX idx_recurring_schedules_wallet
    ON recurring_payment_schedules(wallet_address, status);

CREATE TRIGGER set_updated_at_recurring_schedules
    BEFORE UPDATE ON recurring_payment_schedules
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
