-- migrate:up
-- Adaptive Rate Limiting Schema (Issue #XXX)
--
-- Tables:
--   1. adaptive_rl_signal_snapshots  — historical signal data for analysis
--   2. adaptive_rl_mode_transitions  — immutable audit trail of mode changes

-- ─── 1. Signal snapshots ─────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS adaptive_rl_signal_snapshots (
    id                      BIGSERIAL PRIMARY KEY,
    captured_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    cpu_utilisation         DOUBLE PRECISION NOT NULL CHECK (cpu_utilisation >= 0 AND cpu_utilisation <= 1),
    db_pool_utilisation     DOUBLE PRECISION NOT NULL CHECK (db_pool_utilisation >= 0 AND db_pool_utilisation <= 1),
    redis_memory_pressure   DOUBLE PRECISION NOT NULL CHECK (redis_memory_pressure >= 0 AND redis_memory_pressure <= 1),
    request_queue_depth     BIGINT NOT NULL CHECK (request_queue_depth >= 0),
    error_rate              DOUBLE PRECISION NOT NULL CHECK (error_rate >= 0 AND error_rate <= 1),
    p99_response_time_ms    DOUBLE PRECISION NOT NULL CHECK (p99_response_time_ms >= 0)
);

-- Partition by time for efficient range queries and retention management
CREATE INDEX IF NOT EXISTS idx_adaptive_rl_signals_captured_at
    ON adaptive_rl_signal_snapshots (captured_at DESC);

-- Retention: keep 30 days of signal history
-- (A scheduled job or pg_partman would handle this in production)
COMMENT ON TABLE adaptive_rl_signal_snapshots IS
    'Historical platform health signal snapshots for adaptive rate limiting analysis. Retain 30 days.';

-- ─── 2. Mode transitions ─────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS adaptive_rl_mode_transitions (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    from_mode           TEXT NOT NULL
                            CHECK (from_mode IN ('normal', 'elevated', 'critical', 'emergency')),
    to_mode             TEXT NOT NULL
                            CHECK (to_mode IN ('normal', 'elevated', 'critical', 'emergency')),
    trigger_signal      TEXT NOT NULL,
    -- Full signal snapshot at the time of transition (JSON for flexibility)
    signal_values       JSONB NOT NULL DEFAULT '{}',
    reason              TEXT NOT NULL,
    is_manual_override  BOOLEAN NOT NULL DEFAULT FALSE,
    transitioned_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_adaptive_rl_transitions_at
    ON adaptive_rl_mode_transitions (transitioned_at DESC);

CREATE INDEX IF NOT EXISTS idx_adaptive_rl_transitions_to_mode
    ON adaptive_rl_mode_transitions (to_mode, transitioned_at DESC);

COMMENT ON TABLE adaptive_rl_mode_transitions IS
    'Immutable audit trail of every adaptive rate limiting mode transition.';

-- ─── Grants (adjust role name to match your deployment) ──────────────────────
-- GRANT SELECT, INSERT ON adaptive_rl_signal_snapshots TO app_user;
-- GRANT SELECT, INSERT ON adaptive_rl_mode_transitions TO app_user;
-- GRANT USAGE, SELECT ON SEQUENCE adaptive_rl_signal_snapshots_id_seq TO app_user;
