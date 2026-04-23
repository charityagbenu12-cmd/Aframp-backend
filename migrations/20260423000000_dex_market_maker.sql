-- Market Maker Cycle Logs
-- Feeds the Market Operations Dashboard (#1.08).

CREATE TYPE dex_order_side   AS ENUM ('bid', 'ask');
CREATE TYPE dex_order_type   AS ENUM ('passive', 'active');
CREATE TYPE dex_order_status AS ENUM ('open', 'filled', 'cancelled', 'requoted');

-- Per-cycle summary log (one row per market-making cycle).
CREATE TABLE IF NOT EXISTS market_maker_cycle_logs (
    id                      UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    cycle_at                TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    reference_price         DOUBLE PRECISION NOT NULL,
    bid_price               DOUBLE PRECISION NOT NULL DEFAULT 0,
    ask_price               DOUBLE PRECISION NOT NULL DEFAULT 0,
    spread_pct              DOUBLE PRECISION NOT NULL DEFAULT 0,
    orders_placed           INTEGER     NOT NULL DEFAULT 0,
    orders_cancelled        INTEGER     NOT NULL DEFAULT 0,
    circuit_breaker_tripped BOOLEAN     NOT NULL DEFAULT FALSE,
    inventory_cngn          DOUBLE PRECISION NOT NULL DEFAULT 0,
    inventory_counter       DOUBLE PRECISION NOT NULL DEFAULT 0,
    notes                   TEXT
);

-- Individual DEX orders placed by the bot.
CREATE TABLE IF NOT EXISTS market_maker_orders (
    id               UUID             PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at       TIMESTAMPTZ      NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ      NOT NULL DEFAULT NOW(),
    stellar_offer_id BIGINT,
    side             dex_order_side   NOT NULL,
    order_type       dex_order_type   NOT NULL,
    price            DOUBLE PRECISION NOT NULL,
    amount_cngn      DOUBLE PRECISION NOT NULL,
    status           dex_order_status NOT NULL DEFAULT 'open',
    reference_price  DOUBLE PRECISION NOT NULL,
    rung             INTEGER          NOT NULL DEFAULT 0
);

CREATE INDEX idx_mm_cycle_logs_cycle_at   ON market_maker_cycle_logs (cycle_at DESC);
CREATE INDEX idx_mm_orders_status         ON market_maker_orders (status);
CREATE INDEX idx_mm_orders_stellar_offer  ON market_maker_orders (stellar_offer_id);
