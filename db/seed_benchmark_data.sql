-- =============================================================================
-- Benchmark seed: generates ≥ 1 million transaction records for realistic
-- query profiling. Run against a local development database only.
--
-- Usage:
--   psql "$DATABASE_URL" -f db/seed_benchmark_data.sql
--
-- Runtime: ~2–5 minutes depending on hardware.
-- Disk:    ~800 MB for 1 M transactions + indexes.
-- =============================================================================

\set ON_ERROR_STOP on
\timing on

-- ---------------------------------------------------------------------------
-- 0. Guard: refuse to run against a production database
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF current_database() NOT IN ('aframp_test', 'aframp_dev', 'aframp_benchmark') THEN
        RAISE EXCEPTION
            'Refusing to seed benchmark data into database "%". '
            'Only aframp_test / aframp_dev / aframp_benchmark are allowed.',
            current_database();
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- 1. Seed users (1 000)
-- ---------------------------------------------------------------------------
INSERT INTO users (id, email, phone, created_at, updated_at)
SELECT
    gen_random_uuid(),
    'bench_user_' || n || '@example.com',
    '+234800' || lpad(n::text, 7, '0'),
    now() - (random() * INTERVAL '365 days'),
    now() - (random() * INTERVAL '30 days')
FROM generate_series(1, 1000) AS n
ON CONFLICT DO NOTHING;

-- ---------------------------------------------------------------------------
-- 2. Seed wallets (1 wallet per user, Stellar chain)
--    Includes realistic afri_balance and balance values for balance-check
--    query profiling.
-- ---------------------------------------------------------------------------
INSERT INTO wallets (id, user_id, wallet_address, chain, has_afri_trustline,
                     afri_balance, balance, last_balance_check, created_at, updated_at)
SELECT
    gen_random_uuid(),
    u.id,
    'G' || upper(md5(u.id::text || 'wallet')),
    'stellar',
    true,
    (random() * 50000)::numeric(36,18),
    ((random() * 50000)::numeric(36,18))::text,
    now() - (random() * INTERVAL '1 hour'),
-- ---------------------------------------------------------------------------
INSERT INTO wallets (id, user_id, wallet_address, chain, has_afri_trustline,
                     afri_balance, balance, created_at, updated_at)
SELECT
    gen_random_uuid(),
    u.id,
    'G' || upper(md5(u.id::text || 'wallet')),   -- deterministic fake Stellar address
    'stellar',
    true,
    (random() * 10000)::numeric(36,18),
    (random() * 10000)::text,
    u.created_at,
    u.created_at
FROM users u
WHERE u.email LIKE 'bench_user_%'
ON CONFLICT DO NOTHING;

-- ---------------------------------------------------------------------------
-- 3. Seed 1 000 000 transactions in batches of 10 000
--    Distribution:
--      types:     onramp (50%), offramp (35%), bill_payment (15%)
--      statuses:  completed (70%), failed (10%), pending (10%),
--                 processing (8%), payment_received (2%)
--      providers: paystack (40%), flutterwave (35%), mpesa (25%)
--      date range: last 365 days
-- 3. Seed 1 000 000 transactions
--    Distributed across:
--      - types:     onramp (50%), offramp (35%), bill_payment (15%)
--      - statuses:  completed (70%), failed (10%), pending (10%),
--                   processing (8%), payment_received (2%)
--      - providers: paystack (40%), flutterwave (35%), mpesa (25%)
--      - date range: last 365 days
-- ---------------------------------------------------------------------------
DO $$
DECLARE
    batch_size  INT := 10000;
    total       INT := 1000000;
    inserted    INT := 0;
    types       TEXT[] := ARRAY['onramp','onramp','onramp','onramp','onramp',
                                 'offramp','offramp','offramp','offramp',
                                 'bill_payment','bill_payment','bill_payment'];
    statuses    TEXT[] := ARRAY['completed','completed','completed','completed',
                                 'completed','completed','completed',
                                 'failed','pending','processing',
                                 'payment_received','pending_payment'];
    providers   TEXT[] := ARRAY['paystack','paystack','paystack','paystack',
                                 'flutterwave','flutterwave','flutterwave',
                                 'mpesa','mpesa','mpesa'];
    currencies  TEXT[] := ARRAY['NGN','KES','GHS','ZAR','UGX'];
BEGIN
    WHILE inserted < total LOOP
        INSERT INTO transactions (
            transaction_id, wallet_address, type,
            from_currency, to_currency,
            from_amount, to_amount, cngn_amount,
            status, payment_provider, payment_reference,
            blockchain_tx_hash, stellar_tx_hash, metadata,
            blockchain_tx_hash, metadata,
            created_at, updated_at
        )
        SELECT
            gen_random_uuid(),
            w.wallet_address,
            types[1 + (random() * (array_length(types,1)-1))::int],
            currencies[1 + (random() * (array_length(currencies,1)-1))::int],
            'cNGN',
            (100 + random() * 99900)::numeric(36,18),
            (100 + random() * 99900)::numeric(36,18),
            (100 + random() * 99900)::numeric(36,18),
            statuses[1 + (random() * (array_length(statuses,1)-1))::int],
            providers[1 + (random() * (array_length(providers,1)-1))::int],
            'REF-' || upper(md5(random()::text)),
            CASE WHEN random() > 0.3
                 THEN 'HASH-' || upper(md5(random()::text))
                 ELSE NULL END,
            CASE WHEN random() > 0.5
                 THEN upper(md5(random()::text))
                 ELSE NULL END,
            '{"source":"benchmark"}'::jsonb,
            now() - (random() * INTERVAL '365 days'),
            now() - (random() * INTERVAL '1 day')
        FROM (
            SELECT wallet_address
            FROM wallets
            WHERE wallet_address LIKE 'G%'
            ORDER BY random()
            LIMIT batch_size
        ) w;

        inserted := inserted + batch_size;
        RAISE NOTICE 'Inserted % / % transactions', inserted, total;
        COMMIT;
    END LOOP;
END $$;

-- ---------------------------------------------------------------------------
-- 4. Seed exchange rate history (for rate lookup profiling)
-- ---------------------------------------------------------------------------
INSERT INTO exchange_rates (id, from_currency, to_currency, rate, source, created_at, updated_at)
SELECT
    gen_random_uuid()::text,
    fc,
    'cNGN',
    ((random() * 1000) + 100)::text,
    'benchmark',
    now() - (n * INTERVAL '1 hour'),
    now() - (n * INTERVAL '1 hour')
FROM
    unnest(ARRAY['NGN','KES','GHS','ZAR','UGX']) AS fc,
    generate_series(0, 719) AS n   -- 30 days of hourly rates per pair
ON CONFLICT (from_currency, to_currency) DO NOTHING;

-- ---------------------------------------------------------------------------
-- 5. Update statistics so the planner uses the new data immediately
-- 4. Update statistics so the planner uses the new data immediately
-- ---------------------------------------------------------------------------
ANALYZE transactions;
ANALYZE wallets;
ANALYZE users;
ANALYZE exchange_rates;

\echo 'Benchmark seed complete.'
\echo 'Run EXPLAIN ANALYZE queries from DATABASE_OPTIMIZATIONS.md to profile.'
