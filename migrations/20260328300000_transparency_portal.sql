-- Migration: Transparency Portal schema (Issue #239)
-- Creates the tables that back the public /v1/transparency/* endpoints.

-- ── Snapshots ────────────────────────────────────────────────────────────────
-- Populated by the Reconciliation Engine (#135) after each Deep Check.
-- The transparency API always reads the most-recent row.
CREATE TABLE IF NOT EXISTS transparency_snapshots (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    circulating_supply      NUMERIC(30, 8)  NOT NULL,
    total_fiat_ngn          NUMERIC(30, 8)  NOT NULL,
    collateralisation_ratio NUMERIC(10, 6)  NOT NULL,
    snapshot_at             TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    created_by              TEXT            NOT NULL DEFAULT 'reconciliation_engine'
);

CREATE INDEX IF NOT EXISTS idx_transparency_snapshots_at
    ON transparency_snapshots (snapshot_at DESC);

-- ── Reserve banks ─────────────────────────────────────────────────────────────
-- Anonymised per-bank fiat balances.  Updated alongside each snapshot.
CREATE TABLE IF NOT EXISTS transparency_reserve_banks (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    label            TEXT           NOT NULL,   -- e.g. "Partner Bank A"
    fiat_balance_ngn NUMERIC(30, 8) NOT NULL,
    currency         TEXT           NOT NULL DEFAULT 'NGN',
    snapshot_id      UUID           REFERENCES transparency_snapshots(id) ON DELETE CASCADE,
    updated_at       TIMESTAMPTZ    NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_transparency_reserve_banks_snapshot
    ON transparency_reserve_banks (snapshot_id);

-- ── Audit documents ───────────────────────────────────────────────────────────
-- Third-party attestation reports (PDFs) uploaded by the compliance team.
CREATE TABLE IF NOT EXISTS transparency_audit_documents (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title            TEXT        NOT NULL,
    period           TEXT        NOT NULL,   -- e.g. "Q1 2026"
    auditor          TEXT        NOT NULL,
    published_at     TIMESTAMPTZ NOT NULL,
    download_url     TEXT        NOT NULL,
    sha256_checksum  TEXT        NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_transparency_audit_docs_published
    ON transparency_audit_documents (published_at DESC);
