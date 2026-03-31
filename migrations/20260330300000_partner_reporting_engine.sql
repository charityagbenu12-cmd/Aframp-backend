-- Migration: Partner Reporting Engine
-- Multi-tenant partner data, corridor assignments, reporting audit

-- Settlement partners
CREATE TABLE IF NOT EXISTS partners (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL,
    finance_email   TEXT NOT NULL,
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Partner ↔ corridor assignments (multi-tenant isolation)
CREATE TABLE IF NOT EXISTS partner_corridors (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    partner_id      UUID NOT NULL REFERENCES partners(id) ON DELETE CASCADE,
    corridor_id     TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (partner_id, corridor_id)
);

-- Generated report metadata (for download history)
CREATE TABLE IF NOT EXISTS partner_reports (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    partner_id      UUID NOT NULL REFERENCES partners(id),
    corridor_id     TEXT NOT NULL,
    report_date     DATE NOT NULL,
    format          TEXT NOT NULL DEFAULT 'csv' CHECK (format IN ('csv', 'pdf')),
    download_url    TEXT,
    generated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_partner_corridors_partner
    ON partner_corridors(partner_id);
CREATE INDEX IF NOT EXISTS idx_partner_corridors_corridor
    ON partner_corridors(corridor_id);
CREATE INDEX IF NOT EXISTS idx_partner_reports_partner_date
    ON partner_reports(partner_id, report_date DESC);

-- Trigger
CREATE TRIGGER partners_updated_at
    BEFORE UPDATE ON partners
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

COMMENT ON TABLE partners IS 'Regional settlement partners with corridor access';
COMMENT ON TABLE partner_corridors IS 'Multi-tenant corridor assignments — enforces data isolation';
COMMENT ON TABLE partner_reports IS 'Audit trail of generated settlement reports';
