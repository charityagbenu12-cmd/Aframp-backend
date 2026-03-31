-- External Auditor Portal Schema
-- Provides restricted, read-only access for third-party auditors (e.g. Big Four, CBN).

-- ── Auditor accounts ──────────────────────────────────────────────────────────
CREATE TABLE auditor_accounts (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email           TEXT NOT NULL UNIQUE,
    display_name    TEXT NOT NULL,
    organisation    TEXT NOT NULL,
    -- Argon2id hash of the password
    password_hash   TEXT NOT NULL,
    -- TOTP secret (encrypted at rest via platform key)
    totp_secret_enc TEXT,
    mfa_enabled     BOOLEAN NOT NULL DEFAULT FALSE,
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── IP whitelist ──────────────────────────────────────────────────────────────
CREATE TABLE auditor_ip_whitelist (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    auditor_id      UUID NOT NULL REFERENCES auditor_accounts(id) ON DELETE CASCADE,
    -- CIDR notation, e.g. "203.0.113.0/24"
    cidr            INET NOT NULL,
    label           TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_auditor_ip_whitelist_auditor ON auditor_ip_whitelist(auditor_id);

-- ── Audit windows (time-limited access grants) ────────────────────────────────
CREATE TABLE auditor_access_windows (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    auditor_id      UUID NOT NULL REFERENCES auditor_accounts(id) ON DELETE CASCADE,
    -- Scope: fiscal quarter label, e.g. "Q1-2026"
    scope_label     TEXT NOT NULL,
    -- Restrict data access to this date range
    data_from       TIMESTAMPTZ NOT NULL,
    data_to         TIMESTAMPTZ NOT NULL,
    -- Portal login allowed within this window
    access_from     TIMESTAMPTZ NOT NULL,
    access_to       TIMESTAMPTZ NOT NULL,
    granted_by      UUID,   -- admin_accounts.id
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_auditor_windows_auditor ON auditor_access_windows(auditor_id);

-- ── Sessions ──────────────────────────────────────────────────────────────────
CREATE TABLE auditor_sessions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    auditor_id      UUID NOT NULL REFERENCES auditor_accounts(id) ON DELETE CASCADE,
    window_id       UUID NOT NULL REFERENCES auditor_access_windows(id) ON DELETE CASCADE,
    session_token   TEXT NOT NULL UNIQUE,
    ip_address      INET NOT NULL,
    user_agent      TEXT,
    expires_at      TIMESTAMPTZ NOT NULL,
    terminated_at   TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_auditor_sessions_token   ON auditor_sessions(session_token);
CREATE INDEX idx_auditor_sessions_auditor ON auditor_sessions(auditor_id);

-- ── Audit-of-the-auditor access log ──────────────────────────────────────────
CREATE TABLE auditor_access_log (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id      UUID NOT NULL REFERENCES auditor_sessions(id) ON DELETE CASCADE,
    auditor_id      UUID NOT NULL REFERENCES auditor_accounts(id) ON DELETE CASCADE,
    action          TEXT NOT NULL,   -- e.g. "export_csv", "query_events", "verify_hash_chain"
    query_params    JSONB,
    row_count       BIGINT,
    -- SHA-256 of the exported file bytes (NULL for non-file actions)
    file_checksum   TEXT,
    file_name       TEXT,
    ip_address      INET NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_auditor_access_log_session  ON auditor_access_log(session_id);
CREATE INDEX idx_auditor_access_log_auditor  ON auditor_access_log(auditor_id);
CREATE INDEX idx_auditor_access_log_created  ON auditor_access_log(created_at DESC);

-- ── Quarterly audit packets ───────────────────────────────────────────────────
CREATE TABLE auditor_quarterly_packets (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    quarter_label   TEXT NOT NULL UNIQUE,   -- e.g. "Q1-2026"
    data_from       TIMESTAMPTZ NOT NULL,
    data_to         TIMESTAMPTZ NOT NULL,
    -- SHA-256 of the generated ZIP/JSON bundle
    checksum        TEXT NOT NULL,
    row_count       BIGINT NOT NULL,
    generated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    generated_by    TEXT NOT NULL DEFAULT 'system'
);
