-- Admin Access Control Schema Migration
-- This migration creates the complete admin access control system

-- Create custom types for admin roles and statuses
CREATE TYPE admin_role AS ENUM (
    'super_admin',
    'operations_admin', 
    'security_admin',
    'compliance_admin',
    'read_only_admin'
);

CREATE TYPE admin_status AS ENUM (
    'pending_setup',
    'active',
    'suspended',
    'locked'
);

CREATE TYPE mfa_status AS ENUM (
    'not_configured',
    'configured',
    'required_reconfigure'
);

CREATE TYPE session_status AS ENUM (
    'active',
    'expired',
    'terminated',
    'revoked'
);

CREATE TYPE audit_action_type AS ENUM (
    'account_created',
    'account_suspended',
    'account_reinstated',
    'role_updated',
    'password_changed',
    'mfa_configured',
    'mfa_disabled',
    'session_created',
    'session_terminated',
    'permission_granted',
    'permission_revoked',
    'sensitive_action_executed',
    'login_attempt',
    'login_success',
    'login_failure',
    'account_locked',
    'account_unlocked'
);

-- Admin roles table
CREATE TABLE admin_roles (
    id admin_role PRIMARY KEY,
    description TEXT NOT NULL,
    max_accounts INTEGER NOT NULL DEFAULT 10,
    session_lifetime_minutes INTEGER NOT NULL,
    inactivity_timeout_minutes INTEGER NOT NULL,
    max_concurrent_sessions INTEGER NOT NULL DEFAULT 3,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Permissions table
CREATE TABLE admin_permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) NOT NULL UNIQUE,
    description TEXT NOT NULL,
    category VARCHAR(50) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Role permissions mapping
CREATE TABLE admin_role_permissions (
    role admin_role NOT NULL REFERENCES admin_roles(id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES admin_permissions(id) ON DELETE CASCADE,
    granted_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    granted_by UUID REFERENCES admin_accounts(id),
    PRIMARY KEY (role, permission_id)
);

-- Admin accounts table
CREATE TABLE admin_accounts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    full_name VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role admin_role NOT NULL REFERENCES admin_roles(id),
    status admin_status NOT NULL DEFAULT 'pending_setup',
    mfa_status mfa_status NOT NULL DEFAULT 'not_configured',
    mfa_secret VARCHAR(255), -- TOTP secret
    fido2_credentials JSONB, -- WebAuthn credentials
    last_login_at TIMESTAMP WITH TIME ZONE,
    last_login_ip INET,
    failed_login_count INTEGER NOT NULL DEFAULT 0,
    account_locked_until TIMESTAMP WITH TIME ZONE,
    password_changed_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    mfa_configured_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_by UUID REFERENCES admin_accounts(id)
);

-- Admin sessions table
CREATE TABLE admin_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    admin_id UUID NOT NULL REFERENCES admin_accounts(id) ON DELETE CASCADE,
    issued_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    last_activity_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    ip_address INET NOT NULL,
    user_agent TEXT NOT NULL,
    mfa_verified BOOLEAN NOT NULL DEFAULT false,
    status session_status NOT NULL DEFAULT 'active',
    termination_reason TEXT,
    terminated_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Admin action audit trail
CREATE TABLE admin_audit_trail (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    admin_id UUID REFERENCES admin_accounts(id),
    session_id UUID REFERENCES admin_sessions(id),
    action_type audit_action_type NOT NULL,
    target_resource_type VARCHAR(100),
    target_resource_id UUID,
    action_detail JSONB,
    before_state JSONB,
    after_state JSONB,
    ip_address INET,
    user_agent TEXT,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    previous_entry_hash VARCHAR(64), -- SHA-256 hash of previous entry
    current_entry_hash VARCHAR(64) NOT NULL, -- SHA-256 hash of this entry
    sequence_number BIGSERIAL NOT NULL
);

-- Sensitive action confirmations
CREATE TABLE admin_sensitive_confirmations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    admin_id UUID NOT NULL REFERENCES admin_accounts(id) ON DELETE CASCADE,
    session_id UUID NOT NULL REFERENCES admin_sessions(id) ON DELETE CASCADE,
    action_type VARCHAR(100) NOT NULL,
    target_resource_type VARCHAR(100),
    target_resource_id UUID,
    confirmation_method VARCHAR(50) NOT NULL, -- 'password', 'totp', 'fido2'
    confirmation_data JSONB,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    used_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Permission escalation requests
CREATE TABLE admin_permission_escalations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    requester_id UUID NOT NULL REFERENCES admin_accounts(id) ON DELETE CASCADE,
    requested_permission_id UUID NOT NULL REFERENCES admin_permissions(id),
    reason TEXT NOT NULL,
    duration_minutes INTEGER NOT NULL DEFAULT 60,
    status VARCHAR(50) NOT NULL DEFAULT 'pending', -- 'pending', 'approved', 'rejected', 'expired'
    approved_by UUID REFERENCES admin_accounts(id),
    approved_at TIMESTAMP WITH TIME ZONE,
    expires_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Admin security events for monitoring
CREATE TABLE admin_security_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    admin_id UUID REFERENCES admin_accounts(id),
    event_type VARCHAR(100) NOT NULL, -- 'impossible_travel', 'new_device', 'unusual_hours', 'failed_login_spike'
    event_data JSONB NOT NULL,
    severity VARCHAR(20) NOT NULL DEFAULT 'medium', -- 'low', 'medium', 'high', 'critical'
    resolved BOOLEAN NOT NULL DEFAULT false,
    resolved_by UUID REFERENCES admin_accounts(id),
    resolved_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Insert default admin roles
INSERT INTO admin_roles (id, description, max_accounts, session_lifetime_minutes, inactivity_timeout_minutes, max_concurrent_sessions) VALUES
('super_admin', 'Full system access with all permissions', 3, 60, 15, 2),
('operations_admin', 'Transaction management and KYC review', 5, 240, 30, 3),
('security_admin', 'Security controls and IP management', 3, 180, 20, 2),
('compliance_admin', 'KYC decisions and regulatory reporting', 5, 240, 30, 3),
('read_only_admin', 'View-only access across all areas', 10, 480, 60, 5);

-- Insert default permissions
INSERT INTO admin_permissions (name, description, category) VALUES
-- Account management
('admin.create', 'Create new admin accounts', 'account_management'),
('admin.update_role', 'Update admin account roles', 'account_management'),
('admin.suspend', 'Suspend admin accounts', 'account_management'),
('admin.reinstate', 'Reinstate suspended admin accounts', 'account_management'),
('admin.view', 'View admin account details', 'account_management'),
('admin.list', 'List all admin accounts', 'account_management'),

-- Security management
('security.mfa_manage', 'Manage MFA settings', 'security'),
('security.session_manage', 'Manage admin sessions', 'security'),
('security.audit_view', 'View audit trail', 'security'),
('security.audit_verify', 'Verify audit trail integrity', 'security'),
('security.monitoring', 'Access security monitoring dashboard', 'security'),
('security.ip_whitelist', 'Manage IP whitelist', 'security'),

-- Operations
('operations.transaction_view', 'View all transactions', 'operations'),
('operations.transaction_manage', 'Manage transactions', 'operations'),
('operations.kyc_review', 'Review KYC submissions', 'operations'),
('operations.kyc_approve', 'Approve KYC submissions', 'operations'),
('operations.kyc_reject', 'Reject KYC submissions', 'operations'),

-- Compliance
('compliance.reporting', 'Generate compliance reports', 'compliance'),
('compliance.regulatory_view', 'Access regulatory data', 'compliance'),
('compliance.audit_export', 'Export audit data', 'compliance'),

-- System
('system.config_view', 'View system configuration', 'system'),
('system.config_update', 'Update system configuration', 'system'),
('system.metrics_view', 'View system metrics', 'system'),
('system.health_check', 'Perform system health checks', 'system');

-- Grant all permissions to super admin
INSERT INTO admin_role_permissions (role, permission_id)
SELECT 'super_admin', id FROM admin_permissions;

-- Grant specific permissions to other roles
INSERT INTO admin_role_permissions (role, permission_id)
SELECT 'operations_admin', id FROM admin_permissions 
WHERE name IN (
    'operations.transaction_view', 'operations.transaction_manage',
    'operations.kyc_review', 'operations.kyc_approve', 'operations.kyc_reject',
    'admin.view', 'admin.list'
);

INSERT INTO admin_role_permissions (role, permission_id)
SELECT 'security_admin', id FROM admin_permissions 
WHERE name IN (
    'security.mfa_manage', 'security.session_manage', 'security.audit_view',
    'security.audit_verify', 'security.monitoring', 'security.ip_whitelist',
    'admin.view', 'admin.list'
);

INSERT INTO admin_role_permissions (role, permission_id)
SELECT 'compliance_admin', id FROM admin_permissions 
WHERE name IN (
    'compliance.reporting', 'compliance.regulatory_view', 'compliance.audit_export',
    'operations.transaction_view', 'operations.kyc_review',
    'admin.view', 'admin.list'
);

INSERT INTO admin_role_permissions (role, permission_id)
SELECT 'read_only_admin', id FROM admin_permissions 
WHERE name IN (
    'operations.transaction_view', 'operations.kyc_review',
    'compliance.regulatory_view', 'system.config_view', 'system.metrics_view',
    'security.audit_view', 'admin.view', 'admin.list'
);

-- Create indexes for performance
CREATE INDEX idx_admin_accounts_email ON admin_accounts(email);
CREATE INDEX idx_admin_accounts_role ON admin_accounts(role);
CREATE INDEX idx_admin_accounts_status ON admin_accounts(status);
CREATE INDEX idx_admin_sessions_admin_id ON admin_sessions(admin_id);
CREATE INDEX idx_admin_sessions_status ON admin_sessions(status);
CREATE INDEX idx_admin_sessions_expires_at ON admin_sessions(expires_at);
CREATE INDEX idx_admin_audit_trail_admin_id ON admin_audit_trail(admin_id);
CREATE INDEX idx_admin_audit_trail_timestamp ON admin_audit_trail(timestamp);
CREATE INDEX idx_admin_audit_trail_action_type ON admin_audit_trail(action_type);
CREATE INDEX idx_admin_audit_trail_sequence ON admin_audit_trail(sequence_number);
CREATE INDEX idx_admin_security_events_admin_id ON admin_security_events(admin_id);
CREATE INDEX idx_admin_security_events_event_type ON admin_security_events(event_type);
CREATE INDEX idx_admin_security_events_created_at ON admin_security_events(created_at);

-- Create trigger for updating updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_admin_accounts_updated_at BEFORE UPDATE ON admin_accounts
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_admin_roles_updated_at BEFORE UPDATE ON admin_roles
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_admin_permissions_updated_at BEFORE UPDATE ON admin_permissions
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Create function to generate audit trail hash chain
CREATE OR REPLACE FUNCTION generate_audit_hash()
RETURNS TRIGGER AS $$
DECLARE
    previous_hash VARCHAR(64);
    entry_data TEXT;
BEGIN
    -- Get previous entry hash
    SELECT COALESCE(current_entry_hash, '0'::VARCHAR(64)) INTO previous_hash
    FROM admin_audit_trail 
    WHERE sequence_number = NEW.sequence_number - 1;

    -- Build entry data for hashing
    entry_data := NEW.admin_id::TEXT || 
                  NEW.session_id::TEXT || 
                  NEW.action_type::TEXT || 
                  NEW.target_resource_type::TEXT || 
                  NEW.target_resource_id::TEXT || 
                  COALESCE(NEW.action_detail::TEXT, '') || 
                  COALESCE(NEW.before_state::TEXT, '') || 
                  COALESCE(NEW.after_state::TEXT, '') || 
                  COALESCE(NEW.ip_address::TEXT, '') || 
                  COALESCE(NEW.user_agent, '') || 
                  NEW.timestamp::TEXT || 
                  previous_hash;

    -- Generate SHA-256 hash
    NEW.current_entry_hash := encode(sha256(entry_data::bytea), 'hex');
    NEW.previous_entry_hash := previous_hash;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER generate_audit_hash_trigger BEFORE INSERT ON admin_audit_trail
    FOR EACH ROW EXECUTE FUNCTION generate_audit_hash();

-- Add constraint to ensure hash chain integrity
ALTER TABLE admin_audit_trail ADD CONSTRAINT check_hash_chain 
    CHECK (previous_entry_hash IS NULL OR sequence_number = 1 OR 
           previous_entry_hash = (SELECT current_entry_hash FROM admin_audit_trail t2 
                                 WHERE t2.sequence_number = admin_audit_trail.sequence_number - 1));

-- Create view for active admin sessions with admin details
CREATE VIEW admin_active_sessions AS
SELECT 
    s.id,
    s.admin_id,
    a.full_name,
    a.email,
    a.role,
    s.issued_at,
    s.expires_at,
    s.last_activity_at,
    s.ip_address,
    s.user_agent,
    s.mfa_verified
FROM admin_sessions s
JOIN admin_accounts a ON s.admin_id = a.id
WHERE s.status = 'active' AND s.expires_at > NOW();

-- Create view for admin audit trail with admin details
CREATE VIEW admin_audit_trail_detailed AS
SELECT 
    at.id,
    at.admin_id,
    a.full_name,
    a.email,
    a.role,
    at.session_id,
    at.action_type,
    at.target_resource_type,
    at.target_resource_id,
    at.action_detail,
    at.before_state,
    at.after_state,
    at.ip_address,
    at.user_agent,
    at.timestamp,
    at.sequence_number,
    at.previous_entry_hash,
    at.current_entry_hash
FROM admin_audit_trail at
LEFT JOIN admin_accounts a ON at.admin_id = a.id;
