-- OAuth 2.0 Scopes and Approvals
-- Manages scope definitions and sensitive scope approval workflow

-- OAuth Scopes Table
CREATE TABLE IF NOT EXISTS oauth_scopes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Scope metadata
    name VARCHAR(255) NOT NULL UNIQUE,
    description TEXT NOT NULL,
    category VARCHAR(50) NOT NULL,
    is_sensitive BOOLEAN NOT NULL DEFAULT false,
    
    -- Audit timestamps
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    
    -- Constraints
    CONSTRAINT oauth_scopes_name_format CHECK (name ~ '^[a-z_]+:[a-z_*]+$')
);

-- Scope Approval Requests Table
CREATE TABLE IF NOT EXISTS scope_approvals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Request details
    client_id VARCHAR(255) NOT NULL,
    scope_name VARCHAR(255) NOT NULL REFERENCES oauth_scopes(name),
    
    -- Status tracking
    status VARCHAR(20) NOT NULL DEFAULT 'pending', -- pending, approved, rejected
    
    -- Timestamps
    requested_at TIMESTAMP WITH TIME ZONE NOT NULL,
    approved_at TIMESTAMP WITH TIME ZONE,
    
    -- Approval details
    approved_by VARCHAR(255),
    rejection_reason TEXT,
    
    -- Audit timestamps
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    
    -- Constraints
    CONSTRAINT scope_approvals_status_check CHECK (status IN ('pending', 'approved', 'rejected')),
    CONSTRAINT scope_approvals_unique_pending UNIQUE (client_id, scope_name) WHERE status = 'pending'
);

-- Indexes for efficient queries
CREATE INDEX idx_oauth_scopes_category ON oauth_scopes(category);
CREATE INDEX idx_oauth_scopes_is_sensitive ON oauth_scopes(is_sensitive);
CREATE INDEX idx_scope_approvals_status ON scope_approvals(status);
CREATE INDEX idx_scope_approvals_client_id ON scope_approvals(client_id);
CREATE INDEX idx_scope_approvals_scope_name ON scope_approvals(scope_name);
CREATE INDEX idx_scope_approvals_requested_at ON scope_approvals(requested_at DESC);
CREATE INDEX idx_scope_approvals_client_scope ON scope_approvals(client_id, scope_name);

-- Comments for documentation
COMMENT ON TABLE oauth_scopes IS 'OAuth 2.0 scope definitions with metadata';
COMMENT ON COLUMN oauth_scopes.name IS 'Scope name in format resource:action';
COMMENT ON COLUMN oauth_scopes.is_sensitive IS 'Whether scope requires admin approval';

COMMENT ON TABLE scope_approvals IS 'Sensitive scope approval workflow';
COMMENT ON COLUMN scope_approvals.status IS 'Approval status: pending, approved, or rejected';
COMMENT ON COLUMN scope_approvals.approved_by IS 'Admin user ID who approved the scope';
