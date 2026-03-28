-- OAuth 2.0 Refresh Token Management
-- Implements secure refresh token storage with family tracking for theft detection

CREATE TABLE IF NOT EXISTS refresh_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Token identifiers
    token_id VARCHAR(255) NOT NULL UNIQUE,
    family_id VARCHAR(255) NOT NULL,
    
    -- Token hash (never store plaintext)
    token_hash VARCHAR(255) NOT NULL,
    
    -- Consumer and client info
    consumer_id VARCHAR(255) NOT NULL,
    client_id VARCHAR(255) NOT NULL,
    
    -- Token metadata
    scope TEXT NOT NULL,
    
    -- Timestamps
    issued_at TIMESTAMP WITH TIME ZONE NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    family_expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    last_used_at TIMESTAMP WITH TIME ZONE,
    
    -- Token relationships (for rotation)
    parent_token_id VARCHAR(255),
    replacement_token_id VARCHAR(255),
    
    -- Status tracking
    status VARCHAR(50) NOT NULL DEFAULT 'active',
    
    -- Audit timestamps
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    
    -- Constraints
    CONSTRAINT refresh_tokens_token_id_unique UNIQUE (token_id),
    CONSTRAINT refresh_tokens_expires_check CHECK (expires_at > issued_at),
    CONSTRAINT refresh_tokens_family_expires_check CHECK (family_expires_at > issued_at),
    CONSTRAINT refresh_tokens_status_check CHECK (status IN ('active', 'used', 'revoked', 'expired'))
);

-- Indexes for efficient queries
CREATE INDEX idx_refresh_tokens_token_id ON refresh_tokens(token_id);
CREATE INDEX idx_refresh_tokens_family_id ON refresh_tokens(family_id);
CREATE INDEX idx_refresh_tokens_consumer_id ON refresh_tokens(consumer_id);
CREATE INDEX idx_refresh_tokens_client_id ON refresh_tokens(client_id);
CREATE INDEX idx_refresh_tokens_expires_at ON refresh_tokens(expires_at);
CREATE INDEX idx_refresh_tokens_family_expires_at ON refresh_tokens(family_expires_at);
CREATE INDEX idx_refresh_tokens_status ON refresh_tokens(status);
CREATE INDEX idx_refresh_tokens_created_at ON refresh_tokens(created_at);

-- Composite indexes for common queries
CREATE INDEX idx_refresh_tokens_consumer_status_expires 
    ON refresh_tokens(consumer_id, status, expires_at);

CREATE INDEX idx_refresh_tokens_family_status 
    ON refresh_tokens(family_id, status);

CREATE INDEX idx_refresh_tokens_parent_token 
    ON refresh_tokens(parent_token_id);

-- Comments for documentation
COMMENT ON TABLE refresh_tokens IS 'OAuth 2.0 refresh token storage with family tracking for theft detection and rotation';
COMMENT ON COLUMN refresh_tokens.token_id IS 'Unique token identifier (UUID)';
COMMENT ON COLUMN refresh_tokens.family_id IS 'Token family ID for tracking rotations and theft detection';
COMMENT ON COLUMN refresh_tokens.token_hash IS 'Argon2id hash of the refresh token (never store plaintext)';
COMMENT ON COLUMN refresh_tokens.consumer_id IS 'Consumer/subject ID';
COMMENT ON COLUMN refresh_tokens.client_id IS 'OAuth 2.0 client ID';
COMMENT ON COLUMN refresh_tokens.scope IS 'Space-separated scopes granted to token';
COMMENT ON COLUMN refresh_tokens.status IS 'Token status: active, used, revoked, or expired';
COMMENT ON COLUMN refresh_tokens.family_expires_at IS 'Absolute expiry for entire token family (30 days)';
COMMENT ON COLUMN refresh_tokens.parent_token_id IS 'Parent token ID for rotation tracking';
COMMENT ON COLUMN refresh_tokens.replacement_token_id IS 'Replacement token ID when rotated';
