-- OAuth 2.0 Token Registry
-- Tracks issued access tokens for revocation and lifecycle management

CREATE TABLE IF NOT EXISTS token_registry (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Token identifiers
    jti VARCHAR(255) NOT NULL UNIQUE,
    consumer_id VARCHAR(255) NOT NULL,
    client_id VARCHAR(255) NOT NULL,
    
    -- Token metadata
    scope TEXT NOT NULL,
    issued_at TIMESTAMP WITH TIME ZONE NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    
    -- Revocation tracking
    revoked BOOLEAN NOT NULL DEFAULT false,
    revoked_at TIMESTAMP WITH TIME ZONE,
    
    -- Audit timestamps
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    
    -- Indexes for common queries
    CONSTRAINT token_registry_jti_unique UNIQUE (jti),
    CONSTRAINT token_registry_expires_check CHECK (expires_at > issued_at)
);

-- Indexes for efficient queries
CREATE INDEX idx_token_registry_consumer_id ON token_registry(consumer_id);
CREATE INDEX idx_token_registry_client_id ON token_registry(client_id);
CREATE INDEX idx_token_registry_jti ON token_registry(jti);
CREATE INDEX idx_token_registry_expires_at ON token_registry(expires_at);
CREATE INDEX idx_token_registry_revoked ON token_registry(revoked);
CREATE INDEX idx_token_registry_created_at ON token_registry(created_at);

-- Composite index for common queries
CREATE INDEX idx_token_registry_consumer_revoked_expires 
    ON token_registry(consumer_id, revoked, expires_at);

-- Comment for documentation
COMMENT ON TABLE token_registry IS 'OAuth 2.0 access token registry for tracking issued tokens, revocation status, and lifecycle management';
COMMENT ON COLUMN token_registry.jti IS 'JWT ID - unique token identifier';
COMMENT ON COLUMN token_registry.consumer_id IS 'Consumer/subject ID';
COMMENT ON COLUMN token_registry.client_id IS 'OAuth 2.0 client ID';
COMMENT ON COLUMN token_registry.scope IS 'Space-separated scopes granted to token';
COMMENT ON COLUMN token_registry.revoked IS 'Whether token has been revoked';
COMMENT ON COLUMN token_registry.revoked_at IS 'Timestamp when token was revoked';
