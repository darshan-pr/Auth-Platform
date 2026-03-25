-- Migration 013: OAuth consent tracking
-- Stores whether a user has approved sharing identity (email) with a client app.

CREATE TABLE IF NOT EXISTS oauth_consents (
    id SERIAL PRIMARY KEY,
    tenant_id INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id VARCHAR NOT NULL,
    scope VARCHAR NOT NULL DEFAULT 'email',
    granted BOOLEAN NOT NULL DEFAULT TRUE,
    granted_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE (tenant_id, user_id, client_id)
);

CREATE INDEX IF NOT EXISTS idx_oauth_consents_client ON oauth_consents(client_id);
CREATE INDEX IF NOT EXISTS idx_oauth_consents_user ON oauth_consents(user_id);
