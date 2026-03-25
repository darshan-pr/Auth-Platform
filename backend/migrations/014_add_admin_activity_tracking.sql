-- Migration 014: admin personal auth activity + session tracking

CREATE TABLE IF NOT EXISTS admin_sessions (
    id SERIAL PRIMARY KEY,
    session_id VARCHAR NOT NULL UNIQUE,
    admin_id INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
    tenant_id INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_agent TEXT,
    browser VARCHAR,
    device VARCHAR,
    ip_address VARCHAR,
    city VARCHAR,
    region VARCHAR,
    country VARCHAR,
    isp VARCHAR,
    login_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_seen_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE,
    is_revoked BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_at TIMESTAMP WITH TIME ZONE,
    revoked_reason VARCHAR
);

CREATE INDEX IF NOT EXISTS idx_admin_sessions_admin_id ON admin_sessions(admin_id);
CREATE INDEX IF NOT EXISTS idx_admin_sessions_tenant_id ON admin_sessions(tenant_id);
CREATE INDEX IF NOT EXISTS idx_admin_sessions_active ON admin_sessions(admin_id, is_revoked, expires_at);

CREATE TABLE IF NOT EXISTS admin_activity_events (
    id SERIAL PRIMARY KEY,
    admin_id INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
    tenant_id INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    session_id VARCHAR,
    event_type VARCHAR NOT NULL,
    method VARCHAR,
    resource VARCHAR,
    details VARCHAR,
    user_agent TEXT,
    browser VARCHAR,
    device VARCHAR,
    ip_address VARCHAR,
    city VARCHAR,
    region VARCHAR,
    country VARCHAR,
    isp VARCHAR,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_admin_activity_admin_id ON admin_activity_events(admin_id);
CREATE INDEX IF NOT EXISTS idx_admin_activity_tenant_id ON admin_activity_events(tenant_id);
CREATE INDEX IF NOT EXISTS idx_admin_activity_created_at ON admin_activity_events(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_admin_activity_session_id ON admin_activity_events(session_id);
