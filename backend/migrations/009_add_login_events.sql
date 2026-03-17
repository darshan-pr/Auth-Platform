-- Migration 009: Add login_events table for IP & location tracking
-- Stores every authentication event with client IP and geo data.
-- This migration is IDEMPOTENT — safe to run multiple times.

CREATE TABLE IF NOT EXISTS login_events (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    app_id VARCHAR,
    tenant_id INTEGER REFERENCES tenants(id),
    event_type VARCHAR NOT NULL,
    ip_address VARCHAR,
    city VARCHAR,
    region VARCHAR,
    country VARCHAR,
    lat DOUBLE PRECISION,
    lon DOUBLE PRECISION,
    isp VARCHAR,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Indexes for efficient querying
CREATE INDEX IF NOT EXISTS idx_login_events_user_id ON login_events(user_id);
CREATE INDEX IF NOT EXISTS idx_login_events_tenant_id ON login_events(tenant_id);
CREATE INDEX IF NOT EXISTS idx_login_events_event_type ON login_events(event_type);
CREATE INDEX IF NOT EXISTS idx_login_events_created_at ON login_events(created_at);
CREATE INDEX IF NOT EXISTS idx_login_events_ip_address ON login_events(ip_address);
