-- Migration 016: add admin MFA flag + admin passkey credentials.

ALTER TABLE admins
ADD COLUMN IF NOT EXISTS mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE;

CREATE TABLE IF NOT EXISTS admin_passkey_credentials (
    id SERIAL PRIMARY KEY,
    admin_id INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
    tenant_id INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    credential_id VARCHAR NOT NULL,
    public_key TEXT NOT NULL,
    sign_count INTEGER NOT NULL DEFAULT 0,
    algorithm INTEGER NOT NULL DEFAULT -7,
    device_name VARCHAR DEFAULT 'Admin Device',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_used_at TIMESTAMP WITH TIME ZONE
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_admin_passkey_credential_unique
ON admin_passkey_credentials(credential_id);

CREATE INDEX IF NOT EXISTS idx_admin_passkey_admin_id
ON admin_passkey_credentials(admin_id);

CREATE INDEX IF NOT EXISTS idx_admin_passkey_tenant_id
ON admin_passkey_credentials(tenant_id);
