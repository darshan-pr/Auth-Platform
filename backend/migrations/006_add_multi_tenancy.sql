-- Migration 006: Add Multi-Tenancy Support
-- Creates tenants table and adds tenant_id to all relevant tables

-- 1. Create tenants table
CREATE TABLE IF NOT EXISTS tenants (
    id SERIAL PRIMARY KEY,
    name VARCHAR NOT NULL,
    slug VARCHAR UNIQUE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE
);
CREATE INDEX IF NOT EXISTS idx_tenants_slug ON tenants(slug);

-- 2. Create a default tenant for existing data migration
INSERT INTO tenants (name, slug) VALUES ('Default', 'default')
ON CONFLICT (slug) DO NOTHING;

-- 3. Add tenant_id to admins
ALTER TABLE admins ADD COLUMN IF NOT EXISTS tenant_id INTEGER REFERENCES tenants(id);
UPDATE admins SET tenant_id = (SELECT id FROM tenants WHERE slug = 'default') WHERE tenant_id IS NULL;
ALTER TABLE admins ALTER COLUMN tenant_id SET NOT NULL;

-- 4. Add tenant_id to apps
ALTER TABLE apps ADD COLUMN IF NOT EXISTS tenant_id INTEGER REFERENCES tenants(id);
UPDATE apps SET tenant_id = (SELECT id FROM tenants WHERE slug = 'default') WHERE tenant_id IS NULL;
ALTER TABLE apps ALTER COLUMN tenant_id SET NOT NULL;
CREATE INDEX IF NOT EXISTS idx_apps_tenant_id ON apps(tenant_id);

-- 5. Add tenant_id to users
ALTER TABLE users ADD COLUMN IF NOT EXISTS tenant_id INTEGER REFERENCES tenants(id);
UPDATE users SET tenant_id = (SELECT id FROM tenants WHERE slug = 'default') WHERE tenant_id IS NULL;
ALTER TABLE users ALTER COLUMN tenant_id SET NOT NULL;
CREATE INDEX IF NOT EXISTS idx_users_tenant_id ON users(tenant_id);

-- Change unique constraint from (email, app_id) to (email, tenant_id)
ALTER TABLE users DROP CONSTRAINT IF EXISTS uq_user_email_app;
ALTER TABLE users ADD CONSTRAINT uq_user_email_tenant UNIQUE (email, tenant_id);

-- 6. Add tenant_id to passkey_credentials
ALTER TABLE passkey_credentials ADD COLUMN IF NOT EXISTS tenant_id INTEGER REFERENCES tenants(id);
UPDATE passkey_credentials SET tenant_id = (SELECT id FROM tenants WHERE slug = 'default') WHERE tenant_id IS NULL;
ALTER TABLE passkey_credentials ALTER COLUMN tenant_id SET NOT NULL;
CREATE INDEX IF NOT EXISTS idx_passkey_tenant_id ON passkey_credentials(tenant_id);

-- 7. Add tenant_id to refresh_tokens
ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS tenant_id INTEGER REFERENCES tenants(id);
UPDATE refresh_tokens SET tenant_id = (SELECT id FROM tenants WHERE slug = 'default') WHERE tenant_id IS NULL;
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_tenant_id ON refresh_tokens(tenant_id);
