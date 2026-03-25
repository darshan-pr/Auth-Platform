-- 000_base_schema.sql
-- Creates all base tables if they do not already exist.
-- Safe to run on both fresh and existing databases.

-- 1. tenants (no FKs — must be created first)
CREATE TABLE IF NOT EXISTS tenants (
    id SERIAL PRIMARY KEY,
    name VARCHAR NOT NULL,
    slug VARCHAR UNIQUE NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS ix_tenants_id   ON tenants (id);
CREATE INDEX IF NOT EXISTS ix_tenants_slug ON tenants (slug);

-- 2. admins
CREATE TABLE IF NOT EXISTS admins (
    id SERIAL PRIMARY KEY,
    email VARCHAR UNIQUE,
    password_hash VARCHAR,
    tenant_id INTEGER NOT NULL REFERENCES tenants(id),
    mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE
);

-- 3. apps
CREATE TABLE IF NOT EXISTS apps (
    id SERIAL PRIMARY KEY,
    app_id VARCHAR UNIQUE NOT NULL,
    app_secret VARCHAR NOT NULL,
    tenant_id INTEGER NOT NULL REFERENCES tenants(id),
    name VARCHAR,
    description VARCHAR,
    logo_url VARCHAR,
    otp_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    access_token_expiry_minutes INTEGER NOT NULL DEFAULT 30,
    refresh_token_expiry_days INTEGER NOT NULL DEFAULT 7,
    login_notification_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    force_logout_notification_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    passkey_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    oauth_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    redirect_uris VARCHAR,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS ix_apps_id     ON apps (id);
CREATE INDEX IF NOT EXISTS ix_apps_app_id ON apps (app_id);
CREATE INDEX IF NOT EXISTS ix_apps_tenant ON apps (tenant_id);

-- 4. users
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email VARCHAR NOT NULL,
    password_hash VARCHAR,
    app_id VARCHAR NOT NULL,
    tenant_id INTEGER NOT NULL REFERENCES tenants(id),
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS ix_users_id     ON users (id);
CREATE INDEX IF NOT EXISTS ix_users_email  ON users (email);
CREATE INDEX IF NOT EXISTS ix_users_tenant ON users (tenant_id);

-- unique constraint email+tenant+app
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'uq_user_email_tenant_app'
    ) THEN
        ALTER TABLE users ADD CONSTRAINT uq_user_email_tenant_app UNIQUE (email, tenant_id, app_id);
    END IF;
END $$;

-- 5. refresh_tokens
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id SERIAL PRIMARY KEY,
    token VARCHAR UNIQUE,
    user_id INTEGER,
    tenant_id INTEGER REFERENCES tenants(id),
    expires_at TIMESTAMP
);
CREATE INDEX IF NOT EXISTS ix_refresh_tokens_id     ON refresh_tokens (id);
CREATE INDEX IF NOT EXISTS ix_refresh_tokens_token  ON refresh_tokens (token);
CREATE INDEX IF NOT EXISTS ix_refresh_tokens_tenant ON refresh_tokens (tenant_id);

-- 6. passkey_credentials
CREATE TABLE IF NOT EXISTS passkey_credentials (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    app_id VARCHAR NOT NULL,
    tenant_id INTEGER NOT NULL REFERENCES tenants(id),
    credential_id VARCHAR NOT NULL,
    public_key VARCHAR NOT NULL,
    sign_count INTEGER NOT NULL DEFAULT 0,
    algorithm INTEGER NOT NULL DEFAULT -7,
    device_name VARCHAR DEFAULT 'Unknown Device',
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    last_used_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS ix_passkey_credentials_id    ON passkey_credentials (id);
CREATE INDEX IF NOT EXISTS ix_passkey_credentials_cred  ON passkey_credentials (credential_id);
CREATE INDEX IF NOT EXISTS ix_passkey_credentials_tenant ON passkey_credentials (tenant_id);

-- 7. admin_passkey_credentials
CREATE TABLE IF NOT EXISTS admin_passkey_credentials (
    id SERIAL PRIMARY KEY,
    admin_id INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
    tenant_id INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    credential_id VARCHAR NOT NULL,
    public_key VARCHAR NOT NULL,
    sign_count INTEGER NOT NULL DEFAULT 0,
    algorithm INTEGER NOT NULL DEFAULT -7,
    device_name VARCHAR DEFAULT 'Admin Device',
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    last_used_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS ix_admin_passkey_cred_id     ON admin_passkey_credentials (id);
CREATE INDEX IF NOT EXISTS ix_admin_passkey_cred_admin  ON admin_passkey_credentials (admin_id);
CREATE INDEX IF NOT EXISTS ix_admin_passkey_cred_tenant ON admin_passkey_credentials (tenant_id);
CREATE INDEX IF NOT EXISTS ix_admin_passkey_cred_cred   ON admin_passkey_credentials (credential_id);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'uq_admin_passkey_credential_id'
    ) THEN
        ALTER TABLE admin_passkey_credentials ADD CONSTRAINT uq_admin_passkey_credential_id UNIQUE (credential_id);
    END IF;
END $$;

-- 8. login_events
CREATE TABLE IF NOT EXISTS login_events (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    app_id VARCHAR,
    tenant_id INTEGER REFERENCES tenants(id),
    event_type VARCHAR NOT NULL,
    user_agent VARCHAR,
    browser VARCHAR,
    device VARCHAR,
    ip_address VARCHAR,
    city VARCHAR,
    region VARCHAR,
    country VARCHAR,
    lat DOUBLE PRECISION,
    lon DOUBLE PRECISION,
    isp VARCHAR,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS ix_login_events_id     ON login_events (id);
CREATE INDEX IF NOT EXISTS ix_login_events_user   ON login_events (user_id);
CREATE INDEX IF NOT EXISTS ix_login_events_app    ON login_events (app_id);
CREATE INDEX IF NOT EXISTS ix_login_events_tenant ON login_events (tenant_id);
CREATE INDEX IF NOT EXISTS ix_login_events_type   ON login_events (event_type);

-- 9. oauth_consents
CREATE TABLE IF NOT EXISTS oauth_consents (
    id SERIAL PRIMARY KEY,
    tenant_id INTEGER NOT NULL REFERENCES tenants(id),
    user_id INTEGER NOT NULL REFERENCES users(id),
    client_id VARCHAR NOT NULL,
    scope VARCHAR NOT NULL DEFAULT 'email',
    granted BOOLEAN NOT NULL DEFAULT TRUE,
    granted_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS ix_oauth_consents_id     ON oauth_consents (id);
CREATE INDEX IF NOT EXISTS ix_oauth_consents_tenant ON oauth_consents (tenant_id);
CREATE INDEX IF NOT EXISTS ix_oauth_consents_user   ON oauth_consents (user_id);
CREATE INDEX IF NOT EXISTS ix_oauth_consents_client ON oauth_consents (client_id);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'uq_oauth_consents_tenant_user_client'
    ) THEN
        ALTER TABLE oauth_consents ADD CONSTRAINT uq_oauth_consents_tenant_user_client UNIQUE (tenant_id, user_id, client_id);
    END IF;
END $$;

-- 10. admin_sessions
CREATE TABLE IF NOT EXISTS admin_sessions (
    id SERIAL PRIMARY KEY,
    session_id VARCHAR UNIQUE NOT NULL,
    admin_id INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
    tenant_id INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_agent VARCHAR,
    browser VARCHAR,
    device VARCHAR,
    ip_address VARCHAR,
    city VARCHAR,
    region VARCHAR,
    country VARCHAR,
    isp VARCHAR,
    login_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMPTZ,
    is_revoked BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_at TIMESTAMPTZ,
    revoked_reason VARCHAR
);
CREATE INDEX IF NOT EXISTS ix_admin_sessions_id      ON admin_sessions (id);
CREATE INDEX IF NOT EXISTS ix_admin_sessions_session  ON admin_sessions (session_id);
CREATE INDEX IF NOT EXISTS ix_admin_sessions_admin    ON admin_sessions (admin_id);
CREATE INDEX IF NOT EXISTS ix_admin_sessions_tenant   ON admin_sessions (tenant_id);

-- 11. admin_activity_events
CREATE TABLE IF NOT EXISTS admin_activity_events (
    id SERIAL PRIMARY KEY,
    admin_id INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
    tenant_id INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    session_id VARCHAR,
    event_type VARCHAR NOT NULL,
    method VARCHAR,
    resource VARCHAR,
    details VARCHAR,
    user_agent VARCHAR,
    browser VARCHAR,
    device VARCHAR,
    ip_address VARCHAR,
    city VARCHAR,
    region VARCHAR,
    country VARCHAR,
    isp VARCHAR,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS ix_admin_activity_id      ON admin_activity_events (id);
CREATE INDEX IF NOT EXISTS ix_admin_activity_admin   ON admin_activity_events (admin_id);
CREATE INDEX IF NOT EXISTS ix_admin_activity_tenant  ON admin_activity_events (tenant_id);
CREATE INDEX IF NOT EXISTS ix_admin_activity_session ON admin_activity_events (session_id);
CREATE INDEX IF NOT EXISTS ix_admin_activity_type    ON admin_activity_events (event_type);
