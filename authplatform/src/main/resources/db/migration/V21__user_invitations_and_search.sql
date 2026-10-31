-- Set when a console owner invites a user; the user counts as "invited" until their first login.
ALTER TABLE app_users ADD COLUMN invited_at TIMESTAMPTZ;

-- Paged end-user lists are always scoped to an application and ordered newest first.
CREATE INDEX idx_app_users_app_created ON app_users (app_id, created_at DESC, id);

-- Trigram indexes keep "contains" searches fast. pg_trgm is optional: if the role may not create
-- the extension the searches still work, only without the index.
DO $$
BEGIN
    CREATE EXTENSION IF NOT EXISTS pg_trgm;
EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'pg_trgm unavailable, skipping trigram search indexes: %', SQLERRM;
END
$$;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_trgm') THEN
        CREATE INDEX idx_app_users_email_trgm ON app_users USING gin (lower(email) gin_trgm_ops);
        CREATE INDEX idx_app_users_name_trgm ON app_users USING gin (lower(name) gin_trgm_ops);
        CREATE INDEX idx_accounts_email_trgm ON accounts USING gin (lower(email) gin_trgm_ops);
        CREATE INDEX idx_accounts_name_trgm ON accounts USING gin (lower(name) gin_trgm_ops);
        CREATE INDEX idx_apps_name_trgm ON apps USING gin (lower(name) gin_trgm_ops);
    END IF;
END
$$;
