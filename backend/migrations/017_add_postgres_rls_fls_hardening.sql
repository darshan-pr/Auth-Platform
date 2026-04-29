-- Migration 017: add PostgreSQL RLS + baseline column-level hardening.
-- Backward-compatibility note:
--   Policies allow all rows when app.current_tenant_id is not set, so existing
--   application behavior stays unchanged.
-- Strict mode:
--   Set app.current_tenant_id per request/transaction to enforce tenant isolation.

CREATE OR REPLACE FUNCTION app_current_tenant_id()
RETURNS INTEGER
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    raw_tenant TEXT;
BEGIN
    raw_tenant := current_setting('app.current_tenant_id', true);

    IF raw_tenant IS NULL OR btrim(raw_tenant) = '' THEN
        RETURN NULL;
    END IF;

    RETURN raw_tenant::INTEGER;
EXCEPTION
    WHEN OTHERS THEN
        RETURN NULL;
END;
$$;

CREATE OR REPLACE FUNCTION app_tenant_allows(row_tenant_id INTEGER)
RETURNS BOOLEAN
LANGUAGE SQL
STABLE
AS $$
    SELECT CASE
        WHEN app_current_tenant_id() IS NULL THEN TRUE
        WHEN row_tenant_id IS NULL THEN FALSE
        ELSE row_tenant_id = app_current_tenant_id()
    END;
$$;

CREATE OR REPLACE FUNCTION set_app_tenant_context(target_tenant_id INTEGER)
RETURNS VOID
LANGUAGE SQL
AS $$
    SELECT set_config(
        'app.current_tenant_id',
        CASE
            WHEN target_tenant_id IS NULL THEN ''
            ELSE target_tenant_id::TEXT
        END,
        true
    );
$$;

DO $$
DECLARE
    table_name TEXT;
    tenant_tables TEXT[] := ARRAY[
        'admins',
        'apps',
        'users',
        'refresh_tokens',
        'passkey_credentials',
        'admin_passkey_credentials',
        'login_events',
        'oauth_consents',
        'admin_sessions',
        'admin_activity_events'
    ];
BEGIN
    FOREACH table_name IN ARRAY tenant_tables LOOP
        EXECUTE format('ALTER TABLE IF EXISTS public.%I ENABLE ROW LEVEL SECURITY', table_name);
        EXECUTE format('ALTER TABLE IF EXISTS public.%I FORCE ROW LEVEL SECURITY', table_name);

        IF NOT EXISTS (
            SELECT 1
            FROM pg_policies
            WHERE schemaname = 'public'
              AND tablename = table_name
              AND policyname = 'tenant_isolation'
        ) THEN
            EXECUTE format(
                'CREATE POLICY tenant_isolation ON public.%I
                 USING (app_tenant_allows(tenant_id))
                 WITH CHECK (app_tenant_allows(tenant_id))',
                table_name
            );
        END IF;
    END LOOP;
END $$;

ALTER TABLE IF EXISTS public.tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.tenants FORCE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename = 'tenants'
          AND policyname = 'tenant_isolation'
    ) THEN
        CREATE POLICY tenant_isolation
        ON public.tenants
        USING (app_tenant_allows(id))
        WITH CHECK (app_tenant_allows(id));
    END IF;
END $$;

-- Baseline FLS-style hardening for overly broad grants.
-- No impact on owner permissions used by current application.
REVOKE SELECT(password_hash) ON public.users FROM PUBLIC;
REVOKE SELECT(password_hash) ON public.admins FROM PUBLIC;
REVOKE SELECT(app_secret) ON public.apps FROM PUBLIC;
REVOKE SELECT(token) ON public.refresh_tokens FROM PUBLIC;
REVOKE SELECT(public_key) ON public.passkey_credentials FROM PUBLIC;
REVOKE SELECT(public_key) ON public.admin_passkey_credentials FROM PUBLIC;
