CREATE FUNCTION enforce_app_relation_tenant()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    user_app_id UUID;
    role_app_id UUID;
BEGIN
    SELECT app_id INTO user_app_id
    FROM app_users
    WHERE id = NEW.app_user_id;

    SELECT app_id INTO role_app_id
    FROM roles
    WHERE id = NEW.role_id;

    IF user_app_id IS NULL OR role_app_id IS NULL THEN
        RAISE EXCEPTION 'App user and role must exist before assigning an app relationship';
    END IF;

    IF user_app_id <> role_app_id THEN
        RAISE EXCEPTION 'App user and role must belong to the same app';
    END IF;

    IF NEW.app_id IS NULL THEN
        NEW.app_id := user_app_id;
    ELSIF NEW.app_id <> user_app_id THEN
        RAISE EXCEPTION 'Relationship app_id must match the app user and role';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_app_user_roles_tenant
BEFORE INSERT OR UPDATE OF app_user_id, role_id, app_id
ON app_user_roles
FOR EACH ROW
EXECUTE FUNCTION enforce_app_relation_tenant();

CREATE TRIGGER trg_app_user_role_permission_overrides_tenant
BEFORE INSERT OR UPDATE OF app_user_id, role_id, app_id
ON app_user_role_permission_overrides
FOR EACH ROW
EXECUTE FUNCTION enforce_app_relation_tenant();
