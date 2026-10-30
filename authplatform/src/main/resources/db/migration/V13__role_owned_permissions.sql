ALTER TABLE permissions
    ADD COLUMN role_id UUID,
    ADD COLUMN enabled BOOLEAN NOT NULL DEFAULT TRUE;

ALTER TABLE permissions
    DROP CONSTRAINT IF EXISTS permissions_app_id_key_key;

DO $$
DECLARE
    constraint_name TEXT;
BEGIN
    SELECT conname
    INTO constraint_name
    FROM pg_constraint
    WHERE conrelid = 'app_user_role_permission_overrides'::regclass
      AND confrelid = 'role_permissions'::regclass
      AND contype = 'f'
    LIMIT 1;

    IF constraint_name IS NOT NULL THEN
        EXECUTE format(
            'ALTER TABLE app_user_role_permission_overrides DROP CONSTRAINT %I',
            constraint_name
        );
    END IF;
END $$;

CREATE TEMPORARY TABLE permission_role_map ON COMMIT DROP AS
WITH ranked_permissions AS (
    SELECT
        p.id AS old_permission_id,
        p.app_id,
        p.key,
        p.description,
        rp.role_id,
        ROW_NUMBER() OVER (PARTITION BY p.id ORDER BY rp.role_id) AS role_number
    FROM permissions p
    JOIN role_permissions rp ON rp.permission_id = p.id
)
SELECT
    old_permission_id,
    app_id,
    key,
    description,
    role_id,
    role_number,
    CASE
        WHEN role_number = 1 THEN old_permission_id
        ELSE gen_random_uuid()
    END AS new_permission_id
FROM ranked_permissions;

INSERT INTO permissions (id, app_id, key, description, role_id, enabled)
SELECT
    mapping.new_permission_id,
    mapping.app_id,
    mapping.key,
    mapping.description,
    mapping.role_id,
    TRUE
FROM permission_role_map mapping
WHERE mapping.role_number > 1;

UPDATE permissions permission
SET role_id = mapping.role_id
FROM permission_role_map mapping
WHERE mapping.old_permission_id = permission.id
  AND mapping.role_number = 1;

UPDATE app_user_role_permission_overrides overrides
SET permission_id = mapping.new_permission_id
FROM permission_role_map mapping
WHERE overrides.role_id = mapping.role_id
  AND overrides.permission_id = mapping.old_permission_id
  AND overrides.permission_id <> mapping.new_permission_id;

UPDATE role_permissions role_permission
SET permission_id = mapping.new_permission_id
FROM permission_role_map mapping
WHERE role_permission.role_id = mapping.role_id
  AND role_permission.permission_id = mapping.old_permission_id
  AND role_permission.permission_id <> mapping.new_permission_id;

ALTER TABLE roles
    ADD CONSTRAINT uq_roles_id_app_id UNIQUE (id, app_id);

ALTER TABLE permissions
    ADD CONSTRAINT uq_permissions_role_id_id UNIQUE (role_id, id),
    ADD CONSTRAINT uq_permissions_role_key UNIQUE (role_id, key),
    ADD CONSTRAINT fk_permissions_role_app
        FOREIGN KEY (role_id, app_id)
        REFERENCES roles (id, app_id)
        ON DELETE CASCADE;

ALTER TABLE app_user_role_permission_overrides
    ADD CONSTRAINT fk_user_permission_override_role_permission
        FOREIGN KEY (role_id, permission_id)
        REFERENCES permissions (role_id, id)
        ON DELETE CASCADE;

DROP TABLE role_permissions;
