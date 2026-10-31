DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM app_user_roles user_roles
        JOIN app_users users ON users.id = user_roles.app_user_id
        JOIN roles app_roles ON app_roles.id = user_roles.role_id
        WHERE users.app_id <> app_roles.app_id
    ) THEN
        RAISE EXCEPTION
            'Cannot enforce tenant-scoped role assignments: cross-app app_user_roles rows exist';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM app_user_role_permission_overrides overrides
        JOIN app_users users ON users.id = overrides.app_user_id
        JOIN roles app_roles ON app_roles.id = overrides.role_id
        WHERE users.app_id <> app_roles.app_id
    ) THEN
        RAISE EXCEPTION
            'Cannot enforce tenant-scoped permission overrides: cross-app rows exist';
    END IF;
END $$;

ALTER TABLE app_users
    ADD CONSTRAINT uq_app_users_id_app_id UNIQUE (id, app_id);

ALTER TABLE app_user_roles
    ADD COLUMN app_id UUID;

UPDATE app_user_roles user_roles
SET app_id = users.app_id
FROM app_users users
WHERE users.id = user_roles.app_user_id;

ALTER TABLE app_user_roles
    ALTER COLUMN app_id SET NOT NULL,
    ADD CONSTRAINT fk_app_user_roles_user_app
        FOREIGN KEY (app_user_id, app_id)
        REFERENCES app_users (id, app_id)
        ON DELETE CASCADE,
    ADD CONSTRAINT fk_app_user_roles_role_app
        FOREIGN KEY (role_id, app_id)
        REFERENCES roles (id, app_id)
        ON DELETE CASCADE;

CREATE INDEX idx_app_user_roles_role_app
    ON app_user_roles (role_id, app_id);

ALTER TABLE app_user_role_permission_overrides
    ADD COLUMN app_id UUID;

UPDATE app_user_role_permission_overrides overrides
SET app_id = users.app_id
FROM app_users users
WHERE users.id = overrides.app_user_id;

ALTER TABLE app_user_role_permission_overrides
    ALTER COLUMN app_id SET NOT NULL,
    ADD CONSTRAINT fk_user_permission_override_user_app
        FOREIGN KEY (app_user_id, app_id)
        REFERENCES app_users (id, app_id)
        ON DELETE CASCADE,
    ADD CONSTRAINT fk_user_permission_override_role_app
        FOREIGN KEY (role_id, app_id)
        REFERENCES roles (id, app_id)
        ON DELETE CASCADE;

CREATE INDEX idx_user_permission_override_role_app
    ON app_user_role_permission_overrides (role_id, app_id);

CREATE INDEX idx_user_permission_override_role_permission
    ON app_user_role_permission_overrides (role_id, permission_id);
