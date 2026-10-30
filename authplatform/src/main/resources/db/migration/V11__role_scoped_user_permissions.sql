CREATE TABLE app_user_role_permission_overrides (
    app_user_id UUID NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
    role_id UUID NOT NULL,
    permission_id UUID NOT NULL,
    granted BOOLEAN NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (app_user_id, role_id, permission_id),
    FOREIGN KEY (role_id, permission_id)
        REFERENCES role_permissions(role_id, permission_id) ON DELETE CASCADE
);

INSERT INTO app_user_role_permission_overrides (
    app_user_id, role_id, permission_id, granted
)
SELECT overrides.app_user_id, role_permissions.role_id, overrides.permission_id, overrides.granted
FROM app_user_permission_overrides overrides
JOIN role_permissions ON role_permissions.permission_id = overrides.permission_id
ON CONFLICT (app_user_id, role_id, permission_id) DO NOTHING;

DROP TABLE app_user_permission_overrides;
