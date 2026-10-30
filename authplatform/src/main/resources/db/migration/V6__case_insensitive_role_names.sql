CREATE UNIQUE INDEX uq_roles_app_name_ci ON roles (app_id, lower(name));
