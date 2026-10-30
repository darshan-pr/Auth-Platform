DELETE FROM permissions
WHERE role_id IS NULL;

ALTER TABLE permissions
    ALTER COLUMN role_id SET NOT NULL;
