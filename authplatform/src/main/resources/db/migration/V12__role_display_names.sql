ALTER TABLE roles ADD COLUMN display_name VARCHAR(120);

UPDATE roles
SET display_name = initcap(replace(replace(name, '_', ' '), '-', ' '))
WHERE display_name IS NULL;
