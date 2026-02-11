-- Migration: Make users app-specific
-- Allow same email to register under different apps via composite unique constraint

-- Step 1: Update any existing NULL app_id values to a placeholder
UPDATE users SET app_id = 'default' WHERE app_id IS NULL;

-- Step 2: Make app_id NOT NULL
ALTER TABLE users ALTER COLUMN app_id SET NOT NULL;

-- Step 3: Drop the old unique constraint on email (if it exists)
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_email_key;
DROP INDEX IF EXISTS ix_users_email;

-- Step 4: Add composite unique constraint on (email, app_id)
ALTER TABLE users ADD CONSTRAINT uq_user_email_app UNIQUE (email, app_id);

-- Step 5: Re-create index on email (non-unique)
CREATE INDEX IF NOT EXISTS ix_users_email ON users (email);
