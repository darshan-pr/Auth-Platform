-- Migration 008: Update users unique constraint to include app_id
-- Allows same email to exist in different apps within the same tenant
-- Old constraint: (email, tenant_id)
-- New constraint: (email, tenant_id, app_id)
-- This migration is IDEMPOTENT - safe to run multiple times

-- Step 1: Drop old constraints (if they exist)
ALTER TABLE users DROP CONSTRAINT IF EXISTS uq_user_email_tenant;
ALTER TABLE users DROP CONSTRAINT IF EXISTS uq_user_email_app;

-- Step 2: Drop new constraint if it exists (for idempotency)
ALTER TABLE users DROP CONSTRAINT IF EXISTS uq_user_email_tenant_app;

-- Step 3: Add the new composite unique constraint with app_id
ALTER TABLE users ADD CONSTRAINT uq_user_email_tenant_app UNIQUE (email, tenant_id, app_id);

-- Step 4: Create composite index for faster lookups (IF NOT EXISTS handles idempotency)
CREATE INDEX IF NOT EXISTS idx_users_email_tenant_app ON users(email, tenant_id, app_id);
