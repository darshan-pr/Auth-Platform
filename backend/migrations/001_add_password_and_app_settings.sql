-- Migration script for adding password-based auth and app settings
-- Run this script on your PostgreSQL database to add the new columns

-- Add new columns to apps table
ALTER TABLE apps ADD COLUMN IF NOT EXISTS otp_enabled BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE apps ADD COLUMN IF NOT EXISTS access_token_expiry_minutes INTEGER NOT NULL DEFAULT 30;
ALTER TABLE apps ADD COLUMN IF NOT EXISTS refresh_token_expiry_days INTEGER NOT NULL DEFAULT 7;

-- Add password_hash column to users table
ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash VARCHAR;

-- Verify the changes
SELECT column_name, data_type, is_nullable, column_default 
FROM information_schema.columns 
WHERE table_name = 'apps' AND column_name IN ('otp_enabled', 'access_token_expiry_minutes', 'refresh_token_expiry_days');

SELECT column_name, data_type, is_nullable, column_default 
FROM information_schema.columns 
WHERE table_name = 'users' AND column_name = 'password_hash';
