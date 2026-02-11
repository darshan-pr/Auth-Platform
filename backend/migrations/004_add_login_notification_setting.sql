-- Migration: Add login notification email setting to apps
-- Run this script on your PostgreSQL database

ALTER TABLE apps ADD COLUMN IF NOT EXISTS login_notification_enabled BOOLEAN NOT NULL DEFAULT FALSE;

-- Verify
SELECT column_name, data_type, is_nullable, column_default 
FROM information_schema.columns 
WHERE table_name = 'apps' AND column_name = 'login_notification_enabled';
