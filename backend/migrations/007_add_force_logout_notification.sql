-- Add force logout notification email toggle per app
ALTER TABLE apps ADD COLUMN IF NOT EXISTS force_logout_notification_enabled BOOLEAN DEFAULT FALSE NOT NULL;
