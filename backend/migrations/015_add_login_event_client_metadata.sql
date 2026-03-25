-- Migration 015: capture client metadata on login events for richer auth activity tracking.

ALTER TABLE login_events ADD COLUMN IF NOT EXISTS user_agent TEXT;
ALTER TABLE login_events ADD COLUMN IF NOT EXISTS browser VARCHAR;
ALTER TABLE login_events ADD COLUMN IF NOT EXISTS device VARCHAR;
