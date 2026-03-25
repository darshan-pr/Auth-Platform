-- Migration 012: add per-application OAuth toggle
-- Keeps existing behavior by defaulting to enabled for all current apps.

ALTER TABLE apps ADD COLUMN IF NOT EXISTS oauth_enabled BOOLEAN NOT NULL DEFAULT TRUE;
