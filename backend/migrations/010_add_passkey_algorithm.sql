-- Migration 010: Add algorithm column to passkey credentials for server-side signature verification
-- Safe to run multiple times.

ALTER TABLE passkey_credentials
ADD COLUMN IF NOT EXISTS algorithm INTEGER NOT NULL DEFAULT -7;

-- Backfill any null rows if the column existed without NOT NULL in older installs.
UPDATE passkey_credentials
SET algorithm = -7
WHERE algorithm IS NULL;
