-- Migration: Add OAuth redirect_uris to apps table
-- This column stores comma-separated allowed redirect URIs for the OAuth flow
-- If null/empty, only localhost URIs are allowed (dev mode)

ALTER TABLE apps ADD COLUMN IF NOT EXISTS redirect_uris VARCHAR;

-- Verify
SELECT column_name, data_type, is_nullable
FROM information_schema.columns
WHERE table_name = 'apps' AND column_name = 'redirect_uris';
