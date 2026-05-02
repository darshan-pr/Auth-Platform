-- Add client_type column to apps table (RFC 6749 §2.1)
-- "confidential" = has server/proxy, uses client_secret + PKCE
-- "public" = SPA/mobile, uses PKCE only (no secret)
-- Default to "confidential" so all existing apps keep working.

ALTER TABLE apps ADD COLUMN IF NOT EXISTS client_type VARCHAR(255) NOT NULL DEFAULT 'confidential';
