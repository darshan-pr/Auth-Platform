-- Migration: Add passkey (WebAuthn) support
-- Adds passkey_enabled setting to apps table
-- Creates passkey_credentials table to store user passkeys

-- Add passkey_enabled setting to apps
ALTER TABLE apps ADD COLUMN IF NOT EXISTS passkey_enabled BOOLEAN NOT NULL DEFAULT FALSE;

-- Create passkey credentials table
CREATE TABLE IF NOT EXISTS passkey_credentials (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    app_id VARCHAR NOT NULL,
    credential_id VARCHAR NOT NULL,
    public_key TEXT NOT NULL,
    sign_count INTEGER NOT NULL DEFAULT 0,
    device_name VARCHAR DEFAULT 'Unknown Device',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_used_at TIMESTAMP WITH TIME ZONE,
    UNIQUE(credential_id, app_id)
);

CREATE INDEX IF NOT EXISTS idx_passkey_user_app ON passkey_credentials(user_id, app_id);
CREATE INDEX IF NOT EXISTS idx_passkey_credential_id ON passkey_credentials(credential_id);

-- Verify
SELECT column_name, data_type, is_nullable, column_default 
FROM information_schema.columns 
WHERE table_name = 'apps' AND column_name = 'passkey_enabled';

SELECT column_name, data_type
FROM information_schema.columns 
WHERE table_name = 'passkey_credentials';
