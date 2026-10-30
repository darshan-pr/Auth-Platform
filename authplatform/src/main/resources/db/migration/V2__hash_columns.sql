ALTER TABLE apps ALTER COLUMN secret_key_hash TYPE VARCHAR(64);
ALTER TABLE sessions ALTER COLUMN refresh_token_hash TYPE VARCHAR(64);
ALTER TABLE sessions ALTER COLUMN previous_refresh_hash TYPE VARCHAR(64);
ALTER TABLE email_tokens ALTER COLUMN token_hash TYPE VARCHAR(64);
