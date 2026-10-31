CREATE INDEX IF NOT EXISTS idx_sessions_revoked_at ON sessions(revoked_at);

UPDATE sessions
SET revoked_at = now(), updated_at = now()
WHERE revoked_at IS NULL;
