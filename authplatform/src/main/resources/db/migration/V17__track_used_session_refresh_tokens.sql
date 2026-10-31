CREATE TABLE session_used_refresh_tokens (
    session_id UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    refresh_token_hash VARCHAR(64) NOT NULL,
    CONSTRAINT pk_session_used_refresh_tokens PRIMARY KEY (session_id, refresh_token_hash),
    CONSTRAINT uq_session_used_refresh_tokens_hash UNIQUE (refresh_token_hash)
);

INSERT INTO session_used_refresh_tokens (session_id, refresh_token_hash)
SELECT id, previous_refresh_hash
FROM sessions
WHERE previous_refresh_hash IS NOT NULL
  AND previous_refresh_hash <> '';
