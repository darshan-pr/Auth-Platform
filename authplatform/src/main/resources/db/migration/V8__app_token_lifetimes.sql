ALTER TABLE apps ADD COLUMN access_token_ttl_seconds INTEGER;
ALTER TABLE apps ADD COLUMN refresh_token_ttl_seconds INTEGER;
ALTER TABLE sessions ADD COLUMN access_token_ttl_seconds BIGINT;

ALTER TABLE apps
    ADD CONSTRAINT chk_apps_token_lifetimes
    CHECK (
        (access_token_ttl_seconds IS NULL AND refresh_token_ttl_seconds IS NULL)
        OR (
            access_token_ttl_seconds IS NOT NULL
            AND refresh_token_ttl_seconds IS NOT NULL
            AND access_token_ttl_seconds BETWEEN 60 AND 86400
            AND refresh_token_ttl_seconds BETWEEN 3600 AND 7776000
            AND refresh_token_ttl_seconds >= access_token_ttl_seconds
        )
    );

ALTER TABLE sessions
    ADD CONSTRAINT chk_sessions_access_token_ttl
    CHECK (access_token_ttl_seconds IS NULL OR access_token_ttl_seconds > 0);
