ALTER TABLE apps
    ADD COLUMN icon_url TEXT,
    ADD COLUMN icon_data BYTEA,
    ADD COLUMN icon_content_type VARCHAR(32),
    ADD COLUMN icon_position_x SMALLINT NOT NULL DEFAULT 50,
    ADD COLUMN icon_position_y SMALLINT NOT NULL DEFAULT 50,
    ADD COLUMN icon_zoom_percent SMALLINT NOT NULL DEFAULT 100;
