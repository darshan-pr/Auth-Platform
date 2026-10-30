ALTER TABLE apps
    ALTER COLUMN icon_position_x TYPE INTEGER USING icon_position_x::INTEGER,
    ALTER COLUMN icon_position_y TYPE INTEGER USING icon_position_y::INTEGER,
    ALTER COLUMN icon_zoom_percent TYPE INTEGER USING icon_zoom_percent::INTEGER;
