-- Migration 011: add per-application logo URL
-- Stores the uploaded or configured logo for each OAuth app.

ALTER TABLE apps ADD COLUMN IF NOT EXISTS logo_url VARCHAR;
