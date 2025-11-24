-- D1 schema for the Cloudflare Worker variant of gcli2api.
-- Timestamps are stored as UNIX epoch milliseconds.
CREATE TABLE IF NOT EXISTS accounts (
  id TEXT PRIMARY KEY,
  label TEXT NOT NULL UNIQUE,
  client_id TEXT NOT NULL,
  client_secret TEXT NOT NULL,
  refresh_token TEXT NOT NULL,
  token_uri TEXT NOT NULL DEFAULT 'https://oauth2.googleapis.com/token',
  project_id TEXT NOT NULL,
  access_token TEXT,
  access_token_expires_at INTEGER,
  is_enabled INTEGER NOT NULL DEFAULT 1,
  last_error TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS accounts_enabled_idx ON accounts (is_enabled);
CREATE INDEX IF NOT EXISTS accounts_label_idx ON accounts (label);
