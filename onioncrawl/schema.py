TABLES = """
CREATE TABLE IF NOT EXISTS urls (
    url TEXT PRIMARY KEY, host TEXT NOT NULL, depth INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'queued', priority INTEGER NOT NULL DEFAULT 0, retries INTEGER NOT NULL DEFAULT 0,
    next_due TEXT NOT NULL, lease_until TEXT, last_fetched TEXT, last_hash TEXT, last_code INTEGER,
    discovered_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS hosts (
    host TEXT PRIMARY KEY, first_seen TEXT NOT NULL, last_up TEXT, last_down TEXT,
    consecutive_failures INTEGER NOT NULL DEFAULT 0, state TEXT NOT NULL DEFAULT 'unknown', title TEXT,
    unchanged_streak INTEGER NOT NULL DEFAULT 0, simhash INTEGER
);
CREATE TABLE IF NOT EXISTS pages (
    sha256 TEXT PRIMARY KEY, url TEXT NOT NULL, host TEXT NOT NULL, fetched_at TEXT NOT NULL,
    http_code INTEGER NOT NULL, bytes INTEGER NOT NULL, title TEXT, simhash INTEGER, path TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS uptime (host TEXT NOT NULL, checked_at TEXT NOT NULL, up INTEGER NOT NULL);
"""

INDEXES = """
CREATE INDEX IF NOT EXISTS urls_claim ON urls(status, next_due, priority);
CREATE INDEX IF NOT EXISTS urls_host ON urls(host, status);
CREATE INDEX IF NOT EXISTS pages_simhash ON pages(simhash);
CREATE INDEX IF NOT EXISTS uptime_host ON uptime(host, checked_at);
"""
