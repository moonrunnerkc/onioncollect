SOURCES = """
CREATE TABLE IF NOT EXISTS sources (
    id TEXT PRIMARY KEY, state TEXT NOT NULL, category TEXT NOT NULL, active_host TEXT NOT NULL,
    reviewer TEXT NOT NULL, note TEXT NOT NULL, approved_at TEXT NOT NULL, state_changed_at TEXT NOT NULL,
    reason TEXT, live_at TEXT, next_run TEXT, failed_runs INTEGER NOT NULL DEFAULT 0, cluster_id TEXT
);
CREATE TABLE IF NOT EXISTS hosts (
    host TEXT PRIMARY KEY, state TEXT NOT NULL, source_id TEXT REFERENCES sources(id), found_on TEXT,
    first_seen TEXT NOT NULL, decided_at TEXT, decided_by TEXT, reason TEXT, last_up TEXT, last_down TEXT
);
CREATE TABLE IF NOT EXISTS redirects (
    source_id TEXT NOT NULL, target TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
    PRIMARY KEY (target, source_id)
);
CREATE TABLE IF NOT EXISTS health_items (
    id INTEGER PRIMARY KEY, source_id TEXT NOT NULL, kind TEXT NOT NULL, priority INTEGER NOT NULL,
    detail TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open', opened_at TEXT NOT NULL, last_seen TEXT NOT NULL,
    last_run_id INTEGER, occurrences INTEGER NOT NULL DEFAULT 1, watched_at TEXT, snoozed_until_run INTEGER,
    resolved_at TEXT
);
CREATE TABLE IF NOT EXISTS dispositions (
    id INTEGER PRIMARY KEY, item_id INTEGER NOT NULL REFERENCES health_items(id), source_id TEXT NOT NULL,
    disposition TEXT NOT NULL, applied INTEGER NOT NULL, note TEXT NOT NULL, detail TEXT NOT NULL,
    decided_by TEXT NOT NULL, decided_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS golive_reports (
    id INTEGER PRIMARY KEY, source_id TEXT NOT NULL, run_at TEXT NOT NULL, passed INTEGER NOT NULL, lines TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS sources_state ON sources(state, next_run);
CREATE INDEX IF NOT EXISTS golive_reports_source ON golive_reports(source_id, run_at);
CREATE UNIQUE INDEX IF NOT EXISTS health_items_open ON health_items(source_id, kind) WHERE status = 'open';
CREATE INDEX IF NOT EXISTS dispositions_item ON dispositions(item_id, decided_at);
CREATE INDEX IF NOT EXISTS sources_cluster ON sources(cluster_id);
CREATE INDEX IF NOT EXISTS hosts_state ON hosts(state, first_seen);
CREATE INDEX IF NOT EXISTS hosts_source ON hosts(source_id);
"""

# The crawler's own queue, in its state dir: paths on approved hosts and their scheduling, never page text.
FRONTIER = """
CREATE TABLE IF NOT EXISTS urls (
    source_id TEXT NOT NULL, path TEXT NOT NULL, kind TEXT NOT NULL, page INTEGER NOT NULL, run_id INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'queued', retries INTEGER NOT NULL DEFAULT 0, next_due TEXT NOT NULL,
    lease_until TEXT, last_fetched TEXT, last_code INTEGER, discovered_at TEXT NOT NULL,
    PRIMARY KEY (source_id, path)
);
CREATE INDEX IF NOT EXISTS urls_claim ON urls(status, next_due);
CREATE INDEX IF NOT EXISTS urls_run ON urls(run_id, status);
"""

# Run metrics, beside the source table in collect.db. Only the writer adds to them.
RUNS = """
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY, source_id TEXT NOT NULL, started_at TEXT NOT NULL, finished_at TEXT,
    pages INTEGER NOT NULL DEFAULT 0, failures INTEGER NOT NULL DEFAULT 0, items INTEGER NOT NULL DEFAULT 0,
    incomplete INTEGER NOT NULL DEFAULT 0, fields_resolved INTEGER NOT NULL DEFAULT 0,
    fields_declared INTEGER NOT NULL DEFAULT 0, below_expectation INTEGER NOT NULL DEFAULT 0,
    redactions INTEGER NOT NULL DEFAULT 0, records_new INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS page_metrics (
    run_id INTEGER NOT NULL, source_id TEXT NOT NULL, host TEXT NOT NULL, kind TEXT NOT NULL, fetched_at TEXT NOT NULL,
    status INTEGER, error TEXT, elapsed REAL NOT NULL, bytes INTEGER NOT NULL DEFAULT 0,
    items INTEGER NOT NULL DEFAULT 0, fields_resolved INTEGER NOT NULL DEFAULT 0,
    fields_declared INTEGER NOT NULL DEFAULT 0, redactions INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS run_fields (
    run_id INTEGER NOT NULL, kind TEXT NOT NULL, field TEXT NOT NULL, resolved INTEGER NOT NULL DEFAULT 0,
    declared INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (run_id, kind, field)
);
CREATE TABLE IF NOT EXISTS uptime (host TEXT NOT NULL, checked_at TEXT NOT NULL, up INTEGER NOT NULL);
-- Every path a run fetched, for the log audit: the analyst cannot read the crawler's frontier.
CREATE TABLE IF NOT EXISTS visited_paths (
    source_id TEXT NOT NULL, path TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
    PRIMARY KEY (source_id, path)
);
CREATE INDEX IF NOT EXISTS runs_source ON runs(source_id, finished_at);
CREATE INDEX IF NOT EXISTS page_metrics_source ON page_metrics(source_id, fetched_at);
CREATE INDEX IF NOT EXISTS page_metrics_run ON page_metrics(run_id);
CREATE INDEX IF NOT EXISTS uptime_host ON uptime(host, checked_at);
"""

RECORDS = """
CREATE TABLE IF NOT EXISTS records (
    id INTEGER PRIMARY KEY, source_id TEXT NOT NULL, category TEXT NOT NULL, content_hash TEXT NOT NULL,
    follow_path TEXT, fields TEXT NOT NULL, redactions TEXT NOT NULL, hashes TEXT NOT NULL,
    first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, expires_at TEXT NOT NULL,
    UNIQUE (source_id, content_hash)
);
CREATE VIRTUAL TABLE IF NOT EXISTS records_fts USING fts5(text);
CREATE TABLE IF NOT EXISTS snapshots (
    digest TEXT NOT NULL, source_id TEXT NOT NULL, path TEXT NOT NULL, kind TEXT NOT NULL,
    taken_at TEXT NOT NULL, expires_at TEXT NOT NULL, baseline INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS record_hosts (
    record_id INTEGER NOT NULL REFERENCES records(id), host TEXT NOT NULL, source_id TEXT NOT NULL,
    first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, PRIMARY KEY (record_id, host)
);
CREATE TABLE IF NOT EXISTS fingerprints (
    host TEXT NOT NULL, path TEXT NOT NULL, seed INTEGER NOT NULL, content TEXT NOT NULL, structure TEXT NOT NULL,
    words INTEGER NOT NULL, seen_at TEXT NOT NULL, PRIMARY KEY (host, path)
);
CREATE INDEX IF NOT EXISTS records_source ON records(source_id, last_seen);
CREATE INDEX IF NOT EXISTS records_follow ON records(follow_path);
CREATE INDEX IF NOT EXISTS record_hosts_source ON record_hosts(source_id, record_id);
CREATE INDEX IF NOT EXISTS records_expiry ON records(expires_at);
CREATE INDEX IF NOT EXISTS snapshots_source ON snapshots(source_id, taken_at);
CREATE INDEX IF NOT EXISTS snapshots_expiry ON snapshots(expires_at);
CREATE INDEX IF NOT EXISTS fingerprints_seed ON fingerprints(seed, seen_at);
"""
