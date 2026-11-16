"""SQLite storage.

The `endpoints` table is the ONLY place server hosts/ports live. Nothing outside
scanner.py reads it, and no API model includes its columns.
"""

from __future__ import annotations

import sqlite3
import threading
from typing import Any, Iterable

SCHEMA = """
PRAGMA journal_mode=WAL;

-- INTERNAL ONLY. Never serialized by any API route or export.
CREATE TABLE IF NOT EXISTS endpoints (
    server_id TEXT PRIMARY KEY,
    host      TEXT NOT NULL,
    port      INTEGER NOT NULL,
    UNIQUE(host, port)
);

CREATE TABLE IF NOT EXISTS servers (
    server_id     TEXT PRIMARY KEY,
    first_seen    REAL NOT NULL,
    last_seen     REAL,
    last_checked  REAL,
    online        INTEGER NOT NULL DEFAULT 0,
    name          TEXT,
    motd          TEXT,
    version_name  TEXT,
    protocol      INTEGER,
    software      TEXT,
    mod_loader    TEXT,
    mods_count    INTEGER,
    players_online INTEGER,
    players_max   INTEGER,
    sample_size   INTEGER,
    sample_hidden INTEGER,
    enforces_secure_chat INTEGER,
    has_favicon   INTEGER,
    latency_ms    REAL,
    times_seen    INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_servers_last_seen ON servers(last_seen);

CREATE TABLE IF NOT EXISTS status_history (
    server_id TEXT NOT NULL,
    ts        REAL NOT NULL,
    online    INTEGER NOT NULL,
    players_online INTEGER,
    players_max INTEGER,
    latency_ms REAL
);
CREATE INDEX IF NOT EXISTS idx_hist_server ON status_history(server_id, ts);

CREATE TABLE IF NOT EXISTS scan_jobs (
    job_id   TEXT PRIMARY KEY,
    created  REAL NOT NULL,
    finished REAL,
    status   TEXT NOT NULL,
    kind     TEXT NOT NULL,
    summary  TEXT,
    total    INTEGER NOT NULL DEFAULT 0,
    done     INTEGER NOT NULL DEFAULT 0,
    found    INTEGER NOT NULL DEFAULT 0,
    skipped  INTEGER NOT NULL DEFAULT 0,
    rate     REAL,
    error    TEXT
);

CREATE TABLE IF NOT EXISTS exclusions (
    cidr   TEXT PRIMARY KEY,
    reason TEXT,
    added  REAL NOT NULL
);

-- Moderation federation: servers that opted in and push their own records.
CREATE TABLE IF NOT EXISTS fed_servers (
    fed_id       TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    description  TEXT,
    online_mode  INTEGER,
    api_key_hash TEXT NOT NULL,
    created      REAL NOT NULL,
    last_report  REAL,
    active       INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS fed_events (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    fed_id   TEXT NOT NULL,
    ts       REAL NOT NULL,
    type     TEXT NOT NULL,
    uuid     TEXT,
    username TEXT,
    ip_hash  TEXT,
    detail   TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_uuid ON fed_events(uuid);

CREATE TABLE IF NOT EXISTS fed_sessions (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    fed_id    TEXT NOT NULL,
    uuid      TEXT NOT NULL,
    username  TEXT NOT NULL,
    username_lc TEXT NOT NULL,
    ip_hash   TEXT,
    login_ts  REAL NOT NULL,
    logout_ts REAL,
    clean_close INTEGER
);
CREATE INDEX IF NOT EXISTS idx_sess_uuid ON fed_sessions(uuid);
CREATE INDEX IF NOT EXISTS idx_sess_name ON fed_sessions(username_lc);
CREATE INDEX IF NOT EXISTS idx_sess_ip ON fed_sessions(ip_hash);

CREATE TABLE IF NOT EXISTS fed_punishments (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    fed_id     TEXT NOT NULL,
    uuid       TEXT NOT NULL,
    username   TEXT,
    username_lc TEXT,
    kind       TEXT NOT NULL,
    reason     TEXT,
    issued_ts  REAL NOT NULL,
    expires_ts REAL,
    active     INTEGER NOT NULL DEFAULT 1,
    revoked_ts REAL,
    ip_hash    TEXT
);
CREATE INDEX IF NOT EXISTS idx_pun_uuid ON fed_punishments(uuid);

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS mojang_cache (
    key     TEXT PRIMARY KEY,
    value   TEXT,
    fetched REAL NOT NULL
);
"""


class Database:
    def __init__(self, path: str):
        self.path = path
        self._conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        with self._lock:
            self._conn.executescript(SCHEMA)

    def execute(self, sql: str, params: Iterable[Any] = ()) -> sqlite3.Cursor:
        with self._lock:
            return self._conn.execute(sql, tuple(params))

    def executemany(self, sql: str, rows: Iterable[Iterable[Any]]) -> None:
        with self._lock:
            self._conn.executemany(sql, rows)

    def query(self, sql: str, params: Iterable[Any] = ()) -> list[dict]:
        with self._lock:
            return [dict(r) for r in self._conn.execute(sql, tuple(params)).fetchall()]

    def one(self, sql: str, params: Iterable[Any] = ()) -> dict | None:
        with self._lock:
            r = self._conn.execute(sql, tuple(params)).fetchone()
            return dict(r) if r else None

    def transaction(self):
        return _Tx(self)

    def close(self) -> None:
        with self._lock:
            self._conn.close()


class _Tx:
    def __init__(self, db: Database):
        self.db = db

    def __enter__(self):
        self.db._lock.acquire()
        self.db._conn.execute("BEGIN")
        return self.db

    def __exit__(self, exc_type, exc, tb):
        try:
            self.db._conn.execute("ROLLBACK" if exc_type else "COMMIT")
        finally:
            self.db._lock.release()
        return False
