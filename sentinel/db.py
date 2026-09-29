"""SQLite storage for events."""
import sqlite3
from typing import Iterable

from .models import Event

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       TEXT NOT NULL,
    host     TEXT NOT NULL,
    username TEXT NOT NULL,
    src_ip   TEXT NOT NULL,
    outcome  TEXT NOT NULL CHECK (outcome IN ('failed', 'success'))
);
CREATE INDEX IF NOT EXISTS idx_events_ip_ts ON events (src_ip, ts);
"""


def connect(path: str = ":memory:") -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn


def insert_events(conn: sqlite3.Connection, events: Iterable[Event]) -> int:
    rows = [(e.ts, e.host, e.username, e.src_ip, e.outcome) for e in events]
    conn.executemany(
        "INSERT INTO events (ts, host, username, src_ip, outcome) VALUES (?, ?, ?, ?, ?)",
        rows,
    )
    conn.commit()
    return len(rows)
