"""Transactional local coordination, run fencing, and a durable event outbox."""

import json
import os
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path


SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
 id TEXT PRIMARY KEY, state TEXT NOT NULL, epoch INTEGER NOT NULL,
 input_hash TEXT NOT NULL, workers INTEGER NOT NULL, mode TEXT NOT NULL,
 created REAL NOT NULL, deadline REAL NOT NULL, reason TEXT, calls INTEGER NOT NULL DEFAULT 0,
 model_calls INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS run_limits (
 run_id TEXT PRIMARY KEY, model_calls INTEGER NOT NULL, tool_calls INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS tasks (
 run_id TEXT NOT NULL, shard INTEGER NOT NULL, state TEXT NOT NULL DEFAULT 'READY',
 owner TEXT, fence INTEGER NOT NULL DEFAULT 0, lease_until REAL,
 result TEXT, result_hash TEXT, PRIMARY KEY(run_id,shard)
);
CREATE TABLE IF NOT EXISTS notes (
 id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT NOT NULL, agent_id TEXT NOT NULL,
 text TEXT NOT NULL, created REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
 seq INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT NOT NULL,
 agent_id TEXT NOT NULL, kind TEXT NOT NULL, detail TEXT NOT NULL, created REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS verification (
 run_id TEXT PRIMARY KEY, candidate_hash TEXT NOT NULL, verdict TEXT NOT NULL
);
"""


class Store:
    def __init__(self, root: Path, database_url: str | None = None):
        self.database_url = database_url
        self.root = root.resolve()
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.path = self.root / "control.sqlite3"
        with self.connect() as db:
            db.executescript(SCHEMA)
        if not self.database_url:
            os.chmod(self.path, 0o600)

    @contextmanager
    def connect(self):
        if self.database_url:
            from .postgres import connect
            with connect(self.database_url) as connection:
                yield connection
            return
        db = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        try:
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA busy_timeout=10000")
            db.execute("PRAGMA foreign_keys=ON")
            db.execute("PRAGMA journal_mode=WAL")
            yield db
        finally:
            db.close()

    @contextmanager
    def transaction(self):
        with self.connect() as db:
            try:
                db.execute("BEGIN" if self.database_url else "BEGIN IMMEDIATE")
                yield db
                db.execute("COMMIT")
            except BaseException:
                db.execute("ROLLBACK")
                raise

    @staticmethod
    def event(db, run_id: str, agent_id: str, kind: str, detail: dict):
        db.execute("INSERT INTO events(run_id,agent_id,kind,detail,created) VALUES (?,?,?,?,?)", (
            run_id, agent_id, kind, json.dumps(detail, sort_keys=True, allow_nan=False), time.time(),
        ))

    def lock_run(self, db, run_id):
        suffix = ' FOR UPDATE' if self.database_url else ''
        return db.execute('SELECT * FROM runs WHERE id=?'+suffix, (run_id,)).fetchone()

    def run(self, run_id: str) -> dict:
        with self.connect() as db:
            row = db.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
        if row is None:
            raise ValueError("unknown run")
        return dict(row)

    def events(self, run_id: str, after: int = 0) -> list[dict]:
        with self.connect() as db:
            rows = db.execute("SELECT * FROM events WHERE run_id=? AND seq>? ORDER BY seq LIMIT 1000", (run_id, after)).fetchall()
        return [{**dict(r), "detail": json.loads(r["detail"])} for r in rows]

    def tasks(self, run_id: str) -> list[dict]:
        with self.connect() as db:
            return [dict(r) for r in db.execute("SELECT * FROM tasks WHERE run_id=? ORDER BY shard", (run_id,))]

    def stop(self, run_id: str, reason: str, state: str = "STOPPED"):
        if state not in ("STOPPED", "PAUSED", "FAILED"):
            raise ValueError("invalid stopping state")
        with self.transaction() as db:
            run = self.lock_run(db, run_id)
            if not run:
                raise ValueError("unknown run")
            # Cleanup may pause more than once; preserve the original finding.
            # An operator can still escalate a paused run to STOPPED or FAILED.
            if run["state"] == "RUNNING" or (run["state"] == "PAUSED" and state != "PAUSED"):
                db.execute("UPDATE runs SET state=?,epoch=epoch+1,reason=? WHERE id=?", (state, reason[:1000], run_id))
                self.event(db, run_id, "operator", "run." + state.lower(), {"reason": reason[:1000]})

