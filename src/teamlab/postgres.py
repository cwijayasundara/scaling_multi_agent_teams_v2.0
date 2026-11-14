"""Optional PostgreSQL connection adapter for the service-owned SQL subset.

No model can supply SQL. Requires psycopg 3 and an operator-provisioned database.
TEAMLAB_DATABASE_QUOTA_BYTES, when set, refuses new connections after the
database exceeds that size. PostgreSQL does not enforce this as a disk quota
by itself; the check is the service-side gate.
"""
import os
import re
from contextlib import contextmanager

from .security import SecurityError


def sql(statement):
    if 'sqlite_master' in statement:
        statement = statement.replace('sqlite_master', 'pg_tables').replace("type='table' AND ", '').replace('name=', 'tablename=')
    statement = statement.replace('INTEGER PRIMARY KEY AUTOINCREMENT', 'BIGSERIAL PRIMARY KEY')
    statement = statement.replace('payload BLOB', 'payload BYTEA')
    statement = re.sub(r'\bREAL\b', 'DOUBLE PRECISION', statement)
    statement = statement.replace('?', '%s')
    if statement.startswith('INSERT OR IGNORE INTO work_artifacts'):
        statement = statement.replace('INSERT OR IGNORE', 'INSERT') + ' ON CONFLICT DO NOTHING'
    if statement.startswith('INSERT OR REPLACE INTO verification'):
        statement = statement.replace('INSERT OR REPLACE', 'INSERT') + ' ON CONFLICT(run_id) DO UPDATE SET candidate_hash=EXCLUDED.candidate_hash,verdict=EXCLUDED.verdict'
    if statement.startswith('INSERT OR REPLACE INTO graph_state'):
        statement = statement.replace('INSERT OR REPLACE', 'INSERT') + ' ON CONFLICT(run_id) DO UPDATE SET type=EXCLUDED.type,payload=EXCLUDED.payload,hash=EXCLUDED.hash'
    return statement


class Connection:
    def __init__(self, connection):
        self.connection = connection

    def execute(self, statement, parameters=()):
        return Cursor(self.connection.execute(sql(statement), parameters))

    def executescript(self, script):
        for statement in script.split(';'):
            if statement.strip():
                self.execute(statement.strip())


class Row(dict):
    def __getitem__(self, key):
        if isinstance(key, int):
            return list(self.values())[key]
        return super().__getitem__(key)


class Cursor:
    def __init__(self, cursor):
        self.cursor = cursor

    def fetchone(self):
        row = self.cursor.fetchone()
        return Row(row) if row is not None else None

    def fetchall(self):
        return [Row(row) for row in self.cursor.fetchall()]

    def __iter__(self):
        return iter(self.fetchall())


@contextmanager
def connect(url):
    try:
        import psycopg
        from psycopg.rows import dict_row
    except ImportError as exc:
        raise RuntimeError('PostgreSQL profile requires the postgres optional dependency') from exc
    with psycopg.connect(url, autocommit=True, row_factory=dict_row) as raw:
        raw.execute("SET statement_timeout = '5s'")
        raw.execute("SET lock_timeout = '5s'")
        quota = os.environ.get('TEAMLAB_DATABASE_QUOTA_BYTES')
        if quota is not None:
            limit = int(quota)
            if limit < 1:
                raise SecurityError('invalid database storage quota')
            size = raw.execute('SELECT pg_database_size(current_database()) AS bytes').fetchone()['bytes']
            if size > limit:
                raise SecurityError('infrastructure storage quota exceeded')
        yield Connection(raw)
