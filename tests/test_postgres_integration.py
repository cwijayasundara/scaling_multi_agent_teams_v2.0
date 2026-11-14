"""Optional real-database checks. A URL must point to a disposable test DB."""
import os
from concurrent.futures import ThreadPoolExecutor
import pytest
from teamlab.board import Board
from teamlab.controller import Controller
from teamlab.fixture import generate
from teamlab.postgres import connect
from teamlab.security import SecurityError

URL = os.environ.get('TEAMLAB_TEST_POSTGRES_URL')


@pytest.mark.skipif(not URL, reason='Requires disposable PostgreSQL database and psycopg')
def test_postgres_dynamic_claim_and_stop_fencing(tmp_path):
    source=tmp_path/'input.csv';generate(source,100)
    c=Controller(tmp_path/'root',source,database_url=os.environ['TEAMLAB_TEST_POSTGRES_URL'])
    b=Board(c);root=b.create(c.lead,'Report','Exact results',list(range(c.workers)))
    b.split(c.lead,root['id'],[{'title':str(i),'criteria':'Exact results','partitions':[i]} for i in range(c.workers)])
    with ThreadPoolExecutor(c.workers) as pool:tasks=list(pool.map(b.claim,c.worker_tokens.values()))
    assert len({t['id'] for t in tasks})==c.workers
    c.store.stop(c.run_id,'Database stop fixture')
    from teamlab.security import RunStopped
    with pytest.raises(RunStopped):b.calculate(c.worker_tokens[0],tasks[0]['id'],tasks[0]['fence'])


def test_postgres_adapter_rejects_unreachable_database():
    pytest.importorskip('psycopg')
    with pytest.raises(Exception):
        with connect('postgresql://teamlab:invalid@127.0.0.1:1/none'):
            pass


@pytest.mark.skipif(not URL, reason='Requires disposable PostgreSQL database and psycopg')
def test_postgres_lock_timeout_blocks_a_second_transaction(tmp_path):
    import time
    import psycopg
    source = tmp_path / 'input.csv'
    generate(source, 20)
    Controller(tmp_path / 'root', source, workers=1, database_url=URL)
    holder = psycopg.connect(URL, autocommit=False)
    try:
        holder.execute('LOCK TABLE runs IN ACCESS EXCLUSIVE MODE')
        started = time.monotonic()
        with pytest.raises(Exception):
            with connect(URL) as db:
                db.execute('BEGIN')
                db.execute('SELECT * FROM runs FOR UPDATE')
        assert time.monotonic() - started < 8
    finally:
        holder.rollback()
        holder.close()


@pytest.mark.skipif(not URL, reason='Requires disposable PostgreSQL database and psycopg')
def test_postgres_statement_timeout_and_storage_quota(monkeypatch):
    with connect(URL) as db:
        with pytest.raises(Exception):
            db.execute('SELECT pg_sleep(6)')
    monkeypatch.setenv('TEAMLAB_DATABASE_QUOTA_BYTES', '1')
    with pytest.raises(SecurityError, match='quota'):
        with connect(URL):
            pass
