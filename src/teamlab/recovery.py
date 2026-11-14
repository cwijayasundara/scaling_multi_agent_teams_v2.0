"""Durable graph records and operator-selected, clean-context task recovery."""
import hashlib
import json
import threading
import time

from langgraph.checkpoint.memory import InMemorySaver
from .analytics import canonical, digest
from .board import decoded
from .security import SecurityError


class DurableSaver(InMemorySaver):
    """Persist the pinned SDK saver representation without pickle.

    Keep complete ancestor chains, blobs and pending writes for DeltaChannels.
    A saver belongs to one run; model tools never expose these bytes.
    """
    def __init__(self, store, run_id):
        super().__init__()
        self.store, self.run_id, self.lock = store, run_id, threading.RLock()
        with store.connect() as db:
            db.execute('CREATE TABLE IF NOT EXISTS graph_state(run_id TEXT PRIMARY KEY,type TEXT,payload BLOB,hash TEXT)')
            row = db.execute('SELECT * FROM graph_state WHERE run_id=?', (run_id,)).fetchone()
        if row:
            if hashlib.sha256(row['payload']).hexdigest() != row['hash']:
                raise SecurityError('graph checkpoint integrity failed')
            data = self.serde.loads_typed((row['type'], row['payload']))
            for thread, namespace, items in data['storage']:
                self.storage[thread][namespace].update(items)
            for key, items in data['writes']:
                self.writes[tuple(key)].update({tuple(k): tuple(v) for k, v in items})
            self.blobs.update({tuple(k): tuple(v) for k, v in data['blobs']})

    def flush(self):
        data = {'storage': [(thread, ns, dict(items)) for thread, namespaces in self.storage.items() for ns, items in namespaces.items()],
                'writes': [(key, list(items.items())) for key, items in self.writes.items()], 'blobs': list(self.blobs.items())}
        kind, payload = self.serde.dumps_typed(data)
        if len(payload) > 64*1024*1024:
            raise SecurityError('graph checkpoint quota exceeded')
        with self.store.transaction() as db:
            db.execute('INSERT OR REPLACE INTO graph_state VALUES (?,?,?,?)', (self.run_id, kind, payload, hashlib.sha256(payload).hexdigest()))

    def put(self, *args, **kwargs):
        with self.lock:
            result = super().put(*args, **kwargs)
            self.flush()
            return result

    def put_writes(self, *args, **kwargs):
        with self.lock:
            super().put_writes(*args, **kwargs)
            self.flush()

    def get_tuple(self, config):
        with self.lock:
            return super().get_tuple(config)


class Checkpoints:
    def __init__(self, board):
        self.board, self.c = board, board.c

    def save(self, checkpoint_id):
        """Only scheduler-quiescent task snapshots are restart candidates."""
        with self.c.store.transaction() as db:
            run = self.c.store.lock_run(db, self.c.run_id)
            if run['state'] != 'RUNNING':
                raise SecurityError('checkpoint requires an active run')
            tasks = [decoded(r) for r in db.execute('SELECT * FROM work WHERE run_id=?', (self.c.run_id,))]
            if any(t['state'] == 'LEASED' and t['lease_until'] > time.time() for t in tasks):
                raise ValueError('checkpoint requires no active task leases')
            artifacts = [dict(r) for r in db.execute('SELECT * FROM work_artifacts WHERE run_id=?', (self.c.run_id,))]
            payload = {'format': 1, 'input_hash': self.c.input_hash, 'workers': self.c.workers, 'tasks': tasks, 'artifacts': artifacts,
                       'recovery': 'new run, reviewed task tree, fresh model contexts and credentials'}
            encoded = canonical(payload)
            db.execute('INSERT INTO work_checkpoints VALUES (?,?,?,?,?)', (self.c.run_id, checkpoint_id, digest(payload), encoded, time.time()))
            self.c.store.event(db, self.c.run_id, 'scheduler', 'checkpoint.saved', {'checkpoint_id': checkpoint_id, 'hash': digest(payload)})
            return {'checkpoint_id': checkpoint_id, 'hash': digest(payload)}

    def restore(self, prior_run, checkpoint_id, broker=None):
        c = self.c
        with c.store.connect() as db:
            prior = db.execute('SELECT * FROM runs WHERE id=?', (prior_run,)).fetchone()
            row = db.execute('SELECT * FROM work_checkpoints WHERE run_id=? AND id=?', (prior_run, checkpoint_id)).fetchone()
        if prior is None or prior['state'] not in ('STOPPED', 'PAUSED', 'FAILED'):
            raise ValueError('only an operator-reviewed inactive run can be recovered')
        if row is None:
            raise ValueError('checkpoint not found')
        payload = json.loads(row['payload'])
        if payload.get('format') != 1 or digest(payload) != row['hash'] or payload['input_hash'] != c.input_hash or payload['workers'] != c.workers:
            raise SecurityError('checkpoint integrity or input mismatch')
        tasks = payload['tasks']
        authored = any(t['artifact_hash'] for t in tasks)
        if authored and broker is None:
            raise SecurityError('authored checkpoint recovery requires fresh isolated revalidation')
        imported_sources = []
        for task in tasks:
            if task['state'] != 'DONE':
                continue
            if not self.c.grade_candidate(self.board.records(task), task['result'])['passed']:
                raise SecurityError('checkpoint completed result failed independent revalidation')
            if not task['artifact_hash']:
                continue
            source = next((a for a in payload['artifacts'] if a['task_id']==task['id'] and a['hash']==task['artifact_hash'] and a['fence']==task['fence']), None)
            if source is None or hashlib.sha256(source['content'].encode()).hexdigest() != source['hash']:
                raise SecurityError('checkpoint authored source integrity failed')
            # The gateway monitors exact source before a fresh reproduction.
            c.call(c.verifier, 'verify_artifact', {'task_id': task['id'], 'source_hash': source['hash'], 'source': source['content'], 'recovery': True}, lambda db,who: {'authorized': True})
            result = broker.execute(c.gateway, c.verifier, source['content'], self.board.records(task))
            if digest(result) != task['result_hash'] or not self.c.grade_candidate(self.board.records(task), result)['passed']:
                raise SecurityError('checkpoint authored reproduction failed')
            imported_sources.append(source)
        with c.store.transaction() as db:
            active = c.store.lock_run(db, c.run_id)
            if active['state'] != 'RUNNING':
                raise SecurityError('recovery authority revoked')
            if db.execute('SELECT 1 FROM work WHERE run_id=?', (c.run_id,)).fetchone():
                raise ValueError('recovery target is not empty')
            parents = {t['parent'] for t in tasks if t['parent']}
            for task in tasks:
                task = dict(task)
                task['run_id'] = c.run_id
                task['owner'], task['lease_until'] = None, None
                task['fence'] += 1
                task['version'] += 1
                if authored and task['id'] in parents:
                    task['state'], task['result'], task['result_hash'] = 'WAITING', None, None
                elif task['state']=='DONE' and task['artifact_hash']:
                    # Reintegrate reproduced source into the new run repository.
                    task['state'] = 'VERIFIED'
                elif task['state'] not in ('DONE', 'WAITING'):
                    task['state'] = 'READY' if task['attempts'] < 2 else 'BLOCKED'
                    task['result'], task['result_hash'], task['artifact_hash'] = None, None, None
                for key in ('partitions', 'dependencies', 'result'):
                    if task[key] is not None:
                        task[key] = canonical(task[key])
                keys = list(task)
                db.execute('INSERT INTO work('+','.join(keys)+') VALUES ('+','.join('?' for _ in keys)+')', tuple(task[k] for k in keys))
            for source in imported_sources:
                db.execute('INSERT INTO work_artifacts VALUES (?,?,?,?,?,?,?,?)',
                    (c.run_id,source['hash'],source['task_id'],source['author'],source['name'],source['content'],source['fence']+1,time.time()))
            c.store.event(db, c.run_id, 'operator', 'checkpoint.restored', {'prior_run': prior_run, 'checkpoint_id': checkpoint_id, 'hash': row['hash'], 'fresh_contexts': True, 'authored_sources_reproduced': len(imported_sources)})
