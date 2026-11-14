"""Bounded, run-scoped collaboration. All writes use gateway transactions."""
import json
import secrets
import time

from .analytics import canonical, digest, analyze, combine
from .security import SecurityError

SCHEMA = """
CREATE TABLE IF NOT EXISTS work (
 run_id TEXT NOT NULL, id TEXT NOT NULL, parent TEXT, title TEXT NOT NULL,
 criteria TEXT NOT NULL, creator TEXT NOT NULL, origin TEXT NOT NULL,
 partitions TEXT NOT NULL, dependencies TEXT NOT NULL, state TEXT NOT NULL,
 owner TEXT, fence INTEGER NOT NULL DEFAULT 0, attempts INTEGER NOT NULL DEFAULT 0,
 lease_until REAL, version INTEGER NOT NULL DEFAULT 1, priority INTEGER NOT NULL DEFAULT 0,
 result TEXT, result_hash TEXT, artifact_hash TEXT, blocker TEXT,
 PRIMARY KEY(run_id,id)
);
CREATE TABLE IF NOT EXISTS work_notes (
 seq INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT NOT NULL, task_id TEXT,
 author TEXT NOT NULL, text TEXT NOT NULL, created REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS work_artifacts (
 run_id TEXT NOT NULL, hash TEXT NOT NULL, task_id TEXT NOT NULL,
 author TEXT NOT NULL, name TEXT NOT NULL, content TEXT NOT NULL,
 fence INTEGER NOT NULL, created REAL NOT NULL,
 PRIMARY KEY(run_id,task_id,hash,fence)
);
CREATE TABLE IF NOT EXISTS work_checkpoints (
 run_id TEXT NOT NULL, id TEXT NOT NULL, hash TEXT NOT NULL, payload TEXT NOT NULL,
 created REAL NOT NULL, PRIMARY KEY(run_id,id)
);
"""


def decoded(row):
    result = dict(row)
    for key in ('partitions', 'dependencies', 'result'):
        if result.get(key) is not None:
            result[key] = json.loads(result[key])
    return result


class Board:
    max_tasks = 128
    max_depth = 8

    def __init__(self, controller):
        self.c = controller
        with controller.store.connect() as db:
            db.executescript(SCHEMA)

    def _row(self, db, who, task_id):
        row = db.execute('SELECT * FROM work WHERE run_id=? AND id=?', (who.run_id, task_id)).fetchone()
        if row is None:
            raise ValueError('unknown task in this run')
        return decoded(row)

    def _lease(self, row, who, fence):
        if row['state'] != 'LEASED' or row['owner'] != who.agent_id or row['fence'] != fence or row['lease_until'] <= time.time():
            raise SecurityError('task lease expired, stale or owned by another worker')

    def list(self, token):
        return self.c.call(token, 'list_tasks', {}, lambda db, who: [
            {k: v for k, v in decoded(r).items() if k != 'result'}
            for r in db.execute('SELECT * FROM work WHERE run_id=? ORDER BY priority DESC,id', (who.run_id,))])

    def create(self, token, title, criteria, partitions, dependencies=None):
        """Create the single root; decomposition happens through split()."""
        def handler(db, who):
            if db.execute('SELECT 1 FROM work WHERE run_id=?', (who.run_id,)).fetchone():
                raise ValueError('root already exists; split an existing task')
            if any(type(p) is not int for p in partitions) or sorted(partitions) != list(range(self.c.workers)) or len(set(partitions)) != len(partitions):
                raise ValueError('root must cover all immutable input partitions exactly once')
            if dependencies:
                raise ValueError('root cannot have dependencies')
            return self._insert(db, who, None, title, criteria, partitions, [])
        return self.c.call(token, 'create_task', {'title': title, 'criteria': criteria, 'partitions': partitions}, handler)

    def _insert(self, db, who, parent, title, criteria, partitions, dependencies):
        if not isinstance(title, str) or not 1 <= len(title) <= 160 or not isinstance(criteria, str) or not 1 <= len(criteria) <= 2000:
            raise ValueError('title and acceptance criteria required within quotas')
        if db.execute('SELECT count(*) FROM work WHERE run_id=?', (who.run_id,)).fetchone()[0] >= self.max_tasks:
            raise ValueError('task quota exceeded')
        task_id = secrets.token_hex(8)
        origin = 'live-model' if self.c.mode == 'live' else self.c.mode
        db.execute('INSERT INTO work(run_id,id,parent,title,criteria,creator,origin,partitions,dependencies,state) VALUES (?,?,?,?,?,?,?,?,?,?)',
            (who.run_id, task_id, parent, title, criteria, who.agent_id, origin, canonical(partitions), canonical(dependencies), 'READY'))
        task = self._row(db, who, task_id)
        self.c.store.event(db, who.run_id, who.agent_id, 'task.created', task)
        return task

    def split(self, token, task_id, children, fence=None):
        """Atomically replace a leaf with an exact, nonoverlapping partitioning."""
        def handler(db, who):
            row = self._row(db, who, task_id)
            if row['state'] not in ('READY', 'LEASED', 'BLOCKED'):
                raise ValueError('task cannot be split in its current state')
            if row['state'] == 'LEASED':
                self._lease(row, who, fence)
            elif who.role != 'coordinator':
                raise SecurityError('claim task before splitting it')
            depth, ancestor = 0, row
            while ancestor['parent']:
                depth += 1
                ancestor = self._row(db, who, ancestor['parent'])
            if depth >= self.max_depth:
                raise ValueError('task depth quota exceeded')
            if not 2 <= len(children) <= 16:
                raise ValueError('split needs 2..16 children')
            parts = [p for child in children for p in child['partitions']]
            if any(type(p) is not int for p in parts) or sorted(parts) != sorted(row['partitions']) or len(parts) != len(set(parts)) or any(not child['partitions'] for child in children):
                raise ValueError('children must cover parent partitions exactly once')
            results = []
            # Dependencies can refer to earlier siblings by zero-based index.
            for i, child in enumerate(children):
                indexes = child.get('depends_on', [])
                if any(type(j) is not int or not 0 <= j < i for j in indexes):
                    raise ValueError('dependencies must reference earlier siblings; cycles forbidden')
                deps = list(row['dependencies']) + [results[j]['id'] for j in indexes]
                results.append(self._insert(db, who, task_id, child['title'], child['criteria'], child['partitions'], deps))
            db.execute("UPDATE work SET state='WAITING',fence=fence+1,version=version+1,owner=NULL,result=NULL,result_hash=NULL WHERE run_id=? AND id=?", (who.run_id, task_id))
            self.c.store.event(db, who.run_id, who.agent_id, 'task.split', {'task_id': task_id, 'children': [r['id'] for r in results]})
            return results
        return self.c.call(token, 'split_task', {'task_id': task_id, 'children': children, 'fence': fence}, handler)

    def claim(self, token):
        def handler(db, who):
            rows = db.execute("SELECT * FROM work WHERE run_id=? AND (state='READY' OR (state='LEASED' AND lease_until<=?)) ORDER BY priority DESC,id", (who.run_id, time.time())).fetchall()
            for raw in rows:
                row = decoded(raw)
                if row['attempts'] >= 2:
                    db.execute("UPDATE work SET state='BLOCKED',blocker='attempt budget exhausted',fence=fence+1 WHERE run_id=? AND id=?", (who.run_id, row['id']))
                    self.c.store.event(db, who.run_id, who.agent_id, 'task.blocked', {'task_id': row['id'], 'reason': 'attempt budget exhausted'})
                    continue
                if any(self._row(db, who, dep)['state'] != 'DONE' for dep in row['dependencies']):
                    continue
                db.execute("UPDATE work SET state='LEASED',owner=?,fence=fence+1,attempts=attempts+1,lease_until=?,version=version+1,result=NULL,result_hash=NULL,artifact_hash=NULL WHERE run_id=? AND id=?",
                    (who.agent_id, time.time()+300, who.run_id, row['id']))
                task = self._row(db, who, row['id'])
                self.c.store.event(db, who.run_id, who.agent_id, 'task.claimed', {k: v for k, v in task.items() if k != 'result'})
                return task
            return {'idle': True}
        return self.c.call(token, 'claim_work', {}, handler)

    def notes(self, token, after=0):
        return self.c.call(token, 'read_notes', {'after': after}, lambda db, who: [dict(r) for r in db.execute(
            'SELECT * FROM work_notes WHERE run_id=? AND seq>? ORDER BY seq LIMIT 64', (who.run_id, after))])

    def note(self, token, text, task_id=None):
        if not isinstance(text, str) or not 1 <= len(text) <= 2000:
            raise ValueError('note must contain 1..2000 characters')
        def handler(db, who):
            if task_id:
                self._row(db, who, task_id)
            if db.execute('SELECT count(*) FROM work_notes WHERE run_id=?', (who.run_id,)).fetchone()[0] >= 256:
                raise ValueError('note quota exceeded')
            db.execute('INSERT INTO work_notes(run_id,task_id,author,text,created) VALUES (?,?,?,?,?)', (who.run_id, task_id, who.agent_id, text, time.time()))
            self.c.store.event(db, who.run_id, who.agent_id, 'note.posted', {'task_id': task_id, 'text': text})
            return {'recorded': True}
        return self.c.call(token, 'post_note', {'text': text, 'task_id': task_id}, handler)

    def inspect(self, token, task_id, fence):
        def handler(db, who):
            row = self._row(db, who, task_id)
            self._lease(row, who, fence)
            records = self.records(row)
            return {'task': row, 'sample': records[:5], 'row_count': len(records), 'input_hash': self.c.input_hash}
        return self.c.call(token, 'inspect_work', {'task_id': task_id, 'fence': fence}, handler)

    def records(self, row):
        return [r for part in row['partitions'] for r in self.c.partitions[part]]

    def calculate(self, token, task_id, fence):
        def handler(db, who):
            row = self._row(db, who, task_id)
            self._lease(row, who, fence)
            result = analyze(self.records(row))
            db.execute('UPDATE work SET result=?,result_hash=? WHERE run_id=? AND id=?', (canonical(result), digest(result), who.run_id, task_id))
            return {'result_hash': digest(result), 'source': 'trusted-baseline'}
        return self.c.call(token, 'calculate_work', {'task_id': task_id, 'fence': fence}, handler)

    def submit(self, token, task_id, fence, result_hash):
        def handler(db, who):
            row = self._row(db, who, task_id)
            if row['state'] in ('SUBMITTED', 'VERIFIED', 'DONE') and row['owner'] == who.agent_id and row['fence'] == fence and row['result_hash'] == result_hash:
                return {'submitted': True, 'idempotent': True}
            self._lease(row, who, fence)
            if row['result'] is None or row['result_hash'] != result_hash:
                raise SecurityError('submission does not match owned result')
            db.execute("UPDATE work SET state='SUBMITTED' WHERE run_id=? AND id=?", (who.run_id, task_id))
            self.c.store.event(db, who.run_id, who.agent_id, 'task.submitted', {'task_id': task_id, 'result_hash': result_hash, 'artifact_hash': row['artifact_hash']})
            return {'submitted': True}
        return self.c.call(token, 'submit_task', {'task_id': task_id, 'fence': fence, 'result_hash': result_hash}, handler)

    def verify(self, token, task_id):
        def handler(db, who):
            row = self._row(db, who, task_id)
            if row['state'] != 'SUBMITTED':
                raise ValueError('task not submitted')
            if row['artifact_hash']:
                raise ValueError('artifact submissions require isolated reproduction before verification')
            return self._accept(db, who, row, self.c.grade_candidate(self.records(row), row['result']))
        return self.c.call(token, 'verify_task', {'task_id': task_id}, handler)

    def _accept(self, db, who, row, verdict):
        state = 'VERIFIED' if verdict['passed'] else 'FAILED'
        db.execute('UPDATE work SET state=? WHERE run_id=? AND id=?', (state, who.run_id, row['id']))
        self.c.store.event(db, who.run_id, who.agent_id, 'task.verified', {'task_id': row['id'], 'verdict': verdict})
        return verdict

    def integrate(self, token, task_id):
        def handler(db, who):
            row = self._row(db, who, task_id)
            if row['state'] == 'DONE':
                return {'integrated': True, 'idempotent': True}
            if row['state'] != 'VERIFIED':
                raise SecurityError('protected verification required')
            db.execute("UPDATE work SET state='DONE' WHERE run_id=? AND id=?", (who.run_id, task_id))
            self.c.store.event(db, who.run_id, who.agent_id, 'task.done', {'task_id': task_id})
            parent = row['parent']
            while parent:
                siblings = [decoded(r) for r in db.execute('SELECT * FROM work WHERE run_id=? AND parent=?', (who.run_id, parent))]
                if not all(r['state'] == 'DONE' for r in siblings):
                    break
                result = combine([r['result'] for r in siblings])
                db.execute("UPDATE work SET state='DONE',result=?,result_hash=? WHERE run_id=? AND id=?", (canonical(result), digest(result), who.run_id, parent))
                self.c.store.event(db, who.run_id, who.agent_id, 'task.done', {'task_id': parent})
                parent = self._row(db, who, parent)['parent']
            return {'integrated': True}
        return self.c.call(token, 'integrate_task', {'task_id': task_id}, handler)

    def block(self, token, task_id, fence, reason):
        if not isinstance(reason, str) or not 1 <= len(reason) <= 2000:
            raise ValueError('bounded blocker reason required')
        def handler(db, who):
            row = self._row(db, who, task_id)
            self._lease(row, who, fence)
            db.execute("UPDATE work SET state='BLOCKED',blocker=?,fence=fence+1 WHERE run_id=? AND id=?", (reason, who.run_id, task_id))
            self.c.store.event(db, who.run_id, who.agent_id, 'task.blocked', {'task_id': task_id, 'reason': reason})
            return {'blocked': True}
        return self.c.call(token, 'report_blocker', {'task_id': task_id, 'fence': fence, 'reason': reason}, handler)

    def reprioritize(self, token, task_id, priority, retry=False):
        if type(priority) is not int or not -10 <= priority <= 10:
            raise ValueError('priority must be -10..10')
        def handler(db, who):
            row = self._row(db, who, task_id)
            if retry and (row['state'] not in ('BLOCKED', 'FAILED') or row['attempts'] >= 2):
                raise ValueError('task cannot be retried')
            db.execute('UPDATE work SET priority=?,state=?,version=version+1 WHERE run_id=? AND id=?', (priority, 'READY' if retry else row['state'], who.run_id, task_id))
            return {'updated': True}
        return self.c.call(token, 'reprioritize_task', {'task_id': task_id, 'priority': priority, 'retry': retry}, handler)

    def publish(self, token):
        def handler(db, who):
            roots = [decoded(r) for r in db.execute('SELECT * FROM work WHERE run_id=? AND parent IS NULL', (who.run_id,))]
            if len(roots) != 1 or roots[0]['state'] != 'DONE':
                raise ValueError('root task is not complete')
            candidate = roots[0]['result']
            verdict = self.c.grade_candidate(self.c.records, candidate)
            if not verdict['passed']:
                raise SecurityError('final independent coverage/reference check failed')
            db.execute("UPDATE runs SET state='COMPLETED',epoch=epoch+1 WHERE id=?", (who.run_id,))
            self.c.store.event(db, who.run_id, who.agent_id, 'run.completed', {'candidate_hash': digest(candidate), 'workflow': 'collaborative'})
            return candidate
        candidate = self.c.call(token, 'publish_work', {}, handler)
        return self.c.export(candidate)
