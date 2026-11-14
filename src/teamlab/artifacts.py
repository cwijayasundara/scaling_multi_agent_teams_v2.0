"""Immutable authored sources and exact-hash verification/integration."""
import hashlib
import json
import os
import re
import subprocess
import tempfile
import time
from pathlib import Path

from .analytics import canonical, digest
from .security import SecurityError


def commit_verified_source(repo: Path, task_id: str, author: str, source: str) -> str:
    """Commit exact verified source. The caller owns the repository path."""
    if not re.fullmatch(r'worker-[0-9]+', author or '') or not re.fullmatch(r'[0-9a-f]{16}', task_id or ''):
        raise SecurityError('unexpected artifact author')
    if not isinstance(source, str) or not 1 <= len(source.encode()) <= 64_000 or '\0' in source:
        raise SecurityError('integration source rejected')
    repo = Path(repo)
    if repo.is_symlink():
        raise SecurityError('integration repository must be a real directory')
    repo.mkdir(parents=True, exist_ok=True)
    env = {'PATH': os.defpath, 'HOME': str(repo), 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': os.devnull,
        'GIT_AUTHOR_NAME': 'TeamLab', 'GIT_AUTHOR_EMAIL': 'teamlab@invalid', 'GIT_COMMITTER_NAME': 'TeamLab', 'GIT_COMMITTER_EMAIL': 'teamlab@invalid'}

    def git(*args):
        return subprocess.run(['git', '-c', 'core.hooksPath=/dev/null', '-c', 'commit.gpgsign=false', *args], cwd=repo, env=env, check=True, capture_output=True, text=True, timeout=10).stdout.strip()

    if not (repo / '.git').exists():
        git('init', '-b', 'main')
        git('commit', '--allow-empty', '-m', 'Initialize private run')
    git('checkout', '-B', author, 'main')
    target = repo / 'tasks' / task_id / 'calculation.py'
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(source)
    git('add', '--', str(target.relative_to(repo)))
    if git('diff', '--cached', '--name-only'):
        git('commit', '-m', 'Verified task ' + task_id)
    git('checkout', 'main')
    git('merge', '--ff-only', author)
    return git('rev-parse', 'HEAD')


class Artifacts:
    def __init__(self, board, broker=None):
        self.board, self.c, self.broker = board, board.c, broker

    def write(self, token, task_id, fence, source, name='calculation.py'):
        if name != 'calculation.py' or not isinstance(source, str) or not 1 <= len(source.encode()) <= 64_000 or '\0' in source:
            raise ValueError('only bounded calculation.py source is accepted')
        source_hash = hashlib.sha256(source.encode()).hexdigest()
        def handler(db, who):
            row = self.board._row(db, who, task_id)
            self.board._lease(row, who, fence)
            count = db.execute('SELECT count(*) FROM work_artifacts WHERE run_id=?', (who.run_id,)).fetchone()[0]
            if count >= 256:
                raise ValueError('artifact quota exceeded')
            db.execute('INSERT OR IGNORE INTO work_artifacts VALUES (?,?,?,?,?,?,?,?)',
                (who.run_id, source_hash, task_id, who.agent_id, name, source, fence, time.time()))
            return {'artifact_hash': source_hash, 'bytes': len(source.encode())}
        return self.c.call(token, 'write_artifact', {'task_id': task_id, 'fence': fence, 'source_hash': source_hash, 'source': source}, handler)

    def source(self, db, who, task_id, source_hash):
        row = db.execute('SELECT * FROM work_artifacts WHERE run_id=? AND task_id=? AND hash=? ORDER BY fence DESC LIMIT 1', (who.run_id, task_id, source_hash)).fetchone()
        if row is None or hashlib.sha256(row['content'].encode()).hexdigest() != source_hash:
            raise SecurityError('missing or modified source')
        return dict(row)

    def execute(self, token, task_id, fence, source_hash):
        if self.broker is None:
            raise SecurityError('isolated execution broker required; no host execution fallback')
        # Pre-dispatch monitoring happens before broker execution. The returned
        # permit contains only runtime-selected source and immutable input.
        def authorize(db, who):
            row = self.board._row(db, who, task_id)
            self.board._lease(row, who, fence)
            artifact = self.source(db, who, task_id, source_hash)
            if artifact['author'] != who.agent_id or artifact['fence'] != fence:
                raise SecurityError('source ownership/fence mismatch')
            return {'source': artifact['content'], 'records': self.board.records(row), 'task_version': row['version']}
        permit = self.c.call(token, 'run_artifact', {'task_id': task_id, 'fence': fence, 'source_hash': source_hash}, authorize)
        who = self.c.gateway.active(token)
        result = self.broker.execute(self.c.gateway, token, permit['source'], permit['records'])
        def commit(db, identity):
            row = self.board._row(db, identity, task_id)
            self.board._lease(row, identity, fence)
            if row['version'] != permit['task_version']:
                raise SecurityError('task changed during execution')
            db.execute('UPDATE work SET result=?,result_hash=?,artifact_hash=? WHERE run_id=? AND id=?',
                (canonical(result), digest(result), source_hash, identity.run_id, task_id))
            self.c.store.event(db, who.run_id, who.agent_id, 'artifact.executed', {'task_id': task_id, 'source_hash': source_hash, 'input_hash': digest(permit['records']), 'result_hash': digest(result), 'broker': self.broker.profile})
            return {'result_hash': digest(result), 'artifact_hash': source_hash}
        return self.c.call(token, 'record_execution', {'task_id': task_id, 'fence': fence, 'source_hash': source_hash}, commit)

    def verify(self, token, task_id):
        if self.broker is None:
            raise SecurityError('fresh isolated verification execution required')
        def authorize(db, who):
            row = self.board._row(db, who, task_id)
            if row['state'] != 'SUBMITTED' or not row['artifact_hash']:
                raise ValueError('authored submission required')
            source = self.source(db, who, task_id, row['artifact_hash'])
            return {'task': row, 'source': source['content'], 'records': self.board.records(row)}
        permit = self.c.call(token, 'verify_artifact', {'task_id': task_id}, authorize)
        result = self.broker.execute(self.c.gateway, token, permit['source'], permit['records'])
        verdict = self.c.grade_candidate(permit['records'], result)
        if digest(result) != permit['task']['result_hash']:
            verdict = {'passed': False, 'failed_fields': ['reproduction']}
        def commit(db, who):
            row = self.board._row(db, who, task_id)
            if row['state'] != 'SUBMITTED' or row['version'] != permit['task']['version'] or row['result_hash'] != permit['task']['result_hash']:
                raise SecurityError('submission changed during verification')
            return self.board._accept(db, who, row, verdict)
        return self.c.call(token, 'record_verification', {'task_id': task_id, 'source_hash': permit['task']['artifact_hash']}, commit)

    def integrate(self, token, task_id):
        """Export verified source to a private, service-owned Git repository."""
        # Git has no remote, no agent-supplied options/configuration and runs
        # with a clean environment and disabled hooks/system configuration.
        def handler(db, who):
            row = self.board._row(db, who, task_id)
            if row['state'] not in ('VERIFIED', 'DONE') or not row['artifact_hash']:
                raise SecurityError('verified authored artifact required')
            source = self.source(db, who, task_id, row['artifact_hash'])
            plane = getattr(self.c, 'plane', None)
            if plane is not None:
                commit = plane.integrate({'run_id': who.run_id, 'task_id': task_id, 'author': source['author'], 'source': source['content'], 'source_hash': row['artifact_hash']})
            else:
                commit = commit_verified_source(self.c.root / 'integration' / who.run_id, task_id, source['author'], source['content'])
            self.c.store.event(db, who.run_id, who.agent_id, 'artifact.integrated', {'task_id': task_id, 'source_hash': row['artifact_hash'], 'commit': commit, 'branch': source['author']})
            return {'commit': commit}
        receipt = self.c.call(token, 'integrate_artifact', {'task_id': task_id}, handler)
        self.board.integrate(token, task_id)
        return receipt
