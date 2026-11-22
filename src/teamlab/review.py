"""Read-only operator snapshots and deterministic post-run evidence review."""
import json
from .security import Journal, SecurityError


def all_events(store, run_id):
    result, after = [], 0
    while batch := store.events(run_id, after):
        result.extend(batch)
        after = batch[-1]['seq']
    return result


def snapshot(store, run_id):
    run = store.run(run_id)
    events = all_events(store, run_id)
    summaries = {}
    path = store.root / 'artifacts' / run_id / 'model_summaries.json'
    # Run IDs come from the database, never arbitrary filesystem paths.
    if path.is_file() and not path.is_symlink():
        summaries = json.loads(path.read_text())
    with store.connect() as db:
        has_work = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='work'").fetchone()
        work = []
        if has_work:
            from .board import decoded
            work = [{k: v for k, v in decoded(r).items() if k != 'result'} for r in db.execute('SELECT * FROM work WHERE run_id=?', (run_id,))]
    config = next((e['detail'] for e in reversed(events) if e['kind']=='execution.configured'), {})
    authored = config.get('workflow') == 'authored'
    from .containment import agent_states
    return {
        'work': work,
        'agents': agent_states(store, run_id),
        'run': run,
        'tasks': [{k: t[k] for k in ('shard', 'state', 'owner', 'fence')} for t in store.tasks(run_id)],
        'events': events, 'summaries': summaries,
        'execution': {'profile': 'trusted-tools', 'isolation': 'Shared Python runtime',
                      'sandboxed': False, 'code_execution': config.get('code_execution', 'trusted-baseline'),
                      'description': 'Shared agent runtime; authored code uses a fresh offline OpenShell microVM per execution. Re-run qualify-host after any gateway or image change.' if authored else 'Fixed trusted tools; no per-agent container or microVM.'},
    }


def review(store, run_id):
    """Recompute evidence checks; does not claim an LLM threat-model review."""
    run = store.run(run_id)
    events = all_events(store, run_id)
    findings = [ {'seq': e['seq'], 'agent_id': e['agent_id'], 'kind': e['kind'], 'detail': e['detail']}
                 for e in events if e['kind'] in ('action.denied', 'run.paused', 'run.stopped', 'run.failed') ]
    checks = []
    try:
        audit = store.root / 'audit.jsonl'
        if not audit.is_file():
            raise ValueError('missing audit')
        count = Journal(audit).verify()
        checks.append({'name': 'Root audit hash chain', 'status': 'passed', 'detail': f'{count} records checked across this root.'})
    except (OSError, ValueError, KeyError, TypeError, SecurityError):
        checks.append({'name': 'Root audit hash chain', 'status': 'failed', 'detail': 'Audit is missing or failed integrity verification.'})
    if run['state'] == 'COMPLETED':
        from .cli import validate_bundle
        try:
            result = validate_bundle(store.root / 'artifacts' / run_id)
            checks.append({'name': 'Bundle and independent calculation', 'status': 'passed', 'detail': f"{result['artifacts_checked']} artifacts checked; reference calculation passed."})
        except (OSError, ValueError, KeyError, TypeError, SecurityError):
            checks.append({'name': 'Bundle and independent calculation', 'status': 'failed', 'detail': 'Bundle is missing, invalid, or differs from the reference calculation.'})
    else:
        checks.append({'name': 'Bundle and independent calculation', 'status': 'pending', 'detail': 'Available after successful completion.'})
    authorized = {e['detail'].get('operation_id') for e in events if e['kind'] == 'action.authorized'}
    committed = {e['detail'].get('operation_id') for e in events if e['kind'] == 'action.committed'}
    orphan = committed - authorized
    checks.append({'name': 'Committed action provenance', 'status': 'failed' if orphan else 'passed', 'detail': f'{len(committed)} committed operations; {len(orphan)} without an authorization event.'})
    with store.connect() as db:
        has_reviews = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='behavior_reviews'").fetchone()
        saved = db.execute('SELECT payload FROM behavior_reviews WHERE run_id=?', (run_id,)).fetchone() if has_reviews else None
    behavior = json.loads(saved['payload']) if saved else None
    return {'behavior': behavior, 'run_id': run_id, 'kind': 'deterministic-evidence-review', 'checks': checks, 'findings': findings,
            'limitation': 'Integrity and calculation checks only. Behavioral LLM review, when available, is shown separately with its own evidence coverage. No private reasoning transcript is used. Hashes are not authenticated signatures.'}
