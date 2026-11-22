import json
from threading import Thread
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from teamlab.analytics import digest
from teamlab.cli import main, validate_bundle
from teamlab.controller import Controller
from teamlab.fixture import generate
from teamlab.identity import verify_journal_signatures
from teamlab.security import SecurityError
from teamlab.tracing import chain, current_span, last_operation_id, span, trace_tree


@pytest.fixture
def controller(tmp_path):
    source = tmp_path / "source.csv"
    generate(source, rows=100, seed=3)
    return Controller(tmp_path / "run", source)


def _rewrite(path, index, mutate):
    lines = [json.loads(line) for line in path.read_text().splitlines()]
    mutate(lines[index]['record'])
    previous = '0' * 64
    for item in lines:
        item['previous'] = previous
        item.pop('hash', None)
        item['hash'] = digest(item)
        previous = item['hash']
    path.write_text(''.join(json.dumps(item, sort_keys=True, separators=(',', ':')) + '\n' for item in lines))


def test_scripted_actions_chain_to_run_root(controller):
    controller.run_scripted()
    tree = trace_tree(controller.store, controller.run_id)
    assert tree['trace_id'] == controller.run_id
    roots = [s for s in tree['spans'] if s['parent_id'] is None]
    assert [r['name'] for r in roots] == ['run']
    assert all(s['status'] == 'ok' and s['ended'] is not None for s in tree['spans'])
    submit = next(o for o in tree['operations'] if o['action'] == 'submit_result')
    path = chain(controller.store, controller.run_id, submit['span_id'])
    assert path[0]['span_id'] == submit['span_id']
    assert [p['name'] for p in path if 'name' in p][-2:] == ['worker-turn', 'run']
    plan = next(o for o in tree['operations'] if o['action'] == 'record_plan')
    assert plan['parent_id'] == roots[0]['span_id']


def test_parallel_workers_keep_their_own_parents(controller):
    controller.run_scripted()
    tree = trace_tree(controller.store, controller.run_id)
    turns = {s['span_id']: s['agent_id'] for s in tree['spans'] if s['name'] == 'worker-turn'}
    assert len(turns) == controller.workers
    worker_ops = [op for op in tree['operations'] if op['agent_id'].startswith('worker-')]
    assert worker_ops
    for op in worker_ops:
        assert turns[op['parent_id']] == op['agent_id']


def test_gateway_signs_parent_and_exposes_last_operation(controller):
    assert current_span() is None
    with span(controller.store, controller.run_id, 'outer', 'controller', parent=None) as outer:
        seen = []
        receipt = controller.call(controller.lead, 'get_progress', {}, lambda db, who: seen.append(current_span()) or {})
        assert receipt == {}
        operation = last_operation_id()
        assert seen == [operation] and current_span() == outer
    assert current_span() is None
    event = next(e for e in controller.store.events(controller.run_id) if e['kind'] == 'action.authorized')
    assert event['detail']['request']['parent_id'] == outer
    assert event['detail']['trace'] == {'trace_id': controller.run_id, 'span_id': operation, 'parent_id': outer}


def test_delegated_worker_turn_is_parented_to_delegate_operation(controller):
    from teamlab.agents import AgentTeam
    controller.mode = 'sdk-replay'
    out = AgentTeam(controller, replay=True).run()
    assert validate_bundle(out)['passed']
    tree = trace_tree(controller.store, controller.run_id)
    assert [s['name'] for s in tree['spans'] if s['parent_id'] is None] == ['run']
    delegated = [s for s in tree['spans'] if s['name'] == 'delegated-turn']
    ops = {o['span_id']: o for o in tree['operations']}
    assert len(delegated) == controller.workers
    assert all(ops[s['parent_id']]['action'] == 'delegate' for s in delegated)
    assert {s['agent_id'] for s in delegated} == {f'worker-{i}' for i in range(controller.workers)}
    verification = [s for s in tree['spans'] if s['name'] == 'verifier-turn']
    assert len(verification) == 1 and ops[verification[0]['parent_id']]['action'] == 'request_verification'
    submit = next(o for o in tree['operations'] if o['action'] == 'submit_result')
    names = [p.get('name') or p['action'] for p in chain(controller.store, controller.run_id, submit['span_id'])]
    assert names == ['submit_result', 'delegated-turn', 'delegate', 'run']


def test_collaborative_turns_are_parented_to_rounds(tmp_path):
    from teamlab.collaborative import CollaborativeTeam
    source = tmp_path / 'input.csv'
    generate(source, 100)
    c = Controller(tmp_path / 'root', source, workers=2, mode='sdk-replay')
    out = CollaborativeTeam(c, replay=True).run()
    assert validate_bundle(out)['passed']
    tree = trace_tree(c.store, c.run_id)
    spans = {s['span_id']: s for s in tree['spans']}
    roots = [s for s in tree['spans'] if s['parent_id'] is None]
    assert [r['name'] for r in roots] == ['run']
    rounds = [s for s in tree['spans'] if s['name'].startswith('round-')]
    assert rounds and all(s['parent_id'] == roots[0]['span_id'] for s in rounds)
    turns = [s for s in tree['spans'] if s['name'] == 'turn']
    assert turns and all(spans[s['parent_id']]['name'].startswith('round-') for s in turns)
    assert {s['agent_id'] for s in turns} >= {'coordinator', 'verifier', 'worker-0', 'worker-1'}
    worker_ops = [o for o in tree['operations'] if o['agent_id'].startswith('worker-')]
    assert worker_ops and all(spans[o['parent_id']]['agent_id'] == o['agent_id'] for o in worker_ops)


def test_parent_id_is_signed(controller):
    controller.run_scripted()
    path = controller.store.root / 'audit.jsonl'
    assert verify_journal_signatures(path, controller.store) == controller.gateway.journal.verify()
    _rewrite(path, 2, lambda r: r['trace'].__setitem__('parent_id', 'sp-forged'))
    assert controller.gateway.journal.verify() > 2  # chain still valid
    with pytest.raises(SecurityError, match='differs from signed request'):
        verify_journal_signatures(path, controller.store)
    _rewrite(path, 2, lambda r: (r['trace'].__setitem__('parent_id', 'sp-forged'), r['request'].__setitem__('parent_id', 'sp-forged')))
    with pytest.raises(SecurityError, match='bad signature'):
        verify_journal_signatures(path, controller.store)


def test_span_marks_error_and_reraises(controller):
    with pytest.raises(RuntimeError):
        with span(controller.store, controller.run_id, 'x', 'controller', parent=None):
            raise RuntimeError('boom')
    assert current_span() is None
    ended = [e for e in controller.store.events(controller.run_id) if e['kind'] == 'span.ended']
    assert ended[-1]['detail']['status'] == 'error'


def test_span_inherits_current_span_by_default(controller):
    with span(controller.store, controller.run_id, 'outer', 'controller', parent=None) as outer:
        with span(controller.store, controller.run_id, 'inner', 'controller') as inner:
            assert current_span() == inner and inner.startswith('sp-')
    tree = trace_tree(controller.store, controller.run_id)
    assert {s['name']: s['parent_id'] for s in tree['spans']} == {'outer': None, 'inner': outer}
    assert [p['name'] for p in chain(controller.store, controller.run_id, inner)] == ['inner', 'outer']
    with pytest.raises(ValueError, match='unknown span'):
        chain(controller.store, controller.run_id, 'sp-missing')


def test_trace_cli_and_api(controller, tmp_path, capsys):
    from teamlab.monitoring import server_for
    controller.run_scripted()
    root = str(controller.store.root)
    assert main(['trace', '--root', root, '--run-id', controller.run_id]) == 0
    tree = json.loads(capsys.readouterr().out)
    assert tree['trace_id'] == controller.run_id and tree['spans']
    op = next(o for o in tree['operations'] if o['action'] == 'submit_result')
    assert main(['trace', '--root', root, '--run-id', controller.run_id, '--span', op['span_id']]) == 0
    path = json.loads(capsys.readouterr().out)
    assert path[0]['span_id'] == op['span_id'] and path[-1]['name'] == 'run'
    assert main(['trace', '--root', root, '--run-id', controller.run_id, '--span', 'sp-missing']) == 1
    assert 'unknown span' in capsys.readouterr().err
    missing = tmp_path / 'typo'
    assert main(['trace', '--root', str(missing), '--run-id', 'x']) == 1
    assert 'not found' in capsys.readouterr().err
    assert not missing.exists()
    try:
        server = server_for(controller.store, 'x' * 32, port=0)
    except OSError as exc:
        pytest.skip(f'loopback socket unavailable in this execution environment: {exc}')
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f'http://127.0.0.1:{server.server_port}/runs/{controller.run_id}/trace'
    try:
        with pytest.raises(HTTPError) as denied:
            urlopen(url, timeout=2)
        assert denied.value.code == 403
        with urlopen(Request(url, headers={'Authorization': 'Bearer ' + 'x' * 32}), timeout=2) as response:
            payload = json.load(response)
        assert payload == trace_tree(controller.store, controller.run_id)
    finally:
        server.shutdown()
        server.server_close()


def test_bundle_contains_trace(controller):
    out = controller.run_scripted()
    manifest = json.loads((out / 'manifest.json').read_text())
    assert 'trace.json' in manifest
    trace = json.loads((out / 'trace.json').read_text())
    assert trace['trace_id'] == controller.run_id
    run_span = next(s for s in trace['spans'] if s['name'] == 'run')
    assert run_span['status'] == 'ok'
    assert validate_bundle(out)['passed']
