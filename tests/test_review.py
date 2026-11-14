import json
from pathlib import Path

from teamlab.controller import Controller
from teamlab.fixture import generate
from teamlab.review import all_events, review, snapshot


def completed(tmp_path):
    source = tmp_path / 'input.csv'
    generate(source, rows=100)
    c = Controller(tmp_path / 'root', source)
    c.run_scripted()
    return c


def test_completed_review_checks_real_evidence_and_detects_tampering(tmp_path):
    c = completed(tmp_path)
    result = review(c.store, c.run_id)
    assert all(x['status'] == 'passed' for x in result['checks'])
    assert not result['findings']
    data = snapshot(c.store, c.run_id)
    assert data['execution']['sandboxed'] is False
    assert all(set(t) == {'shard', 'state', 'owner', 'fence'} for t in data['tasks'])
    metrics = c.root / 'artifacts' / c.run_id / 'metrics.json'
    metrics.write_text('{}')
    assert review(c.store, c.run_id)['checks'][1]['status'] == 'failed'
    audit = c.root / 'audit.jsonl'
    audit.write_text('{}\n')
    assert review(c.store, c.run_id)['checks'][0]['status'] == 'failed'
    audit.unlink()
    assert review(c.store, c.run_id)['checks'][0]['status'] == 'failed'


def test_review_detects_missing_authorization_and_reads_all_pages(tmp_path):
    c = completed(tmp_path)
    with c.store.transaction() as db:
        for i in range(1010):
            c.store.event(db, c.run_id, 'worker-0', 'test.event', {'index': i})
        c.store.event(db, c.run_id, 'worker-0', 'action.committed', {'operation_id': 'unauthorized'})
    assert len(all_events(c.store, c.run_id)) > 1000
    assert review(c.store, c.run_id)['checks'][2]['status'] == 'failed'



def test_dashboard_http_routes_without_listening_socket(tmp_path, monkeypatch):
    """Exercise the real HTTP handler even on hosts that prohibit bind()."""
    import io
    import teamlab.monitoring as monitoring
    c = completed(tmp_path)
    holder = {}
    def server(address, handler):
        holder['handler'] = handler
        return type('Server', (), {})()
    monkeypatch.setattr(monitoring, 'ThreadingHTTPServer', server)
    monitoring.server_for(c.store, 'x' * 32)
    class Connection:
        def __init__(self, path, headers):
            self.request = io.BytesIO(f'GET {path} HTTP/1.0\r\n{headers}\r\n'.encode())
            self.output = bytearray()
        def makefile(self, *args):
            return self.request
        def sendall(self, value):
            self.output.extend(value)
    for path in ('/runs', f'/runs/{c.run_id}/snapshot', f'/runs/{c.run_id}/review'):
        for auth, status in (('', b'403'), ('Authorization: Bearer '+ 'x'*32+'\r\n', b'200'), ('Authorization: Bearer '+ 'x'*32+'\r\nOrigin: http://evil.example\r\n', b'403')):
            connection = Connection(path, auth)
            holder['handler'](connection, ('127.0.0.1', 12345), object())
            head, body = bytes(connection.output).split(b'\r\n\r\n', 1)
            assert status in head.splitlines()[0]
            if status == b'200':
                assert json.loads(body)


def test_sdk_records_actual_dispatch_and_return_messages(tmp_path):
    from teamlab.agents import AgentTeam
    from teamlab.security import RunStopped
    import pytest
    source = tmp_path / 'input.csv'
    generate(source, rows=100)
    c = Controller(tmp_path / 'sdk', source, workers=1, mode='sdk-replay')
    team = AgentTeam(c, replay=True)
    team.run()
    events = all_events(c.store, c.run_id)
    messages = [e for e in events if e['kind'] == 'message.sent']
    assert [(e['agent_id'], e['detail']['to']) for e in messages] == [
        ('coordinator', 'worker-0'), ('worker-0', 'coordinator'),
        ('coordinator', 'verifier'), ('verifier', 'coordinator'),
    ]
    assert messages[0]['detail']['content'] == 'Analyze assigned shard 0.'
    assert len([e for e in events if e['kind'] == 'agent.completed']) == 2
    with pytest.raises(RunStopped):
        team.record_message(c.lead, 'worker-0', 'Late dispatch')
