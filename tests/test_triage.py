import json
from types import SimpleNamespace
from threading import Thread
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from teamlab.cli import main
from teamlab.controller import Controller
from teamlab.fixture import generate
from teamlab.security import RunStopped, SecurityError
from teamlab.triage import ALERT_KINDS, ModelTriage, RuleTriage, triage_run


@pytest.fixture
def controller(tmp_path):
    source = tmp_path / "source.csv"
    generate(source, rows=100, seed=3)
    return Controller(tmp_path / "run", source)


class FakeClient:
    def __init__(self, output=None, error=None):
        self.output, self.error, self.calls = output, error, []
        self.responses = SimpleNamespace(create=self.create)

    def create(self, **kwargs):
        self.calls.append(kwargs)
        if self.error is not None:
            raise self.error
        return SimpleNamespace(output_text=json.dumps(self.output))


def violate(controller):
    with pytest.raises(SecurityError):
        controller.gateway.call(controller.worker_tokens[0], 'fetch_url', {}, lambda db, who: None)


def kinds(controller, kind):
    return [e for e in controller.store.events(controller.run_id) if e['kind'] == kind]


def test_capability_violation_gets_true_positive_disposition(controller):
    violate(controller)
    before = controller.store.run(controller.run_id)
    out = triage_run(controller.store, controller.run_id, RuleTriage())
    assert out[0]['report'] == {'classification': 'likely_true_positive', 'recommended_action': 'keep_stopped', 'confidence': 'high'}
    assert out[0]['decision_owner'] == 'human'
    assert out[0]['triager'] == 'rule-triage-v1' and out[0]['alert_kind'] == 'run.stopped'
    assert out[0]['alert_seq'] in out[0]['evidence']
    assert set(out[0]['evidence']) <= set(out[0]['query']['events_examined'])
    after = controller.store.run(controller.run_id)
    assert (after['state'], after['epoch']) == (before['state'], before['epoch'])
    triaged = kinds(controller, 'alert.triaged')
    assert [(e['agent_id'], e['detail']) for e in triaged] == [('triage', {
        'alert_seq': out[0]['alert_seq'], 'classification': 'likely_true_positive',
        'recommended_action': 'keep_stopped', 'triager': 'rule-triage-v1'})]


def test_triage_is_idempotent(controller):
    violate(controller)
    assert len(triage_run(controller.store, controller.run_id, RuleTriage())) == 1
    assert triage_run(controller.store, controller.run_id, RuleTriage()) == []
    assert len(kinds(controller, 'alert.triaged')) == 1


def test_budget_pause_is_operational(tmp_path):
    source = tmp_path / "source.csv"
    generate(source, rows=100, seed=3)
    c = Controller(tmp_path / "run", source, tool_call_limit=1)
    c.claim(c.worker_tokens[0])
    with pytest.raises(RunStopped, match="budget"):
        c.claim(c.worker_tokens[1])
    d = triage_run(c.store, c.run_id, RuleTriage())[0]
    assert d['alert_kind'] == 'run.paused'
    assert (d['report']['classification'], d['report']['recommended_action']) == ('operational', 'raise_limits')


def test_rule_mapping_covers_known_reasons():
    rule = RuleTriage()

    def assess(kind, detail, agent='operator'):
        alert = {'seq': 5, 'kind': kind, 'agent_id': agent, 'detail': detail}
        context = [{'seq': 3, 'kind': 'action.authorized', 'agent_id': 'worker-1', 'detail': {}}, alert]
        r = rule.assess(alert, context)
        return r['classification'], r['recommended_action'], r['confidence'], r['evidence']

    tp = ('likely_true_positive', 'keep_stopped', 'high')
    assert assess('run.stopped', {'reason': 'request signature invalid: worker-1/claim_task'}) == (*tp, [5, 3])
    assert assess('run.stopped', {'reason': 'output-filter-v1: BLOCK on worker-1/post_note'})[:3] == tp
    assert assess('action.denied', {'verdicts': [{'monitor': 'output-filter-v1', 'verdict': 'BLOCK', 'kinds': ['aws_key']}]}, 'worker-1') == (*tp, [5, 3])
    assert assess('action.denied', {'verdicts': [{'monitor': 'deterministic-rules-v1', 'verdict': 'BLOCK'}]}, 'worker-1')[:3] == tp
    assert assess('run.stopped', {'reason': 'deterministic-rules-v1: BLOCK on worker-1/post_note'})[:3] == tp
    human = ('needs_human', 'escalate', 'medium')
    assert assess('run.paused', {'reason': 'monitor unavailable'})[:3] == human
    assert assess('action.denied', {'verdicts': [{'monitor': 'deterministic-rules-v1', 'verdict': 'ALLOW'}, {'monitor': 'luna-team-context-v1', 'verdict': 'PAUSE'}]}, 'worker-1')[:3] == human
    assert assess('run.paused', {'reason': 'luna-action-context-v1: PAUSE on worker-1/submit_result'})[:3] == human
    assert assess('run.paused', {'reason': 'inference budget'}, 'worker-1')[:3] == ('operational', 'raise_limits', 'high')
    assert assess('run.paused', {'reason': 'run deadline exceeded'})[:3] == ('operational', 'raise_limits', 'high')
    assert assess('run.stopped', {'reason': 'operator found a bad input'})[:3] == ('operational', 'restart_clean', 'low')
    assert assess('run.paused', {'reason': 'oversized action'})[:3] == ('needs_human', 'escalate', 'low')
    assert assess('credential.rejected', {'agent_id': 'worker-1', 'key_id': 'k', 'reason': 'refresh signature invalid'}, 'worker-1') == ('likely_true_positive', 'escalate', 'medium', [5, 3])
    assert ALERT_KINDS == {'action.denied', 'run.stopped', 'run.paused', 'credential.rejected'}


def test_model_triage_accepts_supported_evidence(controller):
    controller.store.stop(controller.run_id, 'operator found a bad input')
    seq = kinds(controller, 'run.stopped')[0]['seq']
    fake = FakeClient(output={'think': 'operator stop', 'classification': 'operational', 'recommended_action': 'restart_clean', 'confidence': 'medium', 'evidence': [seq]})
    d = triage_run(controller.store, controller.run_id, ModelTriage(fake))[0]
    assert d['triager'] == 'luna-triage-v1' and 'triage_error' not in d and 'model_report' not in d
    assert d['report']['confidence'] == 'medium' and d['evidence'] == [seq] and d['think'] == 'operator stop'


def test_model_triage_rejects_unsupported_evidence_and_falls_back(controller):
    fake = FakeClient(output={'think': 'x', 'classification': 'likely_false_positive', 'recommended_action': 'restart_clean', 'confidence': 'high', 'evidence': [99999]})
    violate(controller)
    d = triage_run(controller.store, controller.run_id, ModelTriage(fake))[0]
    assert d['triager'] == 'rule-triage-v1' and d['triage_error'] == 'unsupported evidence'
    assert d['report']['classification'] == 'likely_true_positive'
    assert kinds(controller, 'alert.triaged')[0]['detail']['triager'] == 'rule-triage-v1'


def test_model_triage_falls_back_when_the_call_raises(controller):
    violate(controller)
    d = triage_run(controller.store, controller.run_id, ModelTriage(FakeClient(error=TimeoutError('provider detail'))))[0]
    assert d['triager'] == 'rule-triage-v1' and d['triage_error'] == 'TimeoutError'


def test_model_triage_request_is_tool_free_and_strict(controller):
    violate(controller)
    fake = FakeClient(output={'think': 'x', 'classification': 'needs_human', 'recommended_action': 'escalate', 'confidence': 'low', 'evidence': []})
    triage_run(controller.store, controller.run_id, ModelTriage(fake))
    received = fake.calls[0]
    assert received['model'] == 'gpt-6-luna' and received['store'] is False
    assert received['max_output_tokens'] == 800 and received['reasoning'] == {'effort': 'low'}
    assert 'tools' not in received
    assert received['text']['format']['strict'] is True
    assert 'untrusted' in received['instructions'] and 'read-only' in received['instructions']
    schema = received['text']['format']['schema']
    assert set(schema['required']) == {'think', 'classification', 'recommended_action', 'confidence', 'evidence'}
    assert schema['additionalProperties'] is False


def test_attack_demo_reports_triage(tmp_path, capsys):
    assert main(['attack-demo', '--root', str(tmp_path / 'a')]) == 0
    assert json.loads(capsys.readouterr().out)['triage'][0]['classification'] == 'likely_true_positive'


def test_triage_subcommand_prints_dispositions(controller, capsys):
    violate(controller)
    args = ['triage', '--root', str(controller.root), '--run-id', controller.run_id]
    assert main(args) == 0
    out = json.loads(capsys.readouterr().out)
    assert out['triaged_alerts'] == 1 and out['dispositions'][0]['report']['classification'] == 'likely_true_positive'
    assert main(args) == 0
    assert json.loads(capsys.readouterr().out) == {'triaged_alerts': 0, 'dispositions': []}
    assert controller.store.run(controller.run_id)['state'] == 'STOPPED'


def test_triage_failure_does_not_mask_run_error(tmp_path, monkeypatch, capsys):
    import teamlab.triage

    class Boom(Exception):
        pass

    def fail_run(self):
        raise Boom('original failure')

    def fail_triage(*args, **kwargs):
        raise RuntimeError('triage broke')
    monkeypatch.setattr(Controller, 'run_scripted', fail_run)
    monkeypatch.setattr(teamlab.triage, 'triage_run', fail_triage)
    from teamlab.cli import execute, parser
    args = parser().parse_args(['run', '--root', str(tmp_path / 'r'), '--rows', '100'])
    with pytest.raises(Boom):
        execute(args)
    from teamlab.store import Store
    store = Store(tmp_path / 'r')
    with store.connect() as db:
        run_id = db.execute('SELECT id FROM runs').fetchone()['id']
    failed = [e for e in store.events(run_id) if e['kind'] == 'triage.failed']
    assert [e['detail'] for e in failed] == [{'error': 'RuntimeError'}]


def test_execute_triages_a_paused_run(tmp_path, monkeypatch, capsys):
    def fail_run(self):
        raise KeyboardInterrupt
    monkeypatch.setattr(Controller, 'run_scripted', fail_run)
    from teamlab.cli import execute, parser
    with pytest.raises(KeyboardInterrupt):
        execute(parser().parse_args(['run', '--root', str(tmp_path / 'r'), '--rows', '100']))
    assert {'triaged_alerts': 1} in [json.loads(line) for line in capsys.readouterr().out.splitlines()]


def test_monitor_api_serves_triage(controller):
    from teamlab.monitoring import server_for
    violate(controller)
    triage_run(controller.store, controller.run_id, RuleTriage())
    try:
        server = server_for(controller.store, "x" * 32, port=0)
    except OSError as exc:
        pytest.skip(f"loopback socket unavailable in this execution environment: {exc}")
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_port}/runs/{controller.run_id}/triage"
    try:
        with pytest.raises(HTTPError) as denied:
            urlopen(url, timeout=2)
        assert denied.value.code == 403
        with urlopen(Request(url, headers={"Authorization": "Bearer " + "x" * 32}), timeout=2) as response:
            payload = json.load(response)
        assert [d['report']['classification'] for d in payload['dispositions']] == ['likely_true_positive']
    finally:
        server.shutdown()
        server.server_close()


def test_execute_triages_a_completed_runs_alerts(tmp_path, monkeypatch, capsys):
    from teamlab.store import Store
    original = Controller.run_scripted

    def run_with_rejection(self):
        with self.store.transaction() as db:
            self.store.event(db, self.run_id, 'worker-0', 'credential.rejected',
                {'agent_id': 'worker-0', 'key_id': 'k', 'reason': 'refresh signature invalid'})
        return original(self)
    monkeypatch.setattr(Controller, 'run_scripted', run_with_rejection)
    assert main(['run', '--root', str(tmp_path / 'r'), '--rows', '100']) == 0
    lines = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert lines[-1]['state'] == 'COMPLETED'
    assert {'triaged_alerts': 1} in lines
    triaged = [e['detail'] for e in Store(tmp_path / 'r').events(lines[-1]['run_id']) if e['kind'] == 'alert.triaged']
    assert [(d['classification'], d['recommended_action']) for d in triaged] == [('likely_true_positive', 'escalate')]


def test_model_triage_cannot_downgrade_a_deterministic_block(controller):
    violate(controller)
    seq = kinds(controller, 'run.stopped')[0]['seq']
    fake = FakeClient(output={'think': 'looks benign', 'classification': 'likely_false_positive',
        'recommended_action': 'restart_clean', 'confidence': 'high', 'evidence': [seq]})
    d = triage_run(controller.store, controller.run_id, ModelTriage(fake))[0]
    assert d['report'] == {'classification': 'likely_true_positive', 'recommended_action': 'keep_stopped', 'confidence': 'high'}
    assert 'triage_error' not in d and len(fake.calls) == 1
    assert d['model_report'] == {'think': 'looks benign', 'classification': 'likely_false_positive',
        'recommended_action': 'restart_clean', 'confidence': 'high', 'evidence': [seq]}
    assert kinds(controller, 'alert.triaged')[0]['detail']['classification'] == 'likely_true_positive'
