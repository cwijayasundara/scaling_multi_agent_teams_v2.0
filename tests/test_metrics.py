import json
from threading import Thread
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from teamlab.cli import main, validate_bundle
from teamlab.controller import Controller
from teamlab.fixture import generate
from teamlab.metrics import SLO_SECONDS, acknowledge, alert_metrics, fleet_metrics
from teamlab.security import SecurityError
from teamlab.triage import ALERT_KINDS, RuleTriage, triage_run


@pytest.fixture
def controller(tmp_path):
    source = tmp_path / 'source.csv'
    generate(source, rows=100, seed=3)
    return Controller(tmp_path / 'run', source)


def violate(c):
    with pytest.raises(SecurityError):
        c.gateway.call(c.worker_tokens[0], 'fetch_url', {}, lambda db, who: None)


def alerts(c):
    return [e for e in c.store.events(c.run_id) if e['kind'] in ALERT_KINDS]


def ack_events(c):
    return [e for e in c.store.events(c.run_id) if e['kind'] == 'alert.acknowledged']


def test_no_alerts_reports_null_coverage(controller):
    controller.run_scripted()
    m = alert_metrics(controller.store, controller.run_id)
    assert (m['alerts'], m['triage_coverage'], m['human_coverage'], m['dwell_p50_s']) == (0, None, None, None)
    assert m['slo_seconds'] == SLO_SECONDS == 3600 and m['items'] == [] and m['open_alerts'] == 0


def test_triaged_and_acknowledged_alert_metrics(controller, clock):
    violate(controller)
    triage_run(controller.store, controller.run_id, RuleTriage())
    first = alerts(controller)[0]
    clock.advance(120)
    acknowledge(controller.store, controller.run_id, first['seq'], by='tester')
    m = alert_metrics(controller.store, controller.run_id)
    assert m['triage_coverage'] == 1.0 and 0 < m['human_coverage'] <= 1.0
    assert m['alerts'] == len(alerts(controller)) and m['acknowledged'] == 1 and m['open_alerts'] == m['alerts'] - 1
    item = next(i for i in m['items'] if i['alert_seq'] == first['seq'])
    assert 119 <= item['dwell_s'] <= 121 and item['triaged_at'] is not None and item['triage_latency_s'] is not None
    assert m['dwell_measured_from'] == 'alert detection'
    assert ack_events(controller)[0]['detail']['acknowledged_by'] == 'tester'


def test_open_alert_past_an_hour_breaches_slo(controller, clock):
    violate(controller)
    clock.advance(3601, past_deadline=True)
    m = alert_metrics(controller.store, controller.run_id)
    assert m['slo_breaches'] >= 1 and m['oldest_open_age_s'] > 3600
    assert all(i['dwell_s'] is None for i in m['items'])


@pytest.mark.parametrize('case,message', [('missing seq', 'unknown alert'), ('non-alert event', 'not an alert'),
                                          ('other run seq', 'unknown alert'), ('twice', 'already acknowledged')])
def test_acknowledge_refuses_wrong_targets(controller, tmp_path, case, message):
    violate(controller)
    other = Controller(tmp_path / 'run', tmp_path / 'source.csv')
    other_seq = max(e['seq'] for e in other.store.events(other.run_id))
    target = {'missing seq': 10 ** 6, 'other run seq': other_seq,
              'non-alert event': next(e['seq'] for e in controller.store.events(controller.run_id) if e['kind'] not in ALERT_KINDS),
              'twice': alerts(controller)[0]['seq']}[case]
    if case == 'twice':
        acknowledge(controller.store, controller.run_id, target, by='a')
    before = len(ack_events(controller))
    with pytest.raises(ValueError) as refused:
        acknowledge(controller.store, controller.run_id, target, by='b')
    assert str(refused.value) == message
    assert len(ack_events(controller)) == before


def test_ack_note_is_redacted(controller):
    violate(controller)
    seq = alerts(controller)[0]['seq']
    result = acknowledge(controller.store, controller.run_id, seq, by='t', note='call ops@example.com ' + 'x' * 600)
    assert '[REDACTED:email]' in result['note'] and 'ops@example.com' not in result['note'] and len(result['note']) <= 500
    event = ack_events(controller)[0]
    assert 'ops@example.com' not in json.dumps(event['detail'])
    with controller.store.connect() as db:
        stored = db.execute('SELECT note FROM alert_acks').fetchone()['note']
    assert stored == result['note']


def test_ack_and_metrics_cli(controller, capsys, tmp_path):
    violate(controller)
    root = str(controller.store.root)
    assert main(['ack', '--root', root, '--run-id', controller.run_id, '--all-open', '--note', 'seen']) == 0
    assert sorted(json.loads(capsys.readouterr().out)['acknowledged']) == [e['seq'] for e in alerts(controller)]
    assert main(['ack', '--root', root, '--run-id', controller.run_id, '--alert-seq', str(alerts(controller)[0]['seq'])]) == 1
    assert 'already acknowledged' in capsys.readouterr().err
    assert main(['metrics', '--root', root, '--run-id', controller.run_id]) == 0
    m = json.loads(capsys.readouterr().out)
    assert m['acknowledged'] == m['alerts'] == len(alerts(controller)) >= 1
    assert main(['metrics', '--root', root]) == 0
    assert json.loads(capsys.readouterr().out)['runs'][0]['run_id'] == controller.run_id
    missing = tmp_path / 'typo'
    assert main(['ack', '--root', str(missing), '--run-id', 'x', '--all-open']) == 1
    assert main(['metrics', '--root', str(missing)]) == 1
    assert 'not found' in capsys.readouterr().err and not missing.exists()


def test_metrics_api_routes_are_read_only(controller):
    from teamlab.monitoring import server_for
    violate(controller)
    try:
        server = server_for(controller.store, 'x' * 32, port=0)
    except OSError as exc:
        pytest.skip(f'loopback socket unavailable in this execution environment: {exc}')
    Thread(target=server.serve_forever, daemon=True).start()
    base = f'http://127.0.0.1:{server.server_port}'
    auth = {'Authorization': 'Bearer ' + 'x' * 32}
    try:
        for path in ('/metrics', f'/runs/{controller.run_id}/metrics'):
            with pytest.raises(HTTPError) as denied:
                urlopen(base + path, timeout=2)
            assert denied.value.code == 403
            with urlopen(Request(base + path, headers=auth), timeout=2) as response:
                payload = json.load(response)
            assert payload['alerts'] == len(alerts(controller))
            with pytest.raises(HTTPError) as post:
                urlopen(Request(base + path, data=b'{}', method='POST', headers=auth), timeout=2)
            assert post.value.code == 501
    finally:
        server.shutdown()
        server.server_close()


def test_fleet_metrics_sums_runs(tmp_path):
    source = tmp_path / 'source.csv'
    generate(source, rows=100, seed=3)
    first = Controller(tmp_path / 'run', source)
    violate(first)
    second = Controller(tmp_path / 'run', source)
    violate(second)
    acknowledge(second.store, second.run_id, alerts(second)[0]['seq'], by='t')
    m = fleet_metrics(first.store)
    total = len(alerts(first)) + len(alerts(second))
    assert m['alerts'] == total >= 2 and m['acknowledged'] == 1 and m['open_alerts'] == total - 1
    assert {r['run_id'] for r in m['runs']} == {first.run_id, second.run_id}
    assert m['human_coverage'] == 1 / total


def test_bundle_has_alert_metrics(controller):
    out = controller.run_scripted()
    manifest = json.loads((out / 'manifest.json').read_text())
    assert 'alert_metrics.json' in manifest and 'metrics.json' in manifest
    assert json.loads((out / 'alert_metrics.json').read_text())['run_id'] == controller.run_id
    assert validate_bundle(out)['passed']


def test_ack_falls_back_when_os_user_is_unknown(controller, capsys, monkeypatch):
    import getpass

    def boom():
        raise OSError('no user')
    monkeypatch.setattr(getpass, 'getuser', boom)
    violate(controller)
    assert main(['ack', '--root', str(controller.store.root), '--run-id', controller.run_id, '--all-open']) == 0
    assert json.loads(capsys.readouterr().out)['acknowledged_by'] == 'unknown'
