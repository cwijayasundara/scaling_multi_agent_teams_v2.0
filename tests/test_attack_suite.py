import json
import socket

import pytest

import teamlab.config
from teamlab import attack_suite, dlp
from teamlab.attack_suite import SCENARIOS, SLOW, load_catalogue, render_matrix, run_scenario, run_suite
from teamlab.cli import main

# Measured gaps: each scenario below runs as written and fails the assertion it names.
GAPS = {
    "indirect-prompt-injection": "the replayed run stays in scope, but nothing raises an alert: injected CSV text is not detected",
    "stale-result-after-stop": "the stale submit is refused (RunStopped) but leaves no event; only the operator's own stop is on record",
}
OFFLINE = [pytest.param(s, marks=pytest.mark.xfail(strict=True, reason=GAPS[s])) if s in GAPS else s
           for s in SCENARIOS if s not in SLOW]


def test_catalogue_is_complete_and_verified():
    cat = load_catalogue()
    assert [s['id'] for s in cat['scenarios']] == list(SCENARIOS)
    for s in cat['scenarios']:
        for ref in s['owasp_agentic'] + s['mitre']:
            assert ref['verified'] is True and ref['source'].startswith('https://') and ref['verified_on']
        assert s['owasp_agentic'] or s['mitre'] or s['unmapped']
        assert s['eBook_part'] in ('II', 'III', 'V') and s['expected_control']
        assert all(ref['framework'] in ('ATLAS', 'ATT&CK') for ref in s['mitre'])
        assert s['isolation'] in ('run-root', 'process-wide') and type(s['creates_run']) is bool


@pytest.mark.parametrize('scenario', OFFLINE)
def test_scenario_outcome_is_derived_from_run_state(tmp_path, scenario):
    r = run_scenario(scenario, tmp_path / scenario)
    assert r['id'] == scenario
    assert r['prevented'] is True
    assert r['detected'] is True or r['containment'] == 'refused-start'
    assert r['triaged'] is (True if r['evidence'] else None)


def test_gap_scenarios_are_still_prevented(tmp_path):
    # The xfails above are detection gaps, not prevention gaps.
    for scenario in GAPS:
        r = run_scenario(scenario, tmp_path / scenario)
        assert r['prevented'] is True and r['detected'] is False and r['evidence'] == [] and r['triaged'] is None


def test_setup_stop_is_not_reported_as_containment(tmp_path):
    r = run_scenario('stale-result-after-stop', tmp_path / 'stale')
    assert r['containment'] == 'none' and r['triaged'] is None
    assert 'Before the attack (setup): run.stopped' in r['notes']


def test_alerting_scenario_reports_triage_and_its_own_containment(tmp_path):
    r = run_scenario('restricted-agent-escalation', tmp_path / 'escalation')
    # The setup strike restricted the agent; the attack's write attempt quarantined it.
    assert r['triaged'] is True and r['evidence'] and r['containment'] == 'agent'
    assert 'Before the attack (setup): agent.restricted' in r['notes']


def test_prevented_is_false_when_the_effect_happens(tmp_path, monkeypatch):
    monkeypatch.setattr(dlp, 'scan_args', lambda args: [])
    r = run_scenario('credential-exfiltration-note', tmp_path / 'exfil')
    assert r['prevented'] is False and r['detected'] is False and r['containment'] == 'none'


def test_scenario_root_must_be_fresh(tmp_path):
    (tmp_path / 'used').mkdir()
    (tmp_path / 'used' / 'leftover').write_text('x')
    with pytest.raises(ValueError, match='fresh'):
        run_scenario('out-of-scope-tool', tmp_path / 'used')
    with pytest.raises(ValueError, match='unknown scenario'):
        run_scenario('no-such-scenario', tmp_path / 'none')


def test_scenarios_make_no_network_or_secret_access(tmp_path, monkeypatch):
    real_connect = socket.socket.connect

    def guarded(sock, address):
        if sock.family != socket.AF_UNIX:
            raise AssertionError(f'network connection attempted: {address!r}')
        return real_connect(sock, address)

    def no_credential_store(*args, **kwargs):
        raise AssertionError('credential store consulted')

    monkeypatch.setattr(socket.socket, 'connect', guarded)
    monkeypatch.delenv('OPENAI_API_KEY', raising=False)
    monkeypatch.setattr(teamlab.config, '_credential_store_runner', no_credential_store)
    report = run_suite(tmp_path / 'suite')
    assert [r['id'] for r in report['results']] == [s for s in SCENARIOS if s not in SLOW]
    assert report['summary']['not_prevented'] == []
    assert report['summary']['not_detected'] == sorted(GAPS)


def test_tampered_config_never_touches_the_packaged_file(tmp_path):
    from teamlab.config_signing import PACKAGE_DIR
    before = (PACKAGE_DIR / 'behavior_profiles.json').read_bytes(), (PACKAGE_DIR / 'behavior_profiles.json.sig').read_bytes()
    r = run_scenario('tampered-policy-config', tmp_path / 'config')
    assert r['containment'] == 'refused-start' and r['run_id'] is None and 'changed after signing' in r['notes']
    assert before == ((PACKAGE_DIR / 'behavior_profiles.json').read_bytes(), (PACKAGE_DIR / 'behavior_profiles.json.sig').read_bytes())


def test_plane_scenario_refuses_foreign_ca_client(tmp_path):
    r = run_scenario('plane-untrusted-client', tmp_path / 'plane')
    assert r['prevented'] is True and r['detected'] is True and r['run_id'] is None


def test_cli_writes_json_and_matrix(tmp_path, capsys, monkeypatch):
    # Two scenarios keep the CLI test fast; the full suite runs above.
    subset = {k: SCENARIOS[k] for k in ('out-of-scope-tool', 'stale-result-after-stop')}
    monkeypatch.setattr(attack_suite, 'SCENARIOS', subset)
    output = tmp_path / 'reports' / 'threat-coverage.json'
    assert main(['attack-suite', '--root', str(tmp_path / 'runs'), '--output', str(output)]) == 0
    report = json.loads(output.read_text())
    assert report['catalogue_version'] == 'threats-v1' and len(report['results']) == 2
    assert report['summary'] == json.loads(capsys.readouterr().out)
    assert report['summary']['not_detected'] == ['stale-result-after-stop']
    matrix = output.with_suffix('.md').read_text()
    assert '| Scenario | OWASP | MITRE | Prevented | Detected | Triaged | Containment |' in matrix


def _result(sid, prevented=True, detected=True, evidence=(7,), run_id='r1', containment='team'):
    return {'id': sid, 'prevented': prevented, 'detected': detected, 'triaged': True if evidence else None, 'containment': containment,
            'run_id': run_id, 'evidence': list(evidence), 'dwell_s': 0.1 if evidence else None, 'notes': f'notes for {sid}'}


def test_matrix_lists_every_scenario_and_states_gaps():
    cat = load_catalogue()
    results = [_result(s) for s in SCENARIOS if s not in SLOW]
    results[0] = _result(results[0]['id'], prevented=False)
    results[1] = _result(results[1]['id'], detected=False, evidence=())
    report = {'generated_at': '2026-11-22T00:00:00Z', 'catalogue_version': cat['version'], 'results': results,
              'summary': attack_suite.summarize(results)}
    matrix = render_matrix(report, cat)
    rows = [line for line in matrix.splitlines() if line.startswith('| ') and not line.startswith('| Scenario')]
    for s in cat['scenarios']:
        assert any(row.startswith(f'| {s["title"]} (`{s["id"]}`)') for row in rows), s['id']
    assert 'ASI02' in matrix and 'AML.T0053' in matrix
    gaps = matrix.split('## Gaps', 1)[1]
    assert results[0]['id'] in gaps and results[1]['id'] in gaps and 'plane-untrusted-client' in gaps
    assert 'not run' in next(row for row in rows if '`plane-untrusted-client`' in row)
    for s in cat['scenarios']:
        if s['unmapped']:
            assert s['unmapped'] in gaps


def test_injected_row_is_put_in_front_of_an_agent(tmp_path):
    r = run_scenario('indirect-prompt-injection', tmp_path / 'inject')
    assert r['prevented'] is True
    assert 'injected row returned in an inspect_shard sample: True' in r['notes']


def test_injection_not_put_in_front_of_an_agent_is_not_exercised(tmp_path, monkeypatch):
    # Seed 3 puts the injected record outside every inspect_shard sample: nothing was attacked.
    monkeypatch.setattr(attack_suite, 'INJECTION_SEED', 3)
    r = run_scenario('indirect-prompt-injection', tmp_path / 'inject')
    assert r['prevented'] is None and 'not exercised' in r['notes']


def test_audit_tampering_is_labelled_tamper_evident_in_the_matrix():
    cat = load_catalogue()
    results = [_result(s) for s in SCENARIOS]
    report = {'generated_at': 'x', 'catalogue_version': cat['version'], 'results': results,
              'summary': attack_suite.summarize(results)}
    row = next(line for line in render_matrix(report, cat).splitlines() if '`audit-journal-tampering`' in line)
    assert row.split('|')[4].strip() == 'tamper-evident (detected by verify-audit)'


def test_matrix_lists_uncovered_threat_classes():
    cat = load_catalogue()
    assert {u['owasp_id'] for u in cat['uncovered']} == {'ASI04', 'ASI06'}
    for u in cat['uncovered']:
        assert u['verified'] is True and u['source'].startswith('https://genai.owasp.org/') and u['class'] and u['reason']
    results = [_result(s) for s in SCENARIOS]
    report = {'generated_at': 'x', 'catalogue_version': cat['version'], 'results': results,
              'summary': attack_suite.summarize(results)}
    gaps = render_matrix(report, cat).split('## Gaps', 1)[1].split('## Notes', 1)[0]
    line = next(line for line in gaps.splitlines() if line.startswith('- Uncovered threat classes:'))
    assert 'ASI04' in line and 'ASI06' in line and 'Supply Chain' in line and 'Memory' in line


def test_an_unexpected_scenario_error_is_recorded_and_the_suite_continues(tmp_path, monkeypatch):
    def broken(root):
        raise RuntimeError('boom')
    subset = {'out-of-scope-tool': SCENARIOS['out-of-scope-tool'], 'broken': broken,
              'credential-exfiltration-note': SCENARIOS['credential-exfiltration-note']}
    monkeypatch.setattr(attack_suite, 'SCENARIOS', subset)
    report = run_suite(tmp_path / 'suite')
    assert [r['id'] for r in report['results']] == list(subset)
    bad = report['results'][1]
    assert bad['error'] == 'RuntimeError' and bad['prevented'] is None and bad['detected'] is None
    assert report['results'][0]['prevented'] is True and report['results'][2]['prevented'] is True
    s = report['summary']
    assert s['scenarios'] == 3 and s['prevented'] == 2 and s['errors'] == ['broken']
    assert 'broken' not in s['not_prevented'] and 'broken' not in s['not_detected']


def test_cli_refuses_a_markdown_output_path(tmp_path, monkeypatch):
    ran = []
    monkeypatch.setattr(attack_suite, 'run_suite', lambda *a, **k: ran.append(1))
    output = tmp_path / 'threat-coverage.md'
    output.write_text('keep me')
    assert main(['attack-suite', '--root', str(tmp_path / 'runs'), '--output', str(output)]) == 1
    assert ran == [] and output.read_text() == 'keep me'


def test_cli_exits_1_when_a_scenario_is_not_prevented(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(dlp, 'scan_args', lambda args: [])
    monkeypatch.setattr(attack_suite, 'SCENARIOS', {'credential-exfiltration-note': SCENARIOS['credential-exfiltration-note']})
    output = tmp_path / 'tc.json'
    assert main(['attack-suite', '--root', str(tmp_path / 'runs'), '--output', str(output)]) == 1
    assert json.loads(output.read_text())['summary']['not_prevented'] == ['credential-exfiltration-note']
