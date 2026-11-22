import json
import threading
import time
from pathlib import Path

import pytest

from teamlab import attack_suite
from teamlab.attack_suite import run_scenario
from teamlab.cli import main
from teamlab.metrics import alert_metrics
from teamlab.store import Store
from teamlab.tabletop import DEFAULT_INCIDENTS, run_tabletop


@pytest.fixture(scope='module')
def drill(tmp_path_factory):
    return run_tabletop(tmp_path_factory.mktemp('tabletop'))


def test_five_incidents_run_in_separate_roots_with_distinct_runs(drill):
    incidents = drill['incidents']
    assert [i['id'] for i in incidents] == list(DEFAULT_INCIDENTS) and len(incidents) == 5
    assert len({i['root'] for i in incidents}) == 5 and len({i['run_id'] for i in incidents}) == 5
    for i in incidents:
        assert (Path(i['root']) / 'control.sqlite3').is_file()
        assert Store(Path(i['root'])).run(i['run_id'])['state'] == i['state']
    assert drill['elapsed_s'] > 0


def test_concurrent_outcomes_match_a_sequential_run(drill, tmp_path):
    for incident in drill['incidents']:
        alone = run_scenario(incident['id'], tmp_path / incident['id'])
        state = Store(tmp_path / incident['id'] / 'run').run(alone['run_id'])['state']
        assert (incident['state'], incident['containment']) == (state, alone['containment']), incident['id']


def test_without_acknowledgement_every_alert_is_triaged_and_open(drill):
    fleet = drill['fleet']
    assert fleet['alerts'] == sum(i['alerts'] for i in drill['incidents']) > 0
    assert fleet['triage_coverage'] == 1.0 and fleet['triaged'] == fleet['alerts']
    assert fleet['human_coverage'] == 0.0 and fleet['open_alerts'] == fleet['alerts']
    assert all(i['acknowledged'] == 0 and i['triaged'] == i['alerts'] for i in drill['incidents'])


def test_acknowledging_closes_every_alert_with_non_negative_dwell(tmp_path):
    drill = run_tabletop(tmp_path, acknowledge_after_s=0)
    fleet = drill['fleet']
    assert fleet['human_coverage'] == 1.0 and fleet['triage_coverage'] == 1.0 and fleet['open_alerts'] == 0
    assert fleet['acknowledged'] == fleet['alerts'] > 0 and fleet['dwell_max_s'] >= fleet['dwell_p50_s'] >= 0
    for incident in drill['incidents']:
        store = Store(Path(incident['root']))
        items = alert_metrics(store, incident['run_id'])['items']
        assert items and all(item['dwell_s'] >= 0 for item in items), incident['id']
        assert {a['acknowledged_by'] for a in store.alert_acks(incident['run_id']).values()} == {'tabletop'}


def test_incidents_run_concurrently(tmp_path, monkeypatch):
    # Every incident waits for all the others; a serialized drill would break the barrier.
    barrier = threading.Barrier(len(DEFAULT_INCIDENTS), timeout=20)

    def waiting(scenario):
        def run(root):
            barrier.wait()
            return scenario(root)
        return run

    monkeypatch.setattr(attack_suite, 'SCENARIOS', {k: waiting(v) for k, v in attack_suite.SCENARIOS.items()})
    assert len(run_tabletop(tmp_path)['incidents']) == 5


def test_scenario_clock_is_scoped_to_its_own_thread():
    clock = attack_suite._Clock(time.time() - 1000)
    inside, entered, release = [], threading.Event(), threading.Event()

    def scenario():
        with attack_suite._thread_clock(clock):
            inside.append(time.time())
            entered.set()
            release.wait(5)

    worker = threading.Thread(target=scenario)
    worker.start()
    entered.wait(5)
    outside = time.time()
    release.set()
    worker.join()
    assert inside == [clock()] and abs(outside - clock() - 1000) < 60
    assert time.time is attack_suite._real_time


def test_rejects_duplicate_or_empty_incidents(tmp_path):
    with pytest.raises(ValueError):
        run_tabletop(tmp_path, incidents=())
    with pytest.raises(ValueError):
        run_tabletop(tmp_path, incidents=('tool-flooding', 'tool-flooding'))


def test_cli_prints_the_drill(tmp_path, capsys):
    assert main(['tabletop', '--root', str(tmp_path), '--ack-after', '0']) == 0
    out = json.loads(capsys.readouterr().out)
    assert [i['id'] for i in out['incidents']] == list(DEFAULT_INCIDENTS)
    assert out['fleet']['human_coverage'] == 1.0
