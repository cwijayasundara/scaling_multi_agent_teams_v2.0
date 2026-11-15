"""Opt-in real-guest tests against a local OpenShell gateway on the vm driver.

Run with TEAMLAB_TEST_OPENSHELL=1 after following infra/README.md. Never
replace these with the protocol double.
"""
import json
import os
import time
from concurrent.futures import ThreadPoolExecutor

import pytest
from teamlab.controller import Controller
from teamlab.execution import DEADLINE_SECONDS, OpenShellBroker
from teamlab.fixture import generate
from teamlab.qualify import PROBE
from teamlab.security import RunStopped, SecurityError

pytestmark = pytest.mark.skipif(not os.environ.get('TEAMLAB_TEST_OPENSHELL'), reason='Requires a local OpenShell gateway on the vm driver')


@pytest.fixture
def runtime(tmp_path):
    source = tmp_path/'input.csv'; generate(source, 20)
    broker = OpenShellBroker(gateway=os.environ.get('TEAMLAB_TEST_OPENSHELL_GATEWAY', 'openshell'))
    broker.preflight()
    return Controller(tmp_path/'run', source), broker


def test_guest_is_unprivileged_readonly_and_offline(runtime):
    c, b = runtime
    result = b.execute(c.gateway, c.worker_tokens[0], PROBE, [])
    assert result['uid'] == 1000 and not result['etc_writable']
    assert not result['egress_ip'] and not result['egress_private']
    assert not result['dns_upstream'] and not result['egress_placeholder']


def test_records_reach_the_calculation(runtime):
    c, b = runtime
    source = "import json,sys\nprint(json.dumps({'n': len(json.load(sys.stdin)['records'])}))"
    assert b.execute(c.gateway, c.worker_tokens[0], source, [{'a': 1}, {'a': 2}]) == {'n': 2}


def test_infinite_calculation_terminates(runtime):
    c, b = runtime; started = time.monotonic()
    with pytest.raises(SecurityError):
        b.execute(c.gateway, c.worker_tokens[0], 'while True: pass', [])
    assert time.monotonic()-started < DEADLINE_SECONDS + 5


def test_operator_stop_cancels_inflight_guest(runtime):
    c, b = runtime
    with ThreadPoolExecutor(1) as pool:
        pending = pool.submit(b.execute, c.gateway, c.worker_tokens[0], 'while True: pass', [])
        time.sleep(4); started = time.monotonic(); c.store.stop(c.run_id, 'Boundary cancellation test')
        with pytest.raises(RunStopped):
            pending.result(timeout=3)
        assert time.monotonic()-started < 3
