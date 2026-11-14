"""Opt-in real guest tests. Never replace these with the protocol double."""
import os
from pathlib import Path
import time

import pytest
from teamlab.controller import Controller
from teamlab.execution import UnixBroker
from teamlab.fixture import generate
from teamlab.security import SecurityError,RunStopped

pytestmark=pytest.mark.skipif(not os.environ.get('TEAMLAB_TEST_BROKER_SOCKET'),reason='Requires separately provisioned Linux/KVM broker')

@pytest.fixture
def runtime(tmp_path):
    source=tmp_path/'input.csv';generate(source,20)
    c=Controller(tmp_path/'run',source)
    return c,UnixBroker(os.environ['TEAMLAB_TEST_BROKER_SOCKET'])


def test_guest_is_unprivileged_readonly_and_has_no_network_interface(runtime):
    c,b=runtime
    source='''import os,json,socket
try:
 open('/root/teamlab-probe','w').write('probe')
 readonly=False
except OSError:
 readonly=True
s=socket.socket();s.settimeout(.5)
try:
 s.connect(('198.18.0.1',9));network=True
except OSError:
 network=False
print(json.dumps({'uid':os.getuid(),'readonly':readonly,'interfaces':os.listdir('/sys/class/net'),'network':network}))
'''
    result=b.execute(c.gateway,c.worker_tokens[0],source,[])
    assert result['uid']==1000 and result['readonly'] and not result['network']
    assert set(result['interfaces'])<={'lo'}


def test_infinite_calculation_terminates(runtime):
    c,b=runtime;started=time.monotonic()
    with pytest.raises(SecurityError):b.execute(c.gateway,c.worker_tokens[0],'while True: pass',[])
    assert time.monotonic()-started<45


def test_operator_stop_cancels_inflight_guest(runtime):
    from concurrent.futures import ThreadPoolExecutor
    c,b=runtime
    with ThreadPoolExecutor(1) as pool:
        pending=pool.submit(b.execute,c.gateway,c.worker_tokens[0],'while True: pass',[])
        time.sleep(1);started=time.monotonic();c.store.stop(c.run_id,'Boundary cancellation test')
        with pytest.raises(RunStopped):pending.result(timeout=3)
        assert time.monotonic()-started<3
