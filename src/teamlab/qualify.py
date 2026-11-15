"""Live qualification of the OpenShell microVM execution boundary on this host.

Runs real guests through OpenShellBroker and records each check. `qualified`
is true only when every check passes. It covers selected properties of this
host and gateway; it is not a production audit.
"""
import json
import platform
import subprocess
import time
from pathlib import Path
from types import SimpleNamespace

from .execution import DEADLINE_SECONDS, EXPECTED_GUEST_KERNEL, OPENSHELL_VERSION, OpenShellBroker
from .security import SecurityError

PROBE = '''import ipaddress, json, os, socket, uuid
out = {'uid': os.getuid(), 'kernel': os.uname().release}
try:
    open('/etc/teamlab-probe', 'w').write('x'); out['etc_writable'] = True
except OSError:
    out['etc_writable'] = False
for key, target in (('egress_ip', ('1.1.1.1', 443)), ('egress_private', ('198.18.0.1', 9))):
    try:
        socket.create_connection(target, timeout=2).close(); out[key] = True
    except OSError:
        out[key] = False
# OpenShell answers every name locally with a 198.18.0.0/15 placeholder; a real
# upstream lookup would return public addresses or NXDOMAIN for the random name.
answers = []
for host in ('example.com', 'tl-' + uuid.uuid4().hex + '.example.com'):
    try:
        answers += [a[4][0] for a in socket.getaddrinfo(host, 443, socket.AF_INET)]
    except OSError:
        pass
out['dns_answers'] = sorted(set(answers))
out['dns_upstream'] = any(not ipaddress.ip_address(a) in ipaddress.ip_network('198.18.0.0/15') for a in answers)
for address in answers:
    try:
        socket.create_connection((address, 443), timeout=2).close(); out['egress_placeholder'] = True
    except OSError:
        out.setdefault('egress_placeholder', False)
try:
    out['interfaces'] = sorted(os.listdir('/sys/class/net'))
except OSError:
    out['interfaces'] = 'unreadable'
print(json.dumps(out))
'''


class _Gateway:
    """Stands in for the run gateway: always active, fixed identity."""
    def active(self, token):
        return SimpleNamespace(run_id='qualify', agent_id='qualify', epoch=0)


def _check(checks, name, fn):
    started = time.monotonic()
    try:
        detail = fn()
        checks.append({'name': name, 'passed': True, 'detail': detail, 'seconds': round(time.monotonic()-started, 2)})
    except Exception as exc:
        checks.append({'name': name, 'passed': False, 'detail': f'{type(exc).__name__}: {exc}', 'seconds': round(time.monotonic()-started, 2)})


def host_report(broker=None):
    broker = broker or OpenShellBroker()
    gateway, checks = _Gateway(), []
    _check(checks, 'gateway_connected_at_pinned_version', broker.preflight)

    def isolation():
        result = broker.execute(gateway, 'qualify', PROBE, [])
        bad = [k for k in ('etc_writable', 'egress_ip', 'egress_private', 'dns_upstream', 'egress_placeholder') if result.get(k)]
        if result.get('uid') == 0 or bad:
            raise SecurityError(f'boundary property failed: uid={result.get("uid")} open={bad}')
        return result
    _check(checks, 'guest_unprivileged_readonly_offline', isolation)

    def runaway():
        started = time.monotonic()
        try:
            broker.execute(gateway, 'qualify', 'while True: pass', [])
        except SecurityError:
            elapsed = time.monotonic()-started
            if elapsed >= DEADLINE_SECONDS + 5:
                raise SecurityError(f'runaway calculation took {elapsed:.1f}s')
            return {'terminated_after_seconds': round(elapsed, 1)}
        raise SecurityError('infinite calculation returned a result')
    _check(checks, 'runaway_calculation_terminates', runaway)

    def cleanup():
        for _ in range(30):
            listing = subprocess.run([broker.cli, 'sandbox', 'list', '-g', broker.gateway], capture_output=True, text=True, timeout=10)
            leftover = [line.split()[0] for line in listing.stdout.splitlines() if line.startswith('tl-')]
            if not leftover:
                return {'leftover_sandboxes': 0}
            time.sleep(1)
        raise SecurityError(f'sandboxes left after execution: {leftover}')
    _check(checks, 'no_leftover_sandboxes', cleanup)

    return {
        'platform': platform.system(),
        'machine': platform.machine(),
        'profile': OpenShellBroker.profile,
        'openshell_version': OPENSHELL_VERSION,
        'expected_guest_kernel': EXPECTED_GUEST_KERNEL,
        'image': broker.image,
        'checks': checks,
        'qualified': all(c['passed'] for c in checks),
        'scope': 'Selected boundary properties of this host and gateway. Not a production audit; '
                 're-run after any OpenShell, image or host change.',
        'recorded_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
    }


def write_host_report(path: Path, broker=None):
    report = host_report(broker)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2) + '\n')
    return report
