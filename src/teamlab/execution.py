"""Authored-code execution in disposable OpenShell microVM sandboxes.

Each execution (and each verification rerun) gets a fresh OpenShell sandbox
created on a gateway whose compute driver is ``vm`` (libkrun on
Hypervisor.framework or KVM). The sandbox has no network interface, a deny-all
network policy, a hard Landlock requirement, and is deleted afterwards. The
runtime process never evaluates model source itself; it only drives the
``openshell`` CLI with a scrubbed environment. See infra/README.md.
"""
import json
import os
import shutil
import subprocess
import tempfile
import threading
import time
import uuid

from .security import SecurityError

# Pinned together: a gateway upgrade must re-run `teamlab qualify-host`.
OPENSHELL_VERSION = '0.1.8'
EXPECTED_GUEST_KERNEL = '6.12.109'
DEFAULT_IMAGE = ('docker.io/library/python:3.12-slim@sha256:'
                 '5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b')
MAX_PAYLOAD = 32 * 1024 * 1024
MAX_OUTPUT = 16 * 1024 * 1024
BOOT_SECONDS = 30
EXEC_SECONDS = 30
DEADLINE_SECONDS = 45
SCRUBBED_ENV = ('OPENAI_API_KEY', 'TEAMLAB_DATABASE_URL', 'AWS_ACCESS_KEY_ID',
                'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN')

# No network_policies: OpenShell denies all egress. hard_requirement makes the
# sandbox fail to start rather than run without Landlock.
POLICY = """version: 1
filesystem_policy:
  include_workdir: false
  read_only: [/bin, /usr, /lib, /etc, /proc, /dev/urandom]
  read_write: [/tmp, /dev/null]
landlock:
  compatibility: hard_requirement
"""

# Runs inside the guest as the unprivileged sandbox user. One request per VM.
RUNNER = r'''
import ctypes, json, os, resource, signal, subprocess, sys, tempfile
MAX_OUTPUT = 16*1024*1024
def restrict():
    ctypes.CDLL(None).prctl(38, 1, 0, 0, 0)  # PR_SET_NO_NEW_PRIVS
    for kind, limit in ((resource.RLIMIT_CPU, 20), (resource.RLIMIT_AS, 512*1024*1024),
            (resource.RLIMIT_FSIZE, MAX_OUTPUT), (resource.RLIMIT_NPROC, 64),
            (resource.RLIMIT_NOFILE, 32), (resource.RLIMIT_CORE, 0)):
        resource.setrlimit(kind, (limit, limit))
result = {'ok': False, 'reason': 'guest execution failed', 'kernel': os.uname().release}
try:
    request = json.loads(sys.stdin.buffer.read())
    if len(request['source'].encode()) > 64000:
        raise ValueError('source too large')
    with tempfile.TemporaryDirectory(dir='/tmp') as directory:
        source = os.path.join(directory, 'calculation.py')
        with open(source, 'w') as stream:
            stream.write(request['source'])
        os.chmod(source, 0o444)
        with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
            proc = subprocess.Popen([sys.executable, '-I', source], cwd=directory,
                env={'PATH': '/usr/local/bin:/usr/bin:/bin', 'PYTHONDONTWRITEBYTECODE': '1'},
                stdin=subprocess.PIPE, stdout=out, stderr=err, preexec_fn=restrict, start_new_session=True)
            try:
                proc.communicate(json.dumps({'records': request['records']}).encode(), timeout=25)
            finally:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except OSError:  # exited group: ESRCH, or EPERM under OpenShell seccomp
                    pass
                proc.wait()
            if proc.returncode != 0:
                raise ValueError('calculation failed')
            out.seek(0)
            data = out.read(MAX_OUTPUT+1)
            if len(data) > MAX_OUTPUT:
                raise ValueError('output exceeds quota')
            candidate = json.loads(data)
            if not isinstance(candidate, dict):
                raise ValueError('candidate object required')
            result = {'ok': True, 'candidate': candidate, 'kernel': os.uname().release}
except Exception:
    pass
sys.stdout.write(json.dumps(result, allow_nan=False))
'''


def _env():
    return {k: v for k, v in os.environ.items() if k not in SCRUBBED_ENV}


class OpenShellBroker:
    """Same interface as the earlier broker: profile, preflight(), execute()."""
    profile = 'openshell-vm-v1'

    def __init__(self, gateway='openshell', image=DEFAULT_IMAGE, workspace='default',
                 expected_kernel=EXPECTED_GUEST_KERNEL, cli=None):
        if '@sha256:' not in image:
            raise SecurityError('OpenShell guest image must be pinned by digest')
        self.gateway, self.image, self.workspace = gateway, image, workspace
        self.expected_kernel = expected_kernel
        self.cli = shutil.which('openshell') if cli is None else cli

    def _run(self, *args, timeout=30, stdin=None):
        if not self.cli:
            raise SecurityError('openshell CLI not found; install OpenShell (infra/README.md)')
        return subprocess.run([self.cli, *args, '-g', self.gateway, '--workspace', self.workspace],
            input=stdin, capture_output=True, timeout=timeout, env=_env())

    def preflight(self):
        done = self._run('status', '-o', 'json', timeout=10)
        try:
            status = json.loads(done.stdout)
        except ValueError:
            raise SecurityError('OpenShell gateway unreachable') from None
        if status.get('status') != 'connected' or status.get('version') != OPENSHELL_VERSION:
            raise SecurityError(f'OpenShell gateway must be connected and at pinned version {OPENSHELL_VERSION}')
        return {'ready': True, 'profile': self.profile, 'gateway_version': status['version']}

    def _sandbox(self, name):
        done = self._run('sandbox', 'get', name, '-o', 'json', timeout=10)
        return json.loads(done.stdout) if done.returncode == 0 else None

    def _delete(self, name):
        # Fire-and-forget so cancellation returns promptly; reaped in background.
        try:
            proc = subprocess.Popen([self.cli, 'sandbox', 'delete', name, '-g', self.gateway, '--workspace', self.workspace],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=_env())
            threading.Thread(target=proc.wait, daemon=True).start()
        except OSError:
            pass

    def _create(self, name, who):
        with tempfile.NamedTemporaryFile('w', suffix='.yaml', delete=False) as policy:
            policy.write(POLICY)
        try:
            done = self._run('sandbox', 'create', '--name', name, '--from', self.image, '--policy', policy.name,
                '--no-auto-providers', '--no-tty', '--detach', '--restart-policy', 'never',
                '--label', f'teamlab.run={who.run_id}', '--label', f'teamlab.agent={who.agent_id}', timeout=BOOT_SECONDS)
        finally:
            os.unlink(policy.name)
        if done.returncode != 0:
            raise SecurityError('OpenShell sandbox creation failed')

    def _await_ready(self, gateway, token, name, deadline):
        while True:
            gateway.active(token)
            if time.monotonic() > deadline:
                raise SecurityError('OpenShell sandbox boot deadline exceeded')
            state = self._sandbox(name)
            phase = (state or {}).get('phase')
            if phase == 'Ready':
                policy = state.get('policy') or {}
                if policy.get('network_policies') or (policy.get('landlock') or {}).get('compatibility') != 'hard_requirement':
                    raise SecurityError('OpenShell sandbox policy is not the pinned deny-all policy')
                return
            if phase in ('Error', 'Failed', 'Deleting'):
                raise SecurityError('OpenShell sandbox failed to provision')
            time.sleep(.2)

    def execute(self, gateway, token, source, records):
        who = gateway.active(token)
        payload = json.dumps({'source': source, 'records': records}).encode()
        if len(payload) > MAX_PAYLOAD:
            raise SecurityError('execution payload exceeds quota')
        name = 'tl-' + uuid.uuid4().hex[:16]
        started = time.monotonic()
        deadline = started + DEADLINE_SECONDS
        proc = None
        try:
            self._create(name, who)
            self._await_ready(gateway, token, name, started + BOOT_SECONDS)
            with tempfile.TemporaryFile() as out:
                proc = subprocess.Popen([self.cli, 'sandbox', 'exec', '-n', name, '-g', self.gateway, '--workspace', self.workspace,
                    '--no-tty', '--no-login-shell', '--timeout', str(EXEC_SECONDS), '--', 'python3', '-I', '-c', RUNNER],
                    stdin=subprocess.PIPE, stdout=out, stderr=subprocess.DEVNULL, env=_env(), start_new_session=True)
                writer = threading.Thread(target=self._feed, args=(proc, payload), daemon=True)
                writer.start()
                while proc.poll() is None:
                    gateway.active(token)
                    if time.monotonic() > deadline:
                        raise SecurityError('execution deadline exceeded')
                    time.sleep(.05)
                gateway.active(token)
                out.seek(0)
                data = out.read(MAX_OUTPUT * 2)
            try:
                result = json.loads(data)
            except ValueError:
                raise SecurityError('isolated execution returned no result') from None
            if result.get('kernel') != self.expected_kernel:
                raise SecurityError('guest kernel does not match the qualified OpenShell VM runtime')
            if not result.get('ok'):
                raise SecurityError('isolated execution failed')
            return result['candidate']
        finally:
            if proc and proc.poll() is None:
                proc.kill()
            self._delete(name)

    @staticmethod
    def _feed(proc, payload):
        try:
            proc.stdin.write(payload)
            proc.stdin.close()
        except (BrokenPipeError, OSError):
            pass
