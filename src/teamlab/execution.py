"""Offline Firecracker execution over an operator-provisioned Unix broker.

The client holds run authority; the privileged service has no model credentials.
No local subprocess ever evaluates model source. See infra/README.md for the
Linux deployment and its mandatory qualification gate.
"""
import argparse
import hashlib
import json
import os
import platform
import shutil
import signal
import socket
import struct
import subprocess
import tempfile
import threading
import time
from pathlib import Path

from .analytics import canonical, digest
from .security import SecurityError

MAX_FRAME = 32 * 1024 * 1024


def send_frame(sock, payload):
    data = canonical(payload).encode()
    if len(data) > MAX_FRAME:
        raise SecurityError('broker frame exceeds quota')
    sock.sendall(struct.pack('!I', len(data)) + data)


def receive_frame(sock):
    def exact(n):
        out = bytearray()
        while len(out) < n:
            part = sock.recv(min(n-len(out), 65536))
            if not part:
                raise SecurityError('broker disconnected')
            out.extend(part)
        return bytes(out)
    size = struct.unpack('!I', exact(4))[0]
    if size > MAX_FRAME:
        raise SecurityError('broker frame exceeds quota')
    return json.loads(exact(size))


class UnixBroker:
    profile = 'firecracker-jailer-unix-v1'

    def __init__(self, path):
        self.path = str(path)

    def preflight(self):
        with socket.socket(socket.AF_UNIX) as sock:
            sock.settimeout(5)
            sock.connect(self.path)
            send_frame(sock, {'operation': 'health'})
            result = receive_frame(sock)
        if result.get('profile') != self.profile or result.get('network_interfaces') != 0 or not result.get('ready'):
            raise SecurityError('execution broker preflight failed')
        return result

    def execute(self, gateway, token, source, records):
        who = gateway.active(token)
        self.preflight()
        with socket.socket(socket.AF_UNIX) as sock:
            sock.settimeout(2)
            sock.connect(self.path)
            send_frame(sock, {'operation': 'execute', 'source': source, 'records': records,
                'source_hash': hashlib.sha256(source.encode()).hexdigest(), 'input_hash': digest(records),
                'run_id': who.run_id, 'agent_id': who.agent_id, 'epoch': who.epoch})
            output, error = [], []
            def receive():
                try:
                    sock.settimeout(45)
                    output.append(receive_frame(sock))
                except BaseException as exc:
                    error.append(exc)
            thread = threading.Thread(target=receive, daemon=True)
            thread.start()
            deadline = time.monotonic()+45
            try:
                while thread.is_alive():
                    gateway.active(token)
                    if time.monotonic() > deadline:
                        raise SecurityError('execution deadline exceeded')
                    thread.join(.05)
                gateway.active(token)
                if error:
                    raise SecurityError('execution broker failed') from error[0]
                result = output[0]
                if not result.get('ok') or result.get('source_hash') != hashlib.sha256(source.encode()).hexdigest() or result.get('input_hash') != digest(records):
                    raise SecurityError('isolated execution failed or returned mismatched provenance')
                return result['candidate']
            finally:
                # Service monitors disconnect independently and destroys the VM.
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass


def validate_config(config):
    if platform.system() != 'Linux' or os.geteuid() != 0 or not os.access('/dev/kvm', os.R_OK | os.W_OK):
        raise SecurityError('broker requires a dedicated privileged Linux/KVM service')
    for name in ('kernel', 'rootfs', 'firecracker', 'jailer'):
        path = Path(config[name])
        stat = path.lstat()
        if not path.is_absolute() or not path.is_file() or path.is_symlink() or stat.st_uid != 0 or stat.st_mode & 0o022:
            raise SecurityError('broker images/binaries must be root-owned regular immutable files')
        if hashlib.sha256(path.read_bytes()).hexdigest() != config[name+'_sha256']:
            raise SecurityError('broker image/binary hash mismatch: '+name)
    if config['guest_uid'] <= 0 or config['guest_gid'] <= 0 or config['allowed_uid'] <= 0 or config['guest_uid'] == config['allowed_uid']:
        raise SecurityError('unprivileged guest and runtime identities required')
    if not 1 <= config.get('concurrency', 4) <= 8:
        raise SecurityError('broker concurrency outside qualified range')
    base = Path(config['state_dir'])
    base.mkdir(parents=True, exist_ok=True, mode=0o700)
    if base.is_symlink() or base.stat().st_uid != 0 or base.stat().st_mode & 0o077:
        raise SecurityError('private root-owned broker state directory required')


def launch(config, request, client):
    source, records = request['source'], request['records']
    if not isinstance(source, str) or len(source.encode()) > 64_000 or not isinstance(records, list):
        raise SecurityError('invalid execution request')
    if hashlib.sha256(source.encode()).hexdigest() != request['source_hash'] or digest(records) != request['input_hash']:
        raise SecurityError('execution request hash mismatch')
    ident = 'job-'+os.urandom(12).hex()
    base = Path(config['state_dir'])
    # Jailer creates this conventional chroot layout itself when launched.
    root = base / Path(config['firecracker']).name / ident / 'root'
    root.mkdir(parents=True, mode=0o700)
    proc = None
    started = time.monotonic()
    try:
        for name in ('kernel', 'rootfs'):
            os.link(config[name], root / name)
        vm = {'boot-source': {'kernel_image_path': '/kernel', 'boot_args': 'console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda ro init=/sbin/teamlab-init'},
            'drives': [{'drive_id': 'rootfs', 'path_on_host': '/rootfs', 'is_root_device': True, 'is_read_only': True}],
            'machine-config': {'vcpu_count': 1, 'mem_size_mib': 1024},
            'vsock': {'guest_cid': 3, 'uds_path': '/guest.vsock'}}
        (root / 'vm.json').write_text(canonical(vm))
        for path in (root, root/'kernel', root/'rootfs', root/'vm.json'):
            # The dedicated jail UID can read but cannot change image contents.
            if path == root:
                os.chown(path, config['guest_uid'], config['guest_gid'])
            else:
                path.chmod(0o444)
        cmd = [config['jailer'], '--id', ident, '--exec-file', config['firecracker'], '--uid', str(config['guest_uid']), '--gid', str(config['guest_gid']),
            '--chroot-base-dir', str(base), '--cgroup-version', '2', '--cgroup', 'memory.max=1342177280', '--cgroup', 'pids.max=64',
            '--cgroup', 'cpu.max=100000 100000', '--', '--no-api', '--config-file', '/vm.json']
        # No inherited API keys, tracing settings or service credentials.
        proc = subprocess.Popen(cmd, env={'PATH': os.defpath}, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        guest = None
        while time.monotonic()-started < 10:
            if proc.poll() is not None:
                raise SecurityError('microVM exited during boot')
            candidate = socket.socket(socket.AF_UNIX)
            candidate.settimeout(.5)
            try:
                candidate.connect(str(root / 'guest.vsock'))
                candidate.sendall(b'CONNECT 5252\n')
                ack = bytearray()
                while not ack.endswith(b'\n') and len(ack) < 64:
                    chunk = candidate.recv(1)
                    if not chunk:
                        break
                    ack.extend(chunk)
                if ack.startswith(b'OK ') and ack.endswith(b'\n'):
                    guest = candidate
                    break
            except (OSError, SecurityError):
                pass
            candidate.close()
            time.sleep(.05)
        if guest is None:
            raise SecurityError('microVM boot deadline exceeded')
        with guest:
            guest.settimeout(35)
            send_frame(guest, {'source': source, 'records': records})
            output, errors = [], []
            def receive():
                try:
                    output.append(receive_frame(guest))
                except BaseException as exc:
                    errors.append(exc)
            thread = threading.Thread(target=receive, daemon=True)
            thread.start()
            while thread.is_alive():
                import select
                readable, _, _ = select.select([client], [], [], .05)
                if readable and client.recv(1, socket.MSG_PEEK) == b'':
                    raise SecurityError('runtime disconnected; revoke execution')
                if time.monotonic()-started > 40:
                    raise SecurityError('microVM deadline exceeded')
            if errors or not output or not output[0].get('ok'):
                raise SecurityError('guest execution failed')
            return {**output[0], 'source_hash': request['source_hash'], 'input_hash': request['input_hash'], 'elapsed_seconds': time.monotonic()-started}
    finally:
        if proc:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait(timeout=5)
        shutil.rmtree(root.parent, ignore_errors=True)


def serve(config):
    validate_config(config)
    if any(name in os.environ for name in ('OPENAI_API_KEY', 'TEAMLAB_DATABASE_URL')):
        raise SecurityError('execution service must not inherit model/database credentials')
    path = Path(config['socket'])
    if path.exists():
        raise SecurityError('broker socket already exists; operator must resolve stale service')
    semaphore = threading.BoundedSemaphore(config.get('concurrency', 4))
    def handle(client):
        with client:
            try:
                _, uid, _ = struct.unpack('3i', client.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                if uid != config['allowed_uid']:
                    raise SecurityError('broker peer identity rejected')
                client.settimeout(5)
                request = receive_frame(client)
                if request['operation'] == 'health':
                    send_frame(client, {'ready': True, 'profile': UnixBroker.profile, 'network_interfaces': 0,
                        'kernel_sha256': config['kernel_sha256'], 'rootfs_sha256': config['rootfs_sha256']})
                    return
                if request['operation'] != 'execute' or not semaphore.acquire(blocking=False):
                    raise SecurityError('broker unavailable or invalid operation')
                try:
                    send_frame(client, launch(config, request, client))
                finally:
                    semaphore.release()
            except Exception:
                try:
                    send_frame(client, {'ok': False, 'reason': 'broker refused or failed execution'})
                except OSError:
                    pass
    with socket.socket(socket.AF_UNIX) as server:
        server.bind(str(path))
        os.chown(path, config['allowed_uid'], -1)
        path.chmod(0o600)
        server.listen(16)
        try:
            while True:
                client, _ = server.accept()
                threading.Thread(target=handle, args=(client,), daemon=True).start()
        finally:
            path.unlink(missing_ok=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', required=True)
    args = parser.parse_args()
    serve(json.loads(Path(args.config).read_text()))
