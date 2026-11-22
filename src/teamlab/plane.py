"""Authenticated control-plane processes with scrubbed credentials.

The default local profile still runs the gateway, grader, model client and Git
integration in one process. This module is the separated profile: each privilege
is a process with its own environment, a peer-UID check, mutual TLS with a
pinned server key (see plane_tls) and a secret token.
Same-user deployment is weaker than distinct UIDs. A missing service fails
closed. These processes do not prove kernel isolation or cloud immutability.
"""
import argparse
import collections
import hashlib
import http.client
import json
import os
import platform
import re
import secrets
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler
from pathlib import Path

from .analytics import canonical
from .archive import DirectoryArchive, configured_archive
from .artifacts import commit_verified_source
from .grader import grade
from .plane_tls import check_pin, client_context, hostname, issue_plane_pki, server_context
from .security import SecurityError

FOREIGN = ('OPENAI_API_KEY', 'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN', 'TEAMLAB_DATABASE_URL')
SERVICES = ('grader', 'integration', 'gateway', 'model-proxy')
MAX_FRAME = 32 * 1024 * 1024


def send_frame(sock, payload):
    data = canonical(payload).encode()
    if len(data) > MAX_FRAME:
        raise SecurityError('frame exceeds quota')
    sock.sendall(struct.pack('!I', len(data)) + data)


def receive_frame(sock):
    def exact(n):
        out = bytearray()
        while len(out) < n:
            part = sock.recv(min(n-len(out), 65536))
            if not part:
                raise SecurityError('peer disconnected')
            out.extend(part)
        return bytes(out)
    size = struct.unpack('!I', exact(4))[0]
    if size > MAX_FRAME:
        raise SecurityError('frame exceeds quota')
    return json.loads(exact(size))


def peer_uid(sock):
    if platform.system() == 'Linux':
        _pid, uid, _gid = struct_peercred(sock)
        return uid
    import ctypes
    uid = ctypes.c_uint32()
    gid = ctypes.c_uint32()
    libc = ctypes.CDLL(None)
    libc.getpeereid.argtypes = [ctypes.c_int, ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_uint32)]
    libc.getpeereid.restype = ctypes.c_int
    if libc.getpeereid(sock.fileno(), ctypes.byref(uid), ctypes.byref(gid)) != 0:
        raise SecurityError('peer identity unavailable')
    return int(uid.value)


def struct_peercred(sock):
    import struct
    return struct.unpack('3i', sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))


def token_ok(presented, expected):
    return isinstance(presented, str) and len(presented) == len(expected) and secrets.compare_digest(presented, expected)


def credential_flags():
    return {
        'holds_openai_key': 'OPENAI_API_KEY' in os.environ,
        'holds_archive_key': 'AWS_SECRET_ACCESS_KEY' in os.environ,
        'holds_database_url': 'TEAMLAB_DATABASE_URL' in os.environ,
    }


def forbidden_for(service, archive_credentials):
    names = set(FOREIGN)
    if service == 'model-proxy':
        names.discard('OPENAI_API_KEY')
    if service == 'gateway' and archive_credentials:
        names.difference_update({'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN'})
    return tuple(sorted(names))


def expected_flags(service, archive_credentials):
    return {
        'holds_openai_key': service == 'model-proxy',
        'holds_archive_key': service == 'gateway' and archive_credentials,
        'holds_database_url': False,
    }


def rpc(path, token, payload, timeout=30, *, tls):
    """Call a service over mutual TLS. tls holds ca, client_cert, client_key, service and pin."""
    body = {**payload, 'token': token}
    context = client_context(tls['client_cert'], tls['client_key'], tls['ca'])
    with socket.socket(socket.AF_UNIX) as raw:
        raw.settimeout(timeout)
        try:
            raw.connect(str(path))
            sock = context.wrap_socket(raw, server_hostname=hostname(tls['service']))
        except OSError as exc:
            raise SecurityError('control-plane service unavailable') from exc
        with sock:
            check_pin(sock, tls['pin'])
            try:
                send_frame(sock, body)
                result = receive_frame(sock)
            except (OSError, SecurityError, ValueError) as exc:
                raise SecurityError('control-plane service unavailable') from exc
    if not isinstance(result, dict) or not result.get('ok'):
        raise SecurityError('control-plane service refused the request')
    return result


def serve_unix(service, path, token, allowed_uid, handler, forbidden, stop, context):
    """Serve length-prefixed frames: peer-UID check, then mutual TLS (context), then the token."""
    present = [name for name in forbidden if name in os.environ]
    if present:
        raise SecurityError('service inherited a foreign credential')
    socket_path = Path(path)
    if socket_path.exists():
        raise SecurityError('service socket already exists')
    directory = socket_path.parent
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    refusals = collections.Counter()
    lock = threading.Lock()

    def refuse(reason):
        with lock:
            refusals[reason] += 1

    def client_thread(raw):
        with raw:
            try:
                uid = peer_uid(raw)
            except (OSError, SecurityError):
                uid = None
            if uid != allowed_uid:
                refuse('peer')
                return
            try:
                raw.settimeout(30)
                client = context.wrap_socket(raw, server_side=True)
            except (OSError, SecurityError):
                # A failed handshake is answered by closing the connection.
                refuse('tls')
                return
            reason = 'request'
            with client:
                try:
                    request = receive_frame(client)
                    if not token_ok(request.get('token'), token):
                        reason = 'token'
                        raise SecurityError('token rejected')
                    if request.get('operation') == 'health':
                        with lock:
                            counted = dict(refusals)
                        send_frame(client, {'ok': True, 'service': service, 'refusals': counted, **credential_flags()})
                        return
                    send_frame(client, handler(request))
                except Exception:
                    refuse(reason)
                    try:
                        send_frame(client, {'ok': False, 'error': 'service refused the request', 'reason': reason})
                    except OSError:
                        pass

    with socket.socket(socket.AF_UNIX) as server:
        server.bind(str(socket_path))
        try:
            if os.geteuid() == 0 or allowed_uid == os.geteuid():
                os.chown(socket_path, allowed_uid, -1)
        except PermissionError:
            if allowed_uid == os.geteuid():
                raise
        socket_path.chmod(0o600)
        server.listen(32)
        server.settimeout(0.2)
        print(json.dumps({'ready': True, 'service': service}), flush=True)
        try:
            while not stop.is_set():
                try:
                    client, _ = server.accept()
                except TimeoutError:
                    continue
                except OSError:
                    if stop.is_set():
                        break
                    raise
                threading.Thread(target=client_thread, args=(client,), daemon=True).start()
        finally:
            socket_path.unlink(missing_ok=True)


def grade_request(request):
    if request.get('operation') != 'grade':
        raise SecurityError('unknown grader operation')
    records, candidate = request.get('records'), request.get('candidate')
    if not isinstance(records, list) or len(records) > 200_000 or not isinstance(candidate, dict):
        raise SecurityError('invalid grade request')
    encoded = canonical({'records': records, 'candidate': candidate}).encode()
    if len(encoded) > 32_000_000:
        raise SecurityError('grade request exceeds quota')
    return {'ok': True, 'verdict': grade(records, candidate)}


def integration_request(repo_root):
    def handle(request):
        if request.get('operation') != 'integrate':
            raise SecurityError('unknown integration operation')
        run_id, task_id = request.get('run_id'), request.get('task_id')
        source, source_hash = request.get('source'), request.get('source_hash')
        if not re.fullmatch(r'[0-9a-f]{24}', run_id or '') or not re.fullmatch(r'[0-9a-f]{16}', task_id or ''):
            raise SecurityError('invalid integration identity')
        if not re.fullmatch(r'[0-9a-f]{64}', source_hash or '') or not isinstance(source, str):
            raise SecurityError('invalid source hash')
        if hashlib.sha256(source.encode()).hexdigest() != source_hash:
            raise SecurityError('source hash mismatch')
        commit = commit_verified_source(Path(repo_root) / run_id, task_id, request.get('author'), source)
        return {'ok': True, 'commit': commit}
    return handle


def gateway_request(archive):
    def handle(request):
        operation = request.get('operation')
        if archive is None:
            raise SecurityError('gateway archive is not configured')
        if operation == 'preflight':
            archive.preflight()
            return {'ok': True}
        if operation != 'append' or not isinstance(request.get('record'), dict):
            raise SecurityError('unknown gateway operation')
        archive.append(request['record'])
        return {'ok': True}
    return handle


class ProxyHandler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, fmt, *args):
        return

    def _reject(self, code):
        body = b'{"error":"model proxy refused the request"}'
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path != '/health' or not token_ok(self.headers.get('Authorization', '').removeprefix('Bearer ').strip(), self.server.token):
            self._reject(401)
            return
        body = canonical({'ok': True, 'service': 'model-proxy', **credential_flags()}).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path not in ('/v1/responses', '/responses'):
            self._reject(404)
            return
        if not token_ok(self.headers.get('Authorization', '').removeprefix('Bearer ').strip(), self.server.token):
            self._reject(401)
            return
        length = int(self.headers.get('Content-Length', '0') or '0')
        if not 2 <= length <= 512_000:
            self._reject(413)
            return
        raw = self.rfile.read(length)
        try:
            data = json.loads(raw)
        except ValueError:
            self._reject(400)
            return
        if data.get('model') != 'gpt-6-luna' or type(data.get('max_output_tokens')) is not int:
            self._reject(400)
            return
        request = urllib.request.Request(self.server.upstream.rstrip('/') + '/v1/responses', data=raw, method='POST', headers={
            'Authorization': 'Bearer ' + self.server.api_key, 'Content-Type': 'application/json'})
        try:
            with self.server.opener.open(request, timeout=45) as response:
                payload = response.read()
                status = response.status
        except urllib.error.HTTPError as exc:
            payload, status = exc.read(), exc.code
        except (OSError, urllib.error.URLError):
            self._reject(502)
            return
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, msg, headers, fp)


def serve_proxy(token, upstream, stop, context):
    if 'OPENAI_API_KEY' not in os.environ or any(name in os.environ for name in forbidden_for('model-proxy', False)):
        raise SecurityError('model proxy credential boundary rejected')
    from http.server import ThreadingHTTPServer

    class TLSServer(ThreadingHTTPServer):
        def finish_request(self, request, client_address):
            # Handshake in the per-connection thread so a stalled client cannot block accept.
            request.settimeout(30)
            try:
                request = context.wrap_socket(request, server_side=True)
            except OSError:
                return
            with request:
                super().finish_request(request, client_address)

        def handle_error(self, request, client_address):
            return

    server = TLSServer(('127.0.0.1', 0), ProxyHandler)
    server.token = token
    server.api_key = os.environ['OPENAI_API_KEY']
    server.upstream = upstream
    server.opener = urllib.request.build_opener(_NoRedirect)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    print(json.dumps({'ready': True, 'service': 'model-proxy', 'port': server.server_port}), flush=True)
    try:
        while not stop.is_set():
            time.sleep(0.2)
    finally:
        server.shutdown()


class RemoteArchive:
    def __init__(self, path, token, tls):
        self.path, self.token, self.tls = path, token, tls

    def preflight(self):
        rpc(self.path, self.token, {'operation': 'preflight'}, tls=self.tls())

    def append(self, record):
        rpc(self.path, self.token, {'operation': 'append', 'record': record}, tls=self.tls())


class PlaneClient:
    def __init__(self, directory):
        meta_path = Path(directory) / 'plane.json'
        self.meta = json.loads(meta_path.read_text())
        if meta_path.stat().st_mode & 0o077:
            raise SecurityError('control-plane descriptor must be private')
        self.model_base = self.meta.get('model_base')
        self.model_token = self.meta.get('model_token')
        self.archive = RemoteArchive(self.meta['gateway_socket'], self.meta['gateway_token'], lambda: self.tls('gateway'))

    def tls(self, service):
        tls = self.meta['tls']
        return {'ca': tls['ca'], 'client_cert': tls['client_cert'], 'client_key': tls['client_key'],
            'service': service, 'pin': tls['pins'][service]}

    def client_ssl_context(self):
        tls = self.meta['tls']
        return client_context(tls['client_cert'], tls['client_key'], tls['ca'])

    def health(self, service, timeout=30):
        return rpc(self.meta[service + '_socket'], self.meta[service + '_token'], {'operation': 'health'}, timeout, tls=self.tls(service))

    def _status(self, service):
        path = Path(self.meta['status'])
        if not path.exists():
            return 'ok'
        status = json.loads(path.read_text())
        return status.get(service, 'failed')

    def _require(self, service):
        if self._status(service) != 'ok':
            raise SecurityError(service + ' failed closed')

    def preflight(self):
        for service in ('grader', 'integration', 'gateway'):
            self._require(service)
            self._flags(service, self.health(service))
        self._require('model-proxy')
        self._flags('model-proxy', self.proxy_health())

    def _flags(self, service, result):
        flags = {key: bool(result.get(key)) for key in ('holds_openai_key', 'holds_archive_key', 'holds_database_url')}
        if flags != expected_flags(service, bool(self.meta.get('archive_credentials'))):
            raise SecurityError(service + ' credential boundary failed')

    def grade(self, records, candidate):
        self._require('grader')
        return rpc(self.meta['grader_socket'], self.meta['grader_token'], {'operation': 'grade', 'records': records, 'candidate': candidate}, tls=self.tls('grader'))['verdict']

    def integrate(self, request):
        self._require('integration')
        return rpc(self.meta['integration_socket'], self.meta['integration_token'], {'operation': 'integrate', **request}, tls=self.tls('integration'))['commit']

    def proxy_health(self, timeout=3):
        base = urllib.parse.urlsplit(self.model_base)
        if base.scheme != 'https':
            raise SecurityError('model proxy must use TLS')
        connection = http.client.HTTPSConnection(base.hostname, base.port, timeout=timeout, context=self.client_ssl_context())
        try:
            connection.connect()
            check_pin(connection.sock, self.meta['tls']['pins']['model-proxy'])
            connection.request('GET', '/health', headers={'Authorization': 'Bearer ' + self.model_token})
            response = connection.getresponse()
            if response.status != 200:
                raise SecurityError('model proxy preflight failed')
            result = json.loads(response.read())
        except (OSError, http.client.HTTPException, ValueError) as exc:
            raise SecurityError('model proxy unavailable') from exc
        finally:
            connection.close()
        if not result.get('ok') or result.get('service') != 'model-proxy':
            raise SecurityError('model proxy preflight failed')
        return result


def separate_runtime_credentials():
    """Drop model credentials and refuse archive credentials in a separated runtime."""
    for name in ('AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN'):
        if os.environ.get(name):
            raise ValueError('separated runtime must not hold archive credentials')
    os.environ.pop('OPENAI_API_KEY', None)


class Plane:
    def __init__(self, root, allowed_uid=None, archive_dir=None, audit_bucket=None, audit_endpoint=None, audit_days=30, upstream='https://api.openai.com'):
        self.root = Path(root)
        self.allowed_uid = os.geteuid() if allowed_uid is None else allowed_uid
        self.archive_dir = archive_dir
        self.audit_bucket = audit_bucket
        self.audit_endpoint = audit_endpoint
        self.audit_days = audit_days
        self.upstream = upstream
        self.procs = {}
        self.stop = threading.Event()
        self.socket_dir = None
        self.directory = self.root
        self.telemetry = self.root / 'telemetry.jsonl'
        self.status_path = self.root / 'status.json'
        self._watch = None
        self.failures = {name: 0 for name in SERVICES}

    def _env(self, service):
        env = {'PATH': os.environ.get('PATH', os.defpath), 'PYTHONPATH': str(Path(__file__).resolve().parents[1]),
            'PYTHONNOUSERSITE': '1', 'LANG': os.environ.get('LANG', 'C.UTF-8')}
        if service == 'model-proxy' and os.environ.get('OPENAI_API_KEY'):
            env['OPENAI_API_KEY'] = os.environ['OPENAI_API_KEY']
        if service == 'gateway' and self.audit_bucket:
            for name in ('AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN', 'AWS_DEFAULT_REGION'):
                if os.environ.get(name):
                    env[name] = os.environ[name]
            if self.audit_endpoint:
                env['TEAMLAB_AUDIT_ENDPOINT'] = self.audit_endpoint
        return env

    def _spawn(self, service, token_path, pki, socket_path=None):
        server = pki['servers'][service]
        command = [sys.executable, '-m', 'teamlab.plane', 'serve', '--service', service, '--token-file', str(token_path), '--uid', str(self.allowed_uid),
            '--cert', server['cert'], '--key', server['key'], '--ca', pki['ca']]
        if socket_path is not None:
            command += ['--socket', str(socket_path)]
        if service == 'integration':
            command += ['--repo', str(self.root / 'integration')]
        if service == 'gateway' and self.archive_dir:
            command += ['--archive-dir', str(self.archive_dir), '--audit-retention-days', str(self.audit_days)]
        if service == 'gateway' and self.audit_bucket:
            command += ['--audit-bucket', self.audit_bucket, '--audit-retention-days', str(self.audit_days)]
            if self.audit_endpoint:
                command += ['--audit-endpoint', self.audit_endpoint]
        if service == 'model-proxy':
            command += ['--upstream', self.upstream]
        proc = subprocess.Popen(command, env=self._env(service), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        self.procs[service] = proc
        ready_line = []

        def read_ready():
            ready_line.append(proc.stdout.readline())

        reader = threading.Thread(target=read_ready, daemon=True)
        reader.start()
        reader.join(15)
        line = ready_line[0] if ready_line else ''
        if proc.poll() is not None or not line:
            raise SecurityError(service + ' failed to start')
        ready = json.loads(line)
        if not ready.get('ready') or ready.get('service') != service:
            raise SecurityError(service + ' failed to start')
        return ready

    def start(self):
        if 'OPENAI_API_KEY' not in os.environ:
            raise SecurityError('model proxy requires OPENAI_API_KEY in the supervisor only')
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.socket_dir = Path(tempfile.mkdtemp(prefix='tl', dir='/tmp'))
        os.chmod(self.socket_dir, 0o700)
        tokens = {name: secrets.token_urlsafe(32) for name in SERVICES}
        sockets = {}
        try:
            pki = issue_plane_pki(self.socket_dir / 'pki', SERVICES)
            for service in ('grader', 'integration', 'gateway'):
                token_path = self.socket_dir / (service + '.token')
                token_path.write_text(tokens[service])
                os.chmod(token_path, 0o600)
                sockets[service] = self.socket_dir / (service + '.sock')
                self._spawn(service, token_path, pki, sockets[service])
            token_path = self.socket_dir / 'model-proxy.token'
            token_path.write_text(tokens['model-proxy'])
            os.chmod(token_path, 0o600)
            ready = self._spawn('model-proxy', token_path, pki)
            descriptor = {
                'grader_socket': str(sockets['grader']), 'grader_token': tokens['grader'],
                'integration_socket': str(sockets['integration']), 'integration_token': tokens['integration'],
                'gateway_socket': str(sockets['gateway']), 'gateway_token': tokens['gateway'],
                'model_base': 'https://127.0.0.1:%d/v1' % ready['port'], 'model_token': tokens['model-proxy'],
                'tls': {'ca': pki['ca'], 'client_cert': pki['client_cert'], 'client_key': pki['client_key'],
                    'pins': {name: server['pin'] for name, server in pki['servers'].items()}},
                'telemetry': str(self.telemetry), 'status': str(self.status_path),
                'archive_credentials': bool(self.audit_bucket),
            }
            self._write_status({name: 'ok' for name in SERVICES})
            path = self.root / 'plane.json'
            path.write_text(json.dumps(descriptor))
            os.chmod(path, 0o600)
            self.client = PlaneClient(self.root)
            self.client.preflight()
            self._watch = threading.Thread(target=self._watchdog, daemon=True)
            self._watch.start()
            return self
        except Exception:
            self.close()
            raise

    def _write_status(self, status):
        temporary = self.status_path.with_suffix('.tmp')
        temporary.write_text(canonical(status))
        os.chmod(temporary, 0o600)
        os.replace(temporary, self.status_path)

    def _probe(self, service):
        started = time.monotonic()
        try:
            if service == 'model-proxy':
                result = self.client.proxy_health()
            else:
                result = self.client.health(service, timeout=3)
            flags = {key: bool(result.get(key)) for key in ('holds_openai_key', 'holds_archive_key', 'holds_database_url')}
            ok = flags == expected_flags(service, bool(self.audit_bucket))
            reason = None if ok else 'credential-boundary'
        except Exception:
            ok, reason = False, 'unavailable'
        elapsed = time.monotonic() - started
        return ok, reason, elapsed

    def _watchdog(self):
        while not self.stop.is_set():
            status = {}
            for service in SERVICES:
                ok, reason, elapsed = self._probe(service)
                self.failures[service] = 0 if ok else self.failures[service] + 1
                state = 'ok' if self.failures[service] < 2 else 'failed'
                status[service] = state
                with self.telemetry.open('a') as handle:
                    handle.write(canonical({'service': service, 'ok': ok, 'state': state, 'reason': reason, 'elapsed_seconds': round(elapsed, 6), 'time': time.time()}) + '\n')
            self._write_status(status)
            self.stop.wait(0.25)

    def stop_service(self, service):
        proc = self.procs[service]
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()

    def close(self):
        self.stop.set()
        for proc in self.procs.values():
            if proc.poll() is None:
                proc.terminate()
        for proc in self.procs.values():
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=2)
            for stream in (proc.stdout, proc.stderr, proc.stdin):
                if stream is not None and not stream.closed:
                    stream.close()
        self.procs.clear()
        if self.socket_dir and self.socket_dir.exists():
            shutil.rmtree(self.socket_dir, ignore_errors=True)
            self.socket_dir = None


def run_service(args):
    token = Path(args.token_file).read_text().strip()
    if len(token) < 32:
        raise SecurityError('service token missing')
    stop = threading.Event()
    archive_credentials = bool(args.audit_bucket)
    forbidden = forbidden_for(args.service, archive_credentials)
    context = server_context(args.cert, args.key, args.ca)
    if args.service == 'model-proxy':
        serve_proxy(token, args.upstream, stop, context)
        return
    if args.service == 'grader':
        handler = grade_request
    elif args.service == 'integration':
        handler = integration_request(args.repo)
    else:
        archive = None
        if args.archive_dir:
            archive = DirectoryArchive(args.archive_dir, args.audit_retention_days)
        elif args.audit_bucket:
            archive = configured_archive(args.audit_bucket, args.audit_retention_days, endpoint=args.audit_endpoint or os.environ.get('TEAMLAB_AUDIT_ENDPOINT'))
        handler = gateway_request(archive)
        if archive is not None:
            archive.preflight()
    serve_unix(args.service, args.socket, token, args.uid, handler, forbidden, stop, context)


def parser():
    p = argparse.ArgumentParser(prog='teamlab.plane')
    sub = p.add_subparsers(dest='command', required=True)
    serve = sub.add_parser('serve')
    serve.add_argument('--service', required=True, choices=SERVICES)
    serve.add_argument('--socket')
    serve.add_argument('--token-file', required=True)
    serve.add_argument('--uid', type=int, required=True)
    serve.add_argument('--cert', required=True)
    serve.add_argument('--key', required=True)
    serve.add_argument('--ca', required=True)
    serve.add_argument('--repo')
    serve.add_argument('--archive-dir')
    serve.add_argument('--audit-bucket')
    serve.add_argument('--audit-endpoint')
    serve.add_argument('--audit-retention-days', type=int, default=30)
    serve.add_argument('--upstream', default='https://api.openai.com')
    return p


def main(argv=None):
    args = parser().parse_args(argv)
    if args.command == 'serve':
        run_service(args)
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (SecurityError, ValueError, OSError) as exc:
        print(type(exc).__name__ + ': service failed', file=sys.stderr)
        raise SystemExit(1)
