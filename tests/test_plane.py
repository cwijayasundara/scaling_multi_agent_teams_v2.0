"""Separated control-plane processes. Local doubles are not the deployment gate."""
import hashlib
import json
import os
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from teamlab.cli import main
from teamlab.controller import Controller
from teamlab.fixture import generate
from teamlab.grader import grade, reference
from teamlab.plane import Plane, forbidden_for, grade_request, rpc, separate_runtime_credentials, serve_unix
from teamlab.security import SecurityError


class _Upstream(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        return

    def do_POST(self):
        self.server.seen = self.headers.get('Authorization')
        body = b'{"id":"resp_test","output_text":"ok"}'
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def upstream():
    server = ThreadingHTTPServer(('127.0.0.1', 0), _Upstream)
    server.seen = None
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()


@pytest.fixture
def plane(tmp_path, monkeypatch, upstream):
    monkeypatch.setenv('OPENAI_API_KEY', 'sk-plane-test')
    monkeypatch.setenv('AWS_SECRET_ACCESS_KEY', 'archive-should-not-leak')
    supervisor = Plane(tmp_path / 'plane', archive_dir=tmp_path / 'archive', upstream='http://127.0.0.1:%d' % upstream.server_port).start()
    try:
        yield supervisor, upstream
    finally:
        supervisor.close()


def test_services_hide_foreign_credentials_and_grade_remotely(plane, tmp_path):
    supervisor, _upstream = plane
    client = supervisor.client
    source = tmp_path / 'input.csv'
    generate(source, 30)
    controller = Controller(tmp_path / 'run', source, workers=1, mode='sdk-replay', plane=client)
    expected = reference(controller.records)
    assert client.grade(controller.records, expected) == grade(controller.records, expected)
    assert controller.grade_candidate(controller.records, expected)['passed']
    health = rpc(client.meta['grader_socket'], client.meta['grader_token'], {'operation': 'health'})
    assert health['holds_openai_key'] is False and health['holds_archive_key'] is False
    proxy = client.proxy_health()
    assert proxy['holds_openai_key'] is True and proxy['holds_archive_key'] is False
    with pytest.raises(SecurityError):
        rpc(client.meta['grader_socket'], 'not-the-token', {'operation': 'health'})


def test_model_proxy_injects_its_own_key_and_rejects_other_models(plane):
    supervisor, upstream = plane
    client = supervisor.client
    body = json.dumps({'model': 'gpt-6-luna', 'input': 'ping', 'max_output_tokens': 16}).encode()
    request = urllib.request.Request(client.model_base + '/responses', data=body, method='POST', headers={
        'Authorization': 'Bearer ' + client.model_token, 'Content-Type': 'application/json'})
    with urllib.request.urlopen(request, timeout=5) as response:
        assert response.status == 200
    assert upstream.seen == 'Bearer sk-plane-test'
    rejected = urllib.request.Request(client.model_base + '/responses', data=json.dumps({'model': 'other', 'max_output_tokens': 16}).encode(), method='POST', headers={
        'Authorization': 'Bearer ' + client.model_token, 'Content-Type': 'application/json'})
    with pytest.raises(urllib.error.HTTPError) as error:
        urllib.request.urlopen(rejected, timeout=5)
    assert error.value.code == 400


def test_integration_service_commits_exact_source_and_archive_fails_closed(plane):
    supervisor, _upstream = plane
    client = supervisor.client
    source = 'print(1)\n'
    request = {'run_id': 'ab' * 12, 'task_id': 'cd' * 8, 'author': 'worker-1', 'source': source,
        'source_hash': hashlib.sha256(source.encode()).hexdigest()}
    first = client.integrate(request)
    assert len(first) == 40 and client.integrate(request) == first
    request['author'] = '../main'
    with pytest.raises(SecurityError):
        client.integrate(request)
    record = {'operation_id': 'a' * 32, 'run_id': 'b' * 24, 'agent_id': 'controller', 'action': 'post_note',
        'args_hash': 'c' * 64, 'epoch': 1, 'verdicts': [], 'time': 1, 'policy_version': 'test'}
    client.archive.append(record)
    with pytest.raises(SecurityError):
        client.archive.append(record)
    supervisor.stop_service('gateway')
    time.sleep(1.2)
    with pytest.raises(SecurityError):
        client.archive.append(record)
    telemetry = Path(client.meta['telemetry']).read_text()
    assert '"service":"gateway"' in telemetry and '"ok":false' in telemetry


def test_dead_grader_has_no_local_fallback(plane, tmp_path):
    supervisor, _upstream = plane
    source = tmp_path / 'input.csv'
    generate(source, 20)
    controller = Controller(tmp_path / 'run', source, workers=1, plane=supervisor.client)
    expected = reference(controller.records)
    assert controller.grade_candidate(controller.records, expected)['passed']
    supervisor.stop_service('grader')
    time.sleep(1.2)
    with pytest.raises(SecurityError):
        controller.grade_candidate(controller.records, expected)


def test_peer_uid_and_runtime_credential_split(tmp_path, monkeypatch):
    for name in ('OPENAI_API_KEY', 'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN', 'TEAMLAB_DATABASE_URL'):
        monkeypatch.delenv(name, raising=False)
    token = 't' * 32
    path = Path('/tmp') / ('tl-peer-%d.sock' % os.getpid())
    path.unlink(missing_ok=True)
    stop = threading.Event()
    allowed = 1 if os.geteuid() != 1 else 2
    thread = threading.Thread(target=serve_unix, args=('grader', path, token, allowed, grade_request, forbidden_for('grader', False), stop), daemon=True)
    thread.start()
    try:
        deadline = time.time() + 5
        while not path.exists() and time.time() < deadline:
            time.sleep(0.05)
        with pytest.raises(SecurityError):
            rpc(path, token, {'operation': 'health'})
    finally:
        stop.set()
        path.unlink(missing_ok=True)
    monkeypatch.setenv('OPENAI_API_KEY', 'sk-plane-test')
    monkeypatch.setenv('AWS_SECRET_ACCESS_KEY', 'secret')
    with pytest.raises(ValueError, match='archive credentials'):
        separate_runtime_credentials()
    monkeypatch.delenv('AWS_SECRET_ACCESS_KEY')
    separate_runtime_credentials()
    assert 'OPENAI_API_KEY' not in os.environ


def test_host_qualification_fails_closed_without_a_reachable_gateway(tmp_path):
    code = main(['qualify-host', '--output', str(tmp_path / 'host.json'), '--openshell-gateway', 'teamlab-missing-gateway'])
    report = json.loads((tmp_path / 'host.json').read_text())
    assert report['qualified'] is False and code == 2
    assert not report['checks'][0]['passed']
