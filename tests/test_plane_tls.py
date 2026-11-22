"""Mutual TLS with pinned server keys between control-plane services."""
import http.client
import json
import socket
import ssl
import stat
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

import teamlab.plane

from test_plane import plane, upstream  # noqa: F401  (shared real-supervisor fixtures)
from teamlab.fixture import generate
from teamlab.grader import reference
from teamlab.controller import Controller
from teamlab.plane import rpc
from teamlab.plane_tls import CERT_LIFETIME_SECONDS, check_pin, client_context, issue_plane_pki, server_context
from teamlab.security import SecurityError


def _records(tmp_path):
    source = tmp_path / 'input.csv'
    generate(source, 20)
    return Controller(tmp_path / 'run', source, workers=1).records


def _tls_refusals(client):
    return client.health('grader').get('refusals', {}).get('tls', 0)


def test_rpc_over_mtls_with_pinned_server(plane, tmp_path):
    supervisor, _upstream = plane
    client = supervisor.client
    tls = client.meta['tls']
    assert set(tls['pins']) == {'grader', 'integration', 'gateway', 'model-proxy'}
    records = _records(tmp_path)
    assert client.grade(records, reference(records))['passed']


def test_client_without_certificate_is_refused(plane, monkeypatch):
    supervisor, _upstream = plane
    client = supervisor.client
    before = _tls_refusals(client)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_verify_locations(client.meta['tls']['ca'])
    with socket.socket(socket.AF_UNIX) as raw:
        raw.settimeout(5)
        raw.connect(client.meta['grader_socket'])
        with pytest.raises((ssl.SSLError, ConnectionError)):
            with context.wrap_socket(raw, server_hostname='grader.teamlab.internal') as tls_sock:
                # TLS 1.3 reports the missing client certificate after the client's handshake.
                tls_sock.sendall(b'\x00\x00\x00\x02{}')
                if not tls_sock.recv(1):
                    raise ConnectionError('closed')
    monkeypatch.setattr(teamlab.plane, 'client_context', lambda *_args: context)
    with pytest.raises(SecurityError):
        rpc(client.meta['grader_socket'], client.meta['grader_token'], {'operation': 'health'}, tls=client.tls('grader'))
    monkeypatch.undo()
    assert _tls_refusals(client) > before


def test_client_trusting_another_ca_is_refused(plane, tmp_path):
    supervisor, _upstream = plane
    client = supervisor.client
    other = issue_plane_pki(tmp_path / 'other', ('grader',))
    foreign = dict(client.tls('grader'), ca=other['ca'], client_cert=other['client_cert'], client_key=other['client_key'])
    with pytest.raises(SecurityError):
        rpc(client.meta['grader_socket'], client.meta['grader_token'], {'operation': 'health'}, tls=foreign)
    # A client certificate from another CA is refused by the server even when the client trusts the plane CA.
    mixed = dict(client.tls('grader'), client_cert=other['client_cert'], client_key=other['client_key'])
    with pytest.raises(SecurityError):
        rpc(client.meta['grader_socket'], client.meta['grader_token'], {'operation': 'health'}, tls=mixed)


def test_pin_mismatch_is_refused(plane, tmp_path):
    supervisor, _upstream = plane
    client = supervisor.client
    client.meta['tls']['pins']['grader'] = '0' * 64
    records = _records(tmp_path)
    with pytest.raises(SecurityError, match='server key pin mismatch'):
        client.grade(records, reference(records))
    client.meta['tls']['pins']['model-proxy'] = '0' * 64
    with pytest.raises(SecurityError, match='server key pin mismatch'):
        client.proxy_health()


def _handshake(pki, service='grader'):
    server_sock, client_sock = socket.socketpair(socket.AF_UNIX)
    server_sock.settimeout(5)
    client_sock.settimeout(5)
    errors = []

    def serve():
        try:
            with server_context(pki['servers'][service]['cert'], pki['servers'][service]['key'], pki['ca']).wrap_socket(server_sock, server_side=True) as s:
                s.sendall(b'ok')
        except (ssl.SSLError, OSError) as exc:
            errors.append(exc)
            server_sock.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        with client_context(pki['client_cert'], pki['client_key'], pki['ca']).wrap_socket(client_sock, server_hostname=service + '.teamlab.internal') as c:
            check_pin(c, pki['servers'][service]['pin'])
            return c.recv(2)
    finally:
        thread.join(5)


def test_expired_certificate_is_refused(tmp_path):
    fresh = issue_plane_pki(tmp_path / 'fresh', ('grader',))
    assert _handshake(fresh) == b'ok'
    expired = issue_plane_pki(tmp_path / 'expired', ('grader',), now=time.time() - 2 * CERT_LIFETIME_SECONDS)
    with pytest.raises(ssl.SSLCertVerificationError, match='expired'):
        _handshake(expired)


def test_token_still_required_over_valid_tls(plane):
    supervisor, _upstream = plane
    client = supervisor.client
    assert rpc(client.meta['grader_socket'], client.meta['grader_token'], {'operation': 'health'}, tls=client.tls('grader'))['ok']
    with pytest.raises(SecurityError, match='refused'):
        rpc(client.meta['grader_socket'], 'x' * len(client.meta['grader_token']), {'operation': 'health'}, tls=client.tls('grader'))


def test_private_keys_are_0600(plane):
    supervisor, _upstream = plane
    tls = supervisor.client.meta['tls']
    keys = [Path(tls['client_key'])] + sorted(Path(tls['ca']).parent.glob('*.key'))
    assert len(keys) >= 5
    for key in keys:
        assert stat.S_IMODE(key.stat().st_mode) == 0o600, key
    assert not any('BEGIN' in p.read_text() and 'PRIVATE' in p.read_text() for p in Path(tls['ca']).parent.glob('*.pem'))


def test_model_proxy_serves_https_with_client_auth(plane):
    supervisor, _upstream = plane
    client = supervisor.client
    assert client.model_base.startswith('https://127.0.0.1:') and client.model_base.endswith('/v1')
    assert client.proxy_health()['ok']
    port = int(client.model_base.split(':')[2].split('/')[0])
    plain = urllib.request.Request('http://127.0.0.1:%d/health' % port, headers={'Authorization': 'Bearer ' + client.model_token})
    with pytest.raises((urllib.error.URLError, http.client.HTTPException, ConnectionError)):
        urllib.request.urlopen(plain, timeout=5).read()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(client.meta['tls']['ca'])
    connection = http.client.HTTPSConnection('127.0.0.1', port, timeout=5, context=context)
    with pytest.raises((ssl.SSLError, ConnectionError, http.client.HTTPException)):
        connection.request('GET', '/health', headers={'Authorization': 'Bearer ' + client.model_token})
        connection.getresponse().read()
    connection.close()
    import httpx
    with httpx.Client(verify=client.client_ssl_context(), timeout=5) as https:
        response = https.get(client.model_base.removesuffix('/v1') + '/health', headers={'Authorization': 'Bearer ' + client.model_token})
    assert response.status_code == 200 and json.loads(response.content)['service'] == 'model-proxy'


def test_live_model_client_reaches_proxy_over_mtls(plane):
    supervisor, upstream = plane
    client = supervisor.client
    from openai import OpenAI
    from teamlab.budget import SpendBudget
    budget = SpendBudget('1', '1', '1')
    model = OpenAI(api_key=client.model_token, base_url=client.model_base, timeout=5, max_retries=0,
        http_client=budget.client(verify=client.client_ssl_context()))
    response = model.responses.create(model='gpt-6-luna', input='ping', max_output_tokens=16)
    assert response.id == 'resp_test' and upstream.seen == 'Bearer sk-plane-test'
    model.close()
